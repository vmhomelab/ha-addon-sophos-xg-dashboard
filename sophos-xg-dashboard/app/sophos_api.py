from __future__ import annotations

from collections import Counter
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any
from xml.sax.saxutils import escape

import httpx


@dataclass(slots=True)
class SophosClient:
    host: str
    username: str
    password: str
    verify_ssl: bool = False
    timeout: int = 15

    @property
    def api_url(self) -> str:
        return f"{self.host.rstrip('/')}/webconsole/APIController"

    def wrap(self, payload: str) -> str:
        return f"""<Request>
  <Login>
    <Username>{escape(self.username)}</Username>
    <Password>{escape(self.password)}</Password>
  </Login>
  {payload}
</Request>"""

    def form_data(self, payload: str) -> dict[str, str]:
        """Return the form field expected by the Sophos/SFOS XML API.

        SFOS does not process raw XML request bodies on APIController. The XML
        payload must be sent as the `reqxml` form value; otherwise the firewall
        may answer HTTP 200 with an empty body, which looks like a parser error
        in the dashboard.
        """
        return {"reqxml": self.wrap(payload)}

    async def post_xml(self, payload: str) -> str:
        if not self.username or not self.password:
            raise RuntimeError("Sophos username/password are not configured")

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=self.timeout) as client:
            response = await client.post(
                self.api_url,
                data=self.form_data(payload),
            )
            response.raise_for_status()
            if not response.text.strip():
                raise RuntimeError("Sophos API returned an empty response")
            validate_api_response(response.text)
            return response.text

    async def get_firewall_rules_raw(self) -> str:
        return await self.post_xml("""<Get><FirewallRule></FirewallRule></Get>""")

    async def get_nat_rules_raw(self) -> str:
        return await self.post_xml("""<Get><NATRule></NATRule></Get>""")


def _strip_namespace(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _text(node: ET.Element | None) -> str | None:
    if node is None or node.text is None:
        return None
    value = node.text.strip()
    return value if value else None


def _find_text_any(node: ET.Element, names: list[str]) -> str | None:
    wanted = {n.lower() for n in names}
    for child in node.iter():
        if _strip_namespace(child.tag).lower() in wanted:
            value = _text(child)
            if value is not None:
                return value
    return None


def _find_child_text_any(node: ET.Element, names: list[str]) -> str | None:
    """Find a scalar value on the rule node itself, not nested objects.

    Sophos XML API responses can contain nested objects below a FirewallRule or
    NATRule. Those nested objects may also have fields like `Status` or `Name`.
    Rule-level state must therefore prefer direct children, otherwise a disabled
    NAT rule can be shown as enabled because a nested network/service object has
    its own enabled status.
    """
    wanted = {n.lower() for n in names}
    for child in list(node):
        if _strip_namespace(child.tag).lower() in wanted:
            value = _text(child)
            if value is not None:
                return value
    return None


def _list_texts(node: ET.Element, container_names: list[str], item_names: list[str]) -> list[str]:
    containers = {n.lower() for n in container_names}
    items = {n.lower() for n in item_names}
    values: list[str] = []
    for container in node.iter():
        if _strip_namespace(container.tag).lower() not in containers:
            continue
        for item in container.iter():
            if _strip_namespace(item.tag).lower() in items:
                value = _text(item)
                if value:
                    values.append(value)
    return values


def _enabled(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.lower()
    if lowered in {"enable", "enabled", "true", "1", "on", "yes"}:
        return True
    if lowered in {"disable", "disabled", "false", "0", "off", "no"}:
        return False
    return None


def parse_firewall_rules(xml_text: str) -> dict[str, Any]:
    root = ET.fromstring(xml_text)
    rules = []
    for node in root.iter():
        if _strip_namespace(node.tag) != "FirewallRule":
            continue
        name = _find_child_text_any(node, ["Name", "RuleName"]) or _find_text_any(node, ["Name", "RuleName"])
        if not name:
            continue
        status = _find_child_text_any(node, ["Status", "Enable", "Enabled"])
        rules.append(
            {
                "name": name,
                "status": status,
                "enabled": _enabled(status),
                "action": _find_child_text_any(node, ["Action"]),
                "position": _find_child_text_any(node, ["Position"]),
                "source_zones": _list_texts(node, ["SourceZones", "SourceZone"], ["Zone", "Name"]),
                "destination_zones": _list_texts(node, ["DestinationZones", "DestinationZone"], ["Zone", "Name"]),
                "services": _list_texts(node, ["Services", "ServiceList"], ["Service", "Name"]),
                "log_traffic": _find_child_text_any(node, ["LogTraffic"]),
                "raw_type": _strip_namespace(node.tag),
            }
        )
    return {"count": len(rules), "rules": rules}


def validate_api_response(xml_text: str) -> None:
    """Raise a safe diagnostic for explicit SFOS XML API failures."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise RuntimeError(f"Sophos API returned invalid XML: {exc}") from exc

    for node in root.iter():
        if _strip_namespace(node.tag).lower() != "status":
            continue
        value = _text(node)
        if not value:
            continue
        lowered = value.lower()
        if any(marker in lowered for marker in ["failure", "failed", "denied", "unauthori"]):
            raise RuntimeError(f"Sophos API login failed: {value}")


def parse_nat_rules(xml_text: str) -> dict[str, Any]:
    root = ET.fromstring(xml_text)
    rules = []
    for node in root.iter():
        if _strip_namespace(node.tag) != "NATRule":
            continue
        name = _find_child_text_any(node, ["Name", "RuleName"]) or _find_text_any(node, ["Name", "RuleName"])
        if not name:
            continue
        status = _find_child_text_any(node, ["Status", "Enable", "Enabled"])
        rules.append(
            {
                "name": name,
                "status": status,
                "enabled": _enabled(status),
                "position": _find_child_text_any(node, ["Position"]),
                "original_source": _find_text_any(node, ["OriginalSource", "OriginalSourceNetwork"]),
                "translated_source": _find_text_any(node, ["TranslatedSource", "TranslatedSourceNetwork"]),
                "original_destination": _find_text_any(node, ["OriginalDestination", "OriginalDestinationNetwork"]),
                "translated_destination": _find_text_any(node, ["TranslatedDestination", "TranslatedDestinationNetwork"]),
                "services": _list_texts(node, ["Services", "ServiceList"], ["Service", "Name"]),
                "raw_type": _strip_namespace(node.tag),
            }
        )
    return {"count": len(rules), "rules": rules}


def _enabled_count(rules: list[dict[str, Any]], enabled: bool) -> int:
    return sum(1 for rule in rules if rule.get("enabled") is enabled)


def _breakdown(values: list[str | None]) -> dict[str, int]:
    cleaned = [value for value in values if value]
    return dict(Counter(cleaned).most_common())


def _zone_breakdown(rules: list[dict[str, Any]], key: str) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for rule in rules:
        for zone in rule.get(key) or []:
            if zone:
                counter[str(zone)] += 1
    return dict(counter.most_common())


def _nat_translation_type(rule: dict[str, Any]) -> str:
    if rule.get("translated_destination"):
        return "dnat"
    if rule.get("translated_source"):
        return "snat"
    return "other"


def build_dashboard_summary(
    firewall_rules: dict[str, Any] | None,
    nat_rules: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build UI-friendly counters and breakdowns for dashboard cards.

    The XML API parser keeps the original rule rows mostly flat for tables. This
    helper adds aggregate values that are stable for frontend cards and charts.
    """
    fw_rows = list((firewall_rules or {}).get("rules") or [])
    nat_rows = list((nat_rules or {}).get("rules") or [])
    fw_enabled = _enabled_count(fw_rows, True)
    fw_disabled = _enabled_count(fw_rows, False)
    nat_enabled = _enabled_count(nat_rows, True)
    nat_disabled = _enabled_count(nat_rows, False)
    nat_translation_counts = Counter(_nat_translation_type(rule) for rule in nat_rows)

    return {
        "cards": {
            "firewall_total": len(fw_rows),
            "firewall_enabled": fw_enabled,
            "firewall_disabled": fw_disabled,
            "nat_total": len(nat_rows),
            "nat_enabled": nat_enabled,
            "nat_disabled": nat_disabled,
            "logged_firewall_rules": sum(
                1 for rule in fw_rows if _enabled(str(rule.get("log_traffic") or "")) is True
            ),
        },
        "firewall_action_breakdown": _breakdown([rule.get("action") for rule in fw_rows]),
        "firewall_source_zone_breakdown": _zone_breakdown(fw_rows, "source_zones"),
        "firewall_destination_zone_breakdown": _zone_breakdown(fw_rows, "destination_zones"),
        "nat_translation_breakdown": {
            "dnat": nat_translation_counts.get("dnat", 0),
            "snat": nat_translation_counts.get("snat", 0),
            "other": nat_translation_counts.get("other", 0),
        },
    }


def sanitize_error(exc: Exception) -> str:
    message = str(exc)
    if not message:
        message = exc.__class__.__name__
    message = re.sub(r"<Password>.*?</Password>", "<Password>***</Password>", message, flags=re.I | re.S)
    return message
