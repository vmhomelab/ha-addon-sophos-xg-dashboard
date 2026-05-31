from __future__ import annotations

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

    async def post_xml(self, payload: str) -> str:
        if not self.username or not self.password:
            raise RuntimeError("Sophos username/password are not configured")

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=self.timeout) as client:
            response = await client.post(
                self.api_url,
                content=self.wrap(payload),
                headers={"Content-Type": "application/xml"},
            )
            response.raise_for_status()
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
        name = _find_text_any(node, ["Name", "RuleName"])
        if not name:
            continue
        rules.append(
            {
                "name": name,
                "status": _find_text_any(node, ["Status", "Enable"]),
                "enabled": _enabled(_find_text_any(node, ["Status", "Enable"])),
                "action": _find_text_any(node, ["Action"]),
                "position": _find_text_any(node, ["Position"]),
                "source_zones": _list_texts(node, ["SourceZones", "SourceZone"], ["Zone", "Name"]),
                "destination_zones": _list_texts(node, ["DestinationZones", "DestinationZone"], ["Zone", "Name"]),
                "services": _list_texts(node, ["Services", "ServiceList"], ["Service", "Name"]),
                "log_traffic": _find_text_any(node, ["LogTraffic"]),
                "raw_type": _strip_namespace(node.tag),
            }
        )
    return {"count": len(rules), "rules": rules}


def parse_nat_rules(xml_text: str) -> dict[str, Any]:
    root = ET.fromstring(xml_text)
    rules = []
    for node in root.iter():
        if _strip_namespace(node.tag) != "NATRule":
            continue
        name = _find_text_any(node, ["Name", "RuleName"])
        if not name:
            continue
        rules.append(
            {
                "name": name,
                "status": _find_text_any(node, ["Status", "Enable"]),
                "enabled": _enabled(_find_text_any(node, ["Status", "Enable"])),
                "position": _find_text_any(node, ["Position"]),
                "original_source": _find_text_any(node, ["OriginalSource", "OriginalSourceNetwork"]),
                "translated_source": _find_text_any(node, ["TranslatedSource", "TranslatedSourceNetwork"]),
                "original_destination": _find_text_any(node, ["OriginalDestination", "OriginalDestinationNetwork"]),
                "translated_destination": _find_text_any(node, ["TranslatedDestination", "TranslatedDestinationNetwork"]),
                "services": _list_texts(node, ["Services", "ServiceList"], ["Service", "Name"]),
                "raw_type": _strip_namespace(node.tag),
            }
        )
    return {"count": len(rules), "rules": rules}


def sanitize_error(exc: Exception) -> str:
    message = str(exc)
    message = re.sub(r"<Password>.*?</Password>", "<Password>***</Password>", message, flags=re.I | re.S)
    return message
