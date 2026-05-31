from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sophos-xg-dashboard"))

import httpx
import pytest

from app.sophos_api import SophosClient, build_dashboard_summary, parse_firewall_rules, parse_nat_rules, sanitize_error


FIREWALL_XML = """
<Response>
  <FirewallRule>
    <Name>Allow LAN to WAN</Name>
    <Status>Enable</Status>
    <Action>Accept</Action>
    <Position>1</Position>
    <SourceZones><Zone>LAN</Zone></SourceZones>
    <DestinationZones><Zone>WAN</Zone></DestinationZones>
    <Services><Service>HTTP</Service><Service>HTTPS</Service></Services>
    <LogTraffic>Enable</LogTraffic>
  </FirewallRule>
  <FirewallRule>
    <Name>Drop Guest to LAN</Name>
    <Status>Disable</Status>
    <Action>Drop</Action>
    <Position>2</Position>
    <SourceZones><Zone>GUEST</Zone></SourceZones>
    <DestinationZones><Zone>LAN</Zone></DestinationZones>
    <Services><Service>Any</Service></Services>
    <LogTraffic>Disable</LogTraffic>
  </FirewallRule>
</Response>
"""

NAT_XML = """
<Response>
  <NATRule>
    <Name>DNAT Web</Name>
    <Status>Enable</Status>
    <Position>1</Position>
    <OriginalSource>Any</OriginalSource>
    <OriginalDestination>WAN Port</OriginalDestination>
    <TranslatedDestination>web-server</TranslatedDestination>
    <Services><Service>HTTPS</Service></Services>
  </NATRule>
  <NATRule>
    <Name>SNAT Guests</Name>
    <Status>Enable</Status>
    <Position>2</Position>
    <OriginalSource>GUEST_NET</OriginalSource>
    <TranslatedSource>WAN Interface</TranslatedSource>
    <OriginalDestination>Any</OriginalDestination>
    <Services><Service>Any</Service></Services>
  </NATRule>
</Response>
"""


def test_dashboard_summary_exposes_card_statistics_and_breakdowns():
    firewall = parse_firewall_rules(FIREWALL_XML)
    nat = parse_nat_rules(NAT_XML)

    summary = build_dashboard_summary(firewall, nat)

    assert summary["cards"] == {
        "firewall_total": 2,
        "firewall_enabled": 1,
        "firewall_disabled": 1,
        "nat_total": 2,
        "nat_enabled": 2,
        "nat_disabled": 0,
        "logged_firewall_rules": 1,
    }
    assert summary["firewall_action_breakdown"] == {"Accept": 1, "Drop": 1}
    assert summary["firewall_source_zone_breakdown"] == {"LAN": 1, "GUEST": 1}
    assert summary["nat_translation_breakdown"] == {"dnat": 1, "snat": 1, "other": 0}


def test_sophos_client_sends_xml_as_reqxml_form_field():
    client = SophosClient(host="https://192.0.2.10:4444", username="api-user", password="secret")

    data = client.form_data("<Get><FirewallRule></FirewallRule></Get>")

    assert list(data) == ["reqxml"]
    assert "<Username>api-user</Username>" in data["reqxml"]
    assert "<Password>secret</Password>" in data["reqxml"]
    assert "<Get><FirewallRule></FirewallRule></Get>" in data["reqxml"]


@pytest.mark.anyio
async def test_sophos_client_reports_authentication_failure(monkeypatch):
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/webconsole/APIController"
        assert b"reqxml=" in request.content
        return httpx.Response(
            200,
            text='''<?xml version="1.0" encoding="UTF-8"?>
<Response><Login><status>Authentication Failure</status></Login></Response>''',
        )

    class MockAsyncClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            super().__init__(transport=httpx.MockTransport(handler), *args, **kwargs)

    monkeypatch.setattr("app.sophos_api.httpx.AsyncClient", MockAsyncClient)
    client = SophosClient(host="https://192.0.2.10:4444", username="bad", password="bad")

    with pytest.raises(RuntimeError, match="Sophos API login failed: Authentication Failure"):
        await client.get_firewall_rules_raw()


def test_sanitize_error_falls_back_to_exception_type_for_empty_messages():
    assert sanitize_error(TimeoutError()) == "TimeoutError"


def test_frontend_contains_home_assistant_style_stat_cards_and_filterable_tables():
    html = (ROOT / "sophos-xg-dashboard/app/templates/index.html").read_text(encoding="utf-8")

    for required_id in [
        "fw-enabled-count",
        "fw-disabled-count",
        "nat-enabled-count",
        "logged-fw-count",
        "fw-action-breakdown",
        "nat-translation-breakdown",
        "fw-filter",
        "nat-filter",
    ]:
        assert required_id in html

    assert "ha-card" in html
    assert "renderBreakdown" in html
    assert "filterTable" in html
