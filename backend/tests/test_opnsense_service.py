"""Tests for the OPNsense API client (parsers + a mocked end-to-end fetch)."""

from unittest.mock import patch

import httpx
import pytest

from app.services import opnsense_service as svc
from app.services.opnsense_service import OpnsenseError, fetch_opnsense_inventory

_IFACES = {
    "rows": [
        {"identifier": "lan", "description": "LAN", "device": "igc1", "addr4": "192.168.1.1/24", "status": "up"},
        {"identifier": "wan", "description": "WAN", "device": "igc0", "addr4": "203.0.113.5/30", "status": "up"},
    ]
}
_ARP = {
    "rows": [
        {"ip": "192.168.1.10", "mac": "AA:BB:CC:00:00:01", "intf": "igc1", "manufacturer": "Acme", "hostname": ""},
        {"ip": "192.168.1.1", "mac": "AA:BB:CC:00:00:99", "intf": "igc1"},  # the firewall itself
    ]
}
_LEASES = {
    "rows": [
        {"address": "192.168.1.10", "hwaddr": "aa:bb:cc:00:00:01", "hostname": "nas", "state": "active"},
        {"address": "192.168.1.20", "hwaddr": "aa:bb:cc:00:00:02", "hostname": "old", "state": "expired"},
    ]
}
_WG = {
    "rows": [
        {"type": "interface", "name": "wg0"},
        {
            "type": "peer", "name": "laptop", "public-key": "PUBKEY1=", "endpoint": "198.51.100.7:51820",
            "allowed-ips": "10.10.0.2/32, 172.16.5.0/24", "latest-handshake": "12s",
        },
    ]
}
_ROUTES = {
    "rows": [
        {"destination": "10.20.0.0/16", "gateway": "192.168.1.254", "flags": "UGS", "interface-name": "lan"},
        {"destination": "192.168.1.0/24", "gateway": "link#2", "flags": "U", "interface-name": "lan"},
        # What a WireGuard allowed-IPs route looks like on a real firewall.
        {"destination": "10.88.0.0/24", "gateway": "link#12", "flags": "US", "netif": "wg2", "intf_description": "Branch"},
        {"destination": "10.77.0.7", "gateway": "link#14", "flags": "UHS", "netif": "wg0"},
        {"destination": "192.168.1.1", "gateway": "link#7", "flags": "UHS", "intf_description": "Loopback"},
        {"destination": "default", "gateway": "203.0.113.6", "flags": "UGS"},
    ]
}
_STATIC = {"rows": [{"network": "10.30.0.0/24", "gateway": "LAN_GW", "disabled": "0"}]}


def _handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    table = {
        "/api/core/firmware/status": {"product_version": "25.1.5"},
        "/api/diagnostics/system/system_information": {"name": "fw.home.lan"},
        "/api/interfaces/overview/interfaces_info": _IFACES,
        "/api/diagnostics/interface/search_arp": _ARP,
        "/api/dhcpv4/leases/search_lease": _LEASES,
        "/api/wireguard/service/show": _WG,
        "/api/diagnostics/interface/get_routes": _ROUTES,
        "/api/routes/routes/searchroute": _STATIC,
    }
    if path in table:
        return httpx.Response(200, json=table[path])
    return httpx.Response(404, json={})  # plugin not installed


def _patch(handler):
    real = httpx.AsyncClient

    def factory(**kwargs):
        kwargs.pop("verify", None)
        return real(transport=httpx.MockTransport(handler), **kwargs)

    return patch("app.services.opnsense_service.httpx.AsyncClient", factory)


async def test_full_fetch_maps_firewall_clients_vpn_and_networks():
    with _patch(_handler):
        data = await fetch_opnsense_inventory("fw.lan", 443, "k", "s")

    by_ieee = {d["ieee_address"]: d for d in data["devices"]}
    fw = by_ieee["opnsense-fw.lan"]
    assert fw["type"] == "firewall"
    assert fw["ip"] == "192.168.1.1"
    assert fw["label"] == "fw.home.lan"
    assert any(p["key"] == "Version" and p["value"] == "25.1.5" for p in fw["properties"])

    # ARP + DHCP merge into one row by MAC; the firewall's own ARP entry and the
    # expired lease are dropped.
    nas = by_ieee["opnsense-client-aa:bb:cc:00:00:01"]
    assert nas["hostname"] == "nas"
    assert nas["vendor"] == "Acme"
    assert "opnsense-client-aa:bb:cc:00:00:02" not in by_ieee
    assert "opnsense-client-aa:bb:cc:00:00:99" not in by_ieee

    wg = by_ieee["opnsense-wg-PUBKEY1="]
    assert wg["ip"] == "10.10.0.2"
    assert (fw["ieee_address"], wg["ieee_address"]) in data["links"]

    cidrs = {n["cidr"]: n["source"] for n in data["networks"]}
    assert cidrs == {
        "10.20.0.0/16": "route", "10.30.0.0/24": "static", "172.16.5.0/24": "wireguard", "10.88.0.0/24": "route",
    }
    assert next(n for n in data["networks"] if n["cidr"] == "10.88.0.0/24")["via"] == "interface Branch"


async def test_modes_can_be_turned_off():
    with _patch(_handler):
        data = await fetch_opnsense_inventory("fw.lan", 443, "k", "s", clients=False, vpn=False, routes=False)
    assert [d["type"] for d in data["devices"]] == ["firewall"]
    assert data["links"] == [] and data["networks"] == []


async def test_bad_key_raises_sanitized_error():
    def deny(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={})

    with _patch(deny), pytest.raises(OpnsenseError) as exc:
        await fetch_opnsense_inventory("fw.lan", 443, "key123", "secret456")
    assert "Authentication failed" in str(exc.value)
    assert "secret456" not in str(exc.value)


async def test_connection_test_reports_version():
    with _patch(_handler):
        ok, msg = await svc.test_opnsense_connection("fw.lan", 443, "k", "s")
    assert ok and "25.1.5" in msg


def test_legacy_interface_shape():
    legacy = {"igc1": {"description": "LAN", "status": "up", "ipv4": [{"ipaddr": "10.0.0.1", "subnetbits": 24}]}}
    out = svc._interfaces_from(legacy)
    assert out[0]["cidr"] == "10.0.0.1/24" and out[0]["name"] == "LAN"


def test_dns_override_merges_into_existing_ip_row_without_duplicate():
    acc: dict = {}
    svc._merge_host(acc, svc._hosts_from_arp([{"ip": "192.168.1.30", "mac": "aa:bb:cc:00:00:03"}], set())[0])
    svc._merge_host(acc, svc._hosts_from_overrides([{"hostname": "printer", "domain": "lan", "server": "192.168.1.30"}], set())[0])
    assert len(acc) == 1
    row = next(iter(acc.values()))
    assert row["hostname"] == "printer.lan" and row["label"] == "printer"
