"""OPNsense firewall REST API client.

Auth is an API key + secret sent as HTTP Basic (``key:secret``), created under
System → Access → Users → API keys. Read-only is enough: every call here is a
GET (or a read-only search POST).

What it imports, all best-effort (a plugin that is not installed, or a
privilege the key lacks, only drops that part of the result):

- the firewall itself (``router`` node) with its interfaces and version,
- LAN hosts: ARP table, DHCP leases (ISC and Kea), Unbound host overrides,
- VPN peers: WireGuard, OpenVPN sessions, IPsec phase 1,
- routed networks (kernel routes, static routes, gateways, VPN allowed-IPs),
  returned separately so the UI can offer them as scan ranges.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

import httpx

from app.services.mac_utils import normalize_mac
from app.services.zigbee_service import merge_zigbee_properties

logger = logging.getLogger(__name__)

# Same NodeProperty shape and visibility rules as every other importer.
merge_opnsense_properties = merge_zigbee_properties

SOURCE_FIREWALL = "opnsense"
SOURCE_CLIENT = "opnsense-client"
SOURCE_VPN = "opnsense-vpn"
SOURCES = (SOURCE_FIREWALL, SOURCE_CLIENT, SOURCE_VPN)

_CONNECT_TIMEOUT = 8.0
_READ_TIMEOUT = 20.0


class OpnsenseError(ConnectionError):
    """The firewall could not be reached or refused the key (message is safe)."""


def sanitize_error(exc: BaseException) -> str:
    """Credential-free message for an httpx error (the key never leaves)."""
    logger.warning("OPNsense error (sanitized for client): %r", exc)
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        if code in (401, 403):
            return "Authentication failed — check the API key/secret and its privileges"
        if code == 404:
            return "OPNsense API path not found — is this an OPNsense firewall?"
        return f"OPNsense API returned HTTP {code}"
    raw = str(exc).lower()
    if "name or service not known" in raw or "getaddrinfo" in raw or "nodename nor servname" in raw:
        return "OPNsense host could not be resolved"
    if "refused" in raw:
        return "Connection refused by OPNsense host"
    if "certificate" in raw or "ssl" in raw or "tls" in raw:
        return "TLS verification failed — disable TLS verification for self-signed certs"
    if "timed out" in raw or "timeout" in raw:
        return "Connection to OPNsense host timed out"
    return "OPNsense connection failed"


def _client(host: str, port: int, key: str, secret: str, verify_tls: bool) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=f"https://{host}:{port}/api",
        auth=(key, secret),
        verify=verify_tls,
        timeout=httpx.Timeout(_READ_TIMEOUT, connect=_CONNECT_TIMEOUT),
    )


async def _get(client: httpx.AsyncClient, path: str) -> Any:
    resp = await client.get(path)
    resp.raise_for_status()
    return resp.json()


async def _search(client: httpx.AsyncClient, path: str) -> list[dict[str, Any]]:
    """Rows of an OPNsense grid endpoint (``{"rows": [...]}``), GET then POST.

    Grid endpoints answer either verb depending on the version; both return the
    same envelope. Raises on transport/HTTP failure — callers decide whether the
    part is optional.
    """
    try:
        data = await _get(client, path)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code not in (400, 404, 405):
            raise
        resp = await client.post(path, json={"current": 1, "rowCount": -1})
        resp.raise_for_status()
        data = resp.json()
    rows = data.get("rows") if isinstance(data, dict) else data
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []


async def _optional(coro: Any, what: str) -> Any:
    """Await ``coro``; a failed optional part logs and yields None."""
    try:
        return await coro
    except (httpx.HTTPError, ValueError) as exc:
        logger.info("OPNsense %s unavailable: %r", what, exc)
        return None


# --- helpers ----------------------------------------------------------------


def _text(value: Any) -> str | None:
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return None


def _ipv4(value: Any) -> str | None:
    text = _text(value)
    if not text:
        return None
    text = text.split("/")[0]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    return str(ip) if ip.version == 4 else None


def _network(value: Any) -> ipaddress.IPv4Network | None:
    """A routable, non-trivial IPv4 network from ``a.b.c.d/n`` text, else None."""
    text = _text(value)
    if not text:
        return None
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    if net.version != 4 or net.prefixlen == 0:
        return None
    if net.is_loopback or net.is_multicast or net.is_link_local:
        return None
    return net  # type: ignore[return-value]


def _prop(key: str, value: Any, icon: str | None = None) -> dict[str, Any]:
    return {"key": key, "value": str(value), "icon": icon, "visible": False}


def _device(
    ieee: str,
    *,
    type_: str,
    source: str,
    label: str | None = None,
    hostname: str | None = None,
    ip: str | None = None,
    mac: str | None = None,
    vendor: str | None = None,
    model: str | None = None,
    props: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "ieee_address": ieee,
        "type": type_,
        "source": source,
        "label": label or hostname or ip or ieee,
        "hostname": hostname,
        "ip": ip,
        "mac": normalize_mac(mac) if mac else None,
        "vendor": vendor,
        "model": model,
        "properties": props or [],
    }


# --- firewall + interfaces --------------------------------------------------


def firewall_ieee(host: str) -> str:
    return f"opnsense-{host.lower()}"


def _interfaces_from(data: Any) -> list[dict[str, Any]]:
    """Normalize interface info from either API generation.

    New (24.x+): ``/interfaces/overview/interfaces_info`` → ``{"rows": [...]}``
    with ``identifier``, ``description``, ``addr4``, ``status``.
    Old: ``/diagnostics/interface/getInterfaceConfig`` → ``{name: {...}}`` with
    ``ipv4: [{ipaddr, subnetbits}]``.
    """
    out: list[dict[str, Any]] = []
    if isinstance(data, dict) and isinstance(data.get("rows"), list):
        for row in data["rows"]:
            if not isinstance(row, dict):
                continue
            addr = _text(row.get("addr4"))
            if not addr and isinstance(row.get("ipv4"), list) and row["ipv4"]:
                first = row["ipv4"][0]
                addr = f"{first.get('ipaddr')}/{first.get('subnetbits')}"
            out.append(
                {
                    "name": _text(row.get("description")) or _text(row.get("identifier")) or "?",
                    "device": _text(row.get("device")) or _text(row.get("identifier")),
                    "cidr": addr,
                    "up": str(row.get("status", "")).lower() in ("up", "active", "associated"),
                }
            )
    elif isinstance(data, dict):
        for dev, row in data.items():
            if not isinstance(row, dict):
                continue
            addr = None
            ipv4 = row.get("ipv4")
            if isinstance(ipv4, list) and ipv4:
                addr = f"{ipv4[0].get('ipaddr')}/{ipv4[0].get('subnetbits')}"
            out.append(
                {
                    "name": _text(row.get("description")) or dev,
                    "device": dev,
                    "cidr": addr,
                    "up": str(row.get("status", "")).lower() in ("up", "active", "associated"),
                }
            )
    return out


def _firewall_device(
    host: str,
    version: str | None,
    hostname: str | None,
    interfaces: list[dict[str, Any]],
) -> dict[str, Any]:
    props = [_prop("Source", "OPNsense")]
    if version:
        props.append(_prop("Version", version))
    lan_ip: str | None = None
    for itf in interfaces:
        if not itf.get("cidr") or str(itf["cidr"]).startswith(("127.", "None")):
            continue
        props.append(_prop(f"Interface {itf['name']}", itf["cidr"], "Network"))
        if lan_ip is None and itf["name"].lower() == "lan":
            lan_ip = _ipv4(itf["cidr"])
    return _device(
        firewall_ieee(host),
        type_="firewall",
        source=SOURCE_FIREWALL,
        label=hostname or "OPNsense",
        hostname=hostname,
        ip=lan_ip or _ipv4(host),
        vendor="OPNsense",
        model=f"OPNsense {version}" if version else "OPNsense",
        props=props,
    )


# --- LAN hosts --------------------------------------------------------------


def _hosts_from_arp(rows: list[dict[str, Any]], infra_ips: set[str]) -> list[dict[str, Any]]:
    out = []
    for r in rows:
        ip = _ipv4(r.get("ip"))
        mac = normalize_mac(r.get("mac"))
        if not ip or not mac or ip in infra_ips:
            continue
        hostname = _text(r.get("hostname"))
        props = [_prop("Source", "OPNsense ARP")]
        if _text(r.get("intf_description") or r.get("intf")):
            props.append(_prop("Interface", r.get("intf_description") or r.get("intf"), "Network"))
        out.append(
            _device(
                f"opnsense-client-{mac}",
                type_="generic",
                source=SOURCE_CLIENT,
                hostname=hostname,
                ip=ip,
                mac=mac,
                vendor=_text(r.get("manufacturer")),
                props=props,
            )
        )
    return out


def _hosts_from_leases(rows: list[dict[str, Any]], infra_ips: set[str]) -> list[dict[str, Any]]:
    """Normalize ISC (``address``/``hwaddr``) and Kea (``address``/``hwaddr``) leases."""
    out = []
    for r in rows:
        ip = _ipv4(r.get("address") or r.get("ip"))
        mac = normalize_mac(r.get("hwaddr") or r.get("mac"))
        if not ip or not mac or ip in infra_ips:
            continue
        state = str(r.get("state") or r.get("status") or "").lower()
        if state in ("expired", "free", "abandoned", "backup"):
            continue
        props = [_prop("Source", "OPNsense DHCP")]
        itf = _text(r.get("if_descr") or r.get("if") or r.get("interface"))
        if itf:
            props.append(_prop("Interface", itf, "Network"))
        out.append(
            _device(
                f"opnsense-client-{mac}",
                type_="generic",
                source=SOURCE_CLIENT,
                hostname=(_text(r.get("hostname")) or "").rstrip(".") or None,
                ip=ip,
                mac=mac,
                vendor=_text(r.get("man") or r.get("manufacturer")),
                props=props,
            )
        )
    return out


def _hosts_from_overrides(rows: list[dict[str, Any]], infra_ips: set[str]) -> list[dict[str, Any]]:
    """Unbound host overrides: static name → IP, no MAC (keyed by IP)."""
    out = []
    for r in rows:
        ip = _ipv4(r.get("server") or r.get("ip"))
        host = _text(r.get("hostname"))
        if not ip or not host or ip in infra_ips or str(r.get("enabled", "1")) == "0":
            continue
        domain = _text(r.get("domain"))
        fqdn = f"{host}.{domain}" if domain else host
        out.append(
            _device(
                f"opnsense-dns-{ip}",
                type_="generic",
                source=SOURCE_CLIENT,
                label=host,
                hostname=fqdn,
                ip=ip,
                props=[_prop("Source", "OPNsense Unbound"), _prop("DNS name", fqdn, "Globe")],
            )
        )
    return out


# --- VPN --------------------------------------------------------------------


def _wireguard_peers(rows: list[dict[str, Any]], fw_ieee: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Peers from ``/wireguard/service/show`` rows (``type == 'peer'``)."""
    devices: list[dict[str, Any]] = []
    nets: list[dict[str, str]] = []
    for r in rows:
        if r.get("type") != "peer":
            continue
        pub = _text(r.get("public-key"))
        name = _text(r.get("name")) or (pub[:8] if pub else None)
        if not pub or not name:
            continue
        endpoint = _text(r.get("endpoint"))
        allowed = _text(r.get("allowed-ips")) or ""
        props = [
            _prop("Source", "OPNsense WireGuard"),
            _prop("Public key", pub, "KeyRound"),
        ]
        if endpoint:
            props.append(_prop("Endpoint", endpoint, "Globe"))
        if allowed:
            props.append(_prop("Allowed IPs", allowed, "Network"))
        if _text(r.get("latest-handshake")):
            props.append(_prop("Latest handshake", r.get("latest-handshake"), "Clock"))
        tunnel_ip = None
        for cidr in allowed.replace(" ", "").split(","):
            net = _network(cidr)
            if net is None:
                continue
            if net.prefixlen == 32:
                tunnel_ip = tunnel_ip or str(net.network_address)
            else:
                nets.append({"cidr": str(net), "via": f"WireGuard peer {name}", "source": "wireguard"})
        devices.append(
            _device(
                f"opnsense-wg-{pub}",
                type_="generic",
                source=SOURCE_VPN,
                label=name,
                hostname=name,
                ip=tunnel_ip,
                props=props,
            )
        )
    return devices, nets


def _openvpn_sessions(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for r in rows:
        cn = _text(r.get("common_name") or r.get("name"))
        if not cn or cn == "UNDEF":
            continue
        vip = _ipv4(r.get("virtual_address"))
        real = _text(r.get("real_address"))
        props = [_prop("Source", "OPNsense OpenVPN")]
        if real:
            props.append(_prop("Remote address", real, "Globe"))
        out.append(
            _device(
                f"opnsense-ovpn-{cn}",
                type_="generic",
                source=SOURCE_VPN,
                label=cn,
                hostname=cn,
                ip=vip,
                props=props,
            )
        )
    return out


def _ipsec_tunnels(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    devices: list[dict[str, Any]] = []
    nets: list[dict[str, str]] = []
    for r in rows:
        name = _text(r.get("name") or r.get("description"))
        ident = _text(r.get("ikeid") or r.get("id") or r.get("uuid")) or name
        if not name or not ident:
            continue
        remote = _text(r.get("remote-host") or r.get("remote_host") or r.get("remote-addrs"))
        props = [_prop("Source", "OPNsense IPsec")]
        if remote:
            props.append(_prop("Remote gateway", remote, "Globe"))
        if _text(r.get("state") or r.get("phase1desc")):
            props.append(_prop("State", r.get("state") or r.get("phase1desc"), "Activity"))
        devices.append(
            _device(
                f"opnsense-ipsec-{ident}",
                type_="router",
                source=SOURCE_VPN,
                label=name,
                hostname=name,
                ip=_ipv4(remote),
                props=props,
            )
        )
        for key in ("remote-ts", "remote_ts", "remote_subnet"):
            for cidr in str(r.get(key) or "").replace(" ", "").split(","):
                net = _network(cidr)
                if net:
                    nets.append({"cidr": str(net), "via": f"IPsec {name}", "source": "ipsec"})
    return devices, nets


# --- routed networks --------------------------------------------------------


def _networks_from_routes(
    kernel_routes: list[dict[str, Any]],
    static_routes: list[dict[str, Any]],
    local_cidrs: set[str],
) -> list[dict[str, str]]:
    """Networks reachable through a gateway rather than directly attached."""
    nets: list[dict[str, str]] = []
    for r in kernel_routes:
        net = _network(r.get("destination"))
        flags = str(r.get("flags") or "")
        itf = _text(r.get("intf_description") or r.get("interface-name") or r.get("netif"))
        # Reachable through something else than a directly-attached link: a
        # gateway ("G") or a static route ("S", e.g. a WireGuard allowed-IPs
        # route pointing at the tunnel interface). Host routes ("H"), loopback
        # and the networks of the firewall's own interfaces are not "other
        # networks".
        if net is None or "H" in flags or ("G" not in flags and "S" not in flags):
            continue
        if str(net) in local_cidrs or net.prefixlen == 32 or itf == "Loopback":
            continue
        gw = _text(r.get("gateway")) or "gateway"
        via = f"interface {itf}" if gw.startswith("link#") and itf else (f"{gw} ({itf})" if itf else gw)
        nets.append({"cidr": str(net), "via": via, "source": "route"})
    for r in static_routes:
        if str(r.get("disabled", "0")) == "1":
            continue
        net = _network(r.get("network"))
        if net is None or str(net) in local_cidrs:
            continue
        gw = _text(r.get("gateway")) or "gateway"
        nets.append({"cidr": str(net), "via": f"static route via {gw}", "source": "static"})
    return nets


def _dedupe_networks(nets: list[dict[str, str]], local_cidrs: set[str]) -> list[dict[str, str]]:
    # The kernel/static route says which interface carries the network, which is
    # more useful than the VPN peer that merely allows it: it wins a tie.
    priority = {"route": 0, "static": 1, "ipsec": 2, "wireguard": 3}
    seen: dict[str, dict[str, str]] = {}
    for n in sorted(nets, key=lambda n: priority.get(n["source"], 9)):
        if n["cidr"] in local_cidrs:
            continue
        seen.setdefault(n["cidr"], n)
    return sorted(seen.values(), key=lambda n: ipaddress.ip_network(n["cidr"]))


# --- public API -------------------------------------------------------------


async def test_opnsense_connection(
    host: str, port: int, key: str, secret: str, verify_tls: bool = False
) -> tuple[bool, str]:
    """Reachability + auth check via ``/core/firmware/status``."""
    try:
        async with _client(host, port, key, secret, verify_tls) as client:
            data = await _get(client, "/core/firmware/status")
        version = _version(data)
        return True, f"Connected to OPNsense {version}" if version else "Connected to OPNsense"
    except httpx.HTTPError as exc:
        return False, sanitize_error(exc)
    except Exception as exc:  # noqa: BLE001 — safe message, log the rest
        logger.exception("Unexpected error during OPNsense connection test")
        return False, sanitize_error(exc)


def _version(data: Any) -> str | None:
    if not isinstance(data, dict):
        return None
    return _text(data.get("product_version")) or _text((data.get("product") or {}).get("product_version"))


async def fetch_opnsense_inventory(
    host: str,
    port: int,
    key: str,
    secret: str,
    verify_tls: bool = False,
    clients: bool = True,
    vpn: bool = True,
    routes: bool = True,
) -> dict[str, Any]:
    """Return ``{"devices": [...], "links": [(src, tgt)], "networks": [...]}``.

    Raises OpnsenseError when the firewall is unreachable or the key is refused.
    """
    try:
        async with _client(host, port, key, secret, verify_tls) as client:
            status = await _get(client, "/core/firmware/status")
            ifaces_raw = await _optional(_get(client, "/interfaces/overview/interfaces_info"), "interfaces") or (
                await _optional(_get(client, "/diagnostics/interface/getInterfaceConfig"), "interface config")
            )
            sysinfo = await _optional(_get(client, "/diagnostics/system/system_information"), "system information")
            hostname = _text(sysinfo.get("name")) if isinstance(sysinfo, dict) else None
            interfaces = _interfaces_from(ifaces_raw)
            fw = _firewall_device(host, _version(status), hostname, interfaces)
            devices: list[dict[str, Any]] = [fw]
            links: list[tuple[str, str]] = []
            networks: list[dict[str, str]] = []

            infra_ips = {i for i in (_ipv4(x.get("cidr")) for x in interfaces) if i}
            local_cidrs = {
                str(n) for n in (_network(x.get("cidr")) for x in interfaces) if n is not None
            }

            if clients:
                hosts: dict[str, dict[str, Any]] = {}
                for loader, conv, what in (
                    ("/diagnostics/interface/search_arp", _hosts_from_arp, "ARP"),
                    ("/dhcpv4/leases/search_lease", _hosts_from_leases, "ISC DHCP leases"),
                    ("/kea/leases4/search", _hosts_from_leases, "Kea leases"),
                    ("/unbound/settings/search_host_override", _hosts_from_overrides, "Unbound overrides"),
                ):
                    rows = await _optional(_search(client, loader), what)
                    for dev in conv(rows or [], infra_ips):
                        _merge_host(hosts, dev)
                devices.extend(hosts.values())

            if vpn:
                wg = await _optional(_search(client, "/wireguard/service/show"), "WireGuard")
                wg_devs, wg_nets = _wireguard_peers(wg or [], fw["ieee_address"])
                ovpn = await _optional(_search(client, "/openvpn/service/search_sessions"), "OpenVPN")
                ipsec = await _optional(_search(client, "/ipsec/sessions/search_phase1"), "IPsec")
                ipsec_devs, ipsec_nets = _ipsec_tunnels(ipsec or [])
                for dev in [*wg_devs, *_openvpn_sessions(ovpn or []), *ipsec_devs]:
                    devices.append(dev)
                    links.append((fw["ieee_address"], dev["ieee_address"]))
                networks.extend(wg_nets + ipsec_nets)

            if routes:
                kernel = await _optional(_search(client, "/diagnostics/interface/get_routes"), "routing table")
                static = await _optional(_search(client, "/routes/routes/searchroute"), "static routes")
                networks.extend(_networks_from_routes(kernel or [], static or [], local_cidrs))

            networks = _dedupe_networks(networks, local_cidrs)
            if networks:
                fw["properties"].append(
                    _prop("Routed networks", ", ".join(n["cidr"] for n in networks[:12]), "Network")
                )
    except httpx.HTTPError as exc:
        raise OpnsenseError(sanitize_error(exc)) from exc

    return {"devices": devices, "links": links, "networks": networks}


def _merge_host(acc: dict[str, dict[str, Any]], dev: dict[str, Any]) -> None:
    """Merge a LAN host by MAC (or ieee for MAC-less DNS rows), filling blanks.

    A DNS override has no MAC: when an ARP/DHCP row on the same IP exists, the
    override only contributes its name to that row instead of a duplicate.
    """
    key = dev["ieee_address"]
    if not dev.get("mac"):
        for existing in acc.values():
            if existing.get("ip") and existing["ip"] == dev.get("ip"):
                existing["hostname"] = existing.get("hostname") or dev.get("hostname")
                if existing["label"] in (None, existing["ip"]):
                    existing["label"] = dev["label"]
                keys = {p["key"] for p in existing["properties"]}
                existing["properties"] += [p for p in dev["properties"] if p["key"] not in keys]
                return
    prev = acc.get(key)
    if prev is None:
        acc[key] = dev
        return
    for field, value in dev.items():
        if field == "properties":
            keys = {p["key"] for p in prev["properties"]}
            prev["properties"] += [p for p in value if p["key"] not in keys]
        elif value and (field != "label" or prev.get("label") in (None, prev.get("ip"))):
            prev[field] = value
