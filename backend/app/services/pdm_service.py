"""Proxmox Datacenter Manager (PDM) inventory service.

Mirrors ``proxmox_service`` but talks to one PDM instance instead of a Proxmox
VE host. PDM is the single pane of glass over several *remotes* (Proxmox VE
clusters/hosts and Proxmox Backup Servers), so one authenticated call to
``GET /api2/json/resources/list`` returns every node, VM and LXC of every
remote. The service returns plain homelable node dicts + parent->child edge
hints; DB persistence lives in the route layer (``app.api.routes.pdm``).

Auth uses a PDM **API token** (never a password). Unlike PVE/PBS, the PDM
header is ``Authorization: PDMAPIToken=<token_id>:<secret>`` (colon, not ``=``)
where ``token_id`` looks like ``user@realm!tokenname``. The ``Auditor`` role on
``/resource`` is all that is needed.

Endpoints used (PDM API viewer, https://pdm.proxmox.com/docs/api-viewer/):
``/version``, ``/remotes/remote`` (best effort, for node addresses),
``/resources/list`` and ``/pve/remotes/{remote}/{qemu|lxc}/{vmid}/config``
(best effort, for the NIC MAC and a static LXC address).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Any

import httpx

from app.services.proxmox_service import (
    _extract_lxc_ip,
    _extract_net_mac,
    _gb,
    _int_or_none,
    merge_proxmox_properties,
)

logger = logging.getLogger(__name__)

# Same property-merge contract as the Proxmox import.
merge_pdm_properties = merge_proxmox_properties

_CONNECT_TIMEOUT = 8.0
_READ_TIMEOUT = 30.0
_CONFIG_CONCURRENCY = 8
_PDM_LABEL = "Proxmox Datacenter Manager"
_MAX_REMOTE_ERROR = 200


def _sanitize_pdm_error(exc: BaseException) -> str:
    """Return a generic, credential-free message for a PDM/HTTP error.

    Raw httpx errors can echo the request URL and, in some stacks, the
    ``Authorization: PDMAPIToken=...:<secret>`` header. Map known patterns to
    coarse categories so the token never reaches an API client. The original
    exception is logged at WARNING for operators.
    """
    logger.warning("PDM error (sanitized for client): %r", exc)
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        if code in (401, 403):
            return "Authentication failed — check the API token and its permissions"
        if code == 404:
            return "PDM API path not found — is this a Proxmox Datacenter Manager host?"
        return f"PDM API returned HTTP {code}"
    raw = str(exc).lower()
    if "name or service not known" in raw or "getaddrinfo" in raw or "nodename nor servname" in raw:
        return "PDM host could not be resolved"
    if "refused" in raw:
        return "Connection refused by PDM host"
    if "certificate" in raw or "ssl" in raw or "tls" in raw:
        return "TLS verification failed — disable 'verify TLS' for self-signed certs"
    if "timed out" in raw or "timeout" in raw:
        return "Connection to PDM host timed out"
    return "PDM connection failed"


def _auth_header(token_id: str, token_secret: str) -> dict[str, str]:
    return {"Authorization": f"PDMAPIToken={token_id}:{token_secret}"}


def _host_ieee(remote: str, node: str) -> str:
    """Synthetic id of a PVE node. ``/`` cannot occur in a remote id, so the
    id is unambiguous whatever the node is called."""
    return f"pdm-{remote}/node/{node}"


def _guest_ieee(remote: str, vmid: Any) -> str:
    """Synthetic id of a guest: a VMID is unique across a PVE cluster, so the
    id survives a migration between nodes of the same remote."""
    return f"pdm-{remote}/{vmid}"


def _pbs_ieee(remote: str, name: str) -> str:
    return f"pdm-{remote}/pbs/{name}"


def _address_ip(address: Any) -> str | None:
    """The address of a remote's node when it is a literal IP (not a name)."""
    if not isinstance(address, str):
        return None
    candidate = address.strip()
    if candidate.startswith("[") and "]" in candidate:  # [::1]:8006
        candidate = candidate[1:candidate.index("]")]
    elif candidate.count(":") == 1:  # host:port
        candidate = candidate.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _node_name(raw: dict[str, Any]) -> str | None:
    name = raw.get("node") or raw.get("name")
    if name:
        return str(name)
    # id = "remote/<remote>/node/<name>"
    rid = raw.get("id")
    if isinstance(rid, str) and "/node/" in rid:
        return rid.rsplit("/node/", 1)[1] or None
    return None


def _host_node(remote: str, raw: dict[str, Any], ip: str | None) -> dict[str, Any] | None:
    name = _node_name(raw)
    if not name:
        return None
    ieee = _host_ieee(remote, name)
    return {
        "id": ieee,
        "label": name,
        "type": "proxmox",
        "ieee_address": ieee,
        "hostname": name,
        "ip": ip,
        "status": "online" if raw.get("status") == "online" else "offline",
        "cpu_count": _int_or_none(raw.get("maxcpu")),
        "ram_gb": _gb(raw.get("maxmem")),
        "disk_gb": None,
        "vendor": "Proxmox VE",
        "model": None,
        "remote": remote,
        "remote_type": "pve",
        "parent_ieee": None,
    }


def _pbs_node(remote: str, raw: dict[str, Any], ip: str | None) -> dict[str, Any] | None:
    name = _node_name(raw)
    if not name:
        return None
    ieee = _pbs_ieee(remote, name)
    return {
        "id": ieee,
        "label": name,
        "type": "server",
        "ieee_address": ieee,
        "hostname": name,
        "ip": ip,
        # A PBS node resource carries no status field: it answered, so it is up.
        "status": "online",
        "cpu_count": _int_or_none(raw.get("maxcpu")),
        "ram_gb": _gb(raw.get("maxmem")),
        "disk_gb": None,
        "vendor": "Proxmox Backup Server",
        "model": None,
        "remote": remote,
        "remote_type": "pbs",
        "parent_ieee": None,
    }


def _guest_node(
    remote: str,
    raw: dict[str, Any],
    kind: str,
    ip: str | None = None,
    mac: str | None = None,
) -> dict[str, Any] | None:
    """Build a vm/lxc node from a ``pve-qemu`` / ``pve-lxc`` resource."""
    vmid = raw.get("vmid")
    if vmid is None:
        return None
    ieee = _guest_ieee(remote, vmid)
    node_type = "vm" if kind == "qemu" else "lxc"
    name = raw.get("name") or f"{node_type}-{vmid}"
    host = raw.get("node")
    return {
        "id": ieee,
        "label": name,
        "type": node_type,
        "ieee_address": ieee,
        "hostname": name,
        "ip": ip,
        "mac": mac,
        "status": "online" if raw.get("status") == "running" else "offline",
        "cpu_count": _int_or_none(raw.get("maxcpu")),
        "ram_gb": _gb(raw.get("maxmem")),
        "disk_gb": _gb(raw.get("maxdisk")),
        "vendor": "Proxmox VE",
        "model": kind.upper(),
        "vmid": vmid,
        "remote": remote,
        "remote_type": "pve",
        "pve_node": host,
        "parent_ieee": _host_ieee(remote, str(host)) if host else None,
    }


def build_pdm_properties(node: dict[str, Any]) -> list[dict[str, Any]]:
    """NodeProperty list for a PDM device (specs + identity), all hidden by
    default like the Proxmox import."""
    props: list[dict[str, Any]] = []
    if node.get("remote"):
        props.append({"key": "Remote", "value": str(node["remote"]), "icon": None, "visible": False})
    if node.get("vmid") is not None:
        props.append({"key": "VMID", "value": str(node["vmid"]), "icon": None, "visible": False})
    if node.get("model"):
        props.append({"key": "Kind", "value": node["model"], "icon": None, "visible": False})
    if node.get("cpu_count") is not None:
        props.append({"key": "CPU Cores", "value": str(node["cpu_count"]), "icon": "Cpu", "visible": False})
    if node.get("ram_gb") is not None:
        props.append({"key": "RAM", "value": f"{node['ram_gb']} GB", "icon": "MemoryStick", "visible": False})
    if node.get("disk_gb") is not None:
        props.append({"key": "Disk", "value": f"{node['disk_gb']} GB", "icon": "HardDrive", "visible": False})
    props.append({"key": "Source", "value": _PDM_LABEL, "icon": None, "visible": False})
    return props


def build_pdm_cluster_links(nodes: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """Chain the PVE hosts of each remote into cluster links.

    A remote with several nodes is a cluster; hosts of *different* remotes are
    unrelated and never linked. Returns consecutive ``(source, target)`` pairs
    per remote, in node order.
    """
    by_remote: dict[str, list[str]] = {}
    for n in nodes:
        if n.get("type") == "proxmox" and n.get("ieee_address"):
            by_remote.setdefault(str(n.get("remote") or ""), []).append(n["ieee_address"])
    pairs: list[tuple[str, str]] = []
    for hosts in by_remote.values():
        pairs.extend((hosts[i], hosts[i + 1]) for i in range(len(hosts) - 1))
    return pairs


async def _get_json(
    client: httpx.AsyncClient, path: str, params: dict[str, Any] | None = None
) -> Any:
    resp = await client.get(path, params=params)
    resp.raise_for_status()
    return resp.json().get("data")


def _remote_addresses(remotes: Any) -> dict[str, tuple[str, list[str]]]:
    """``remote id -> (type, node addresses)`` from ``/remotes/remote``.

    Only ``id``, ``type`` and ``nodes`` are read: that endpoint also carries the
    remote's own ``authid``/``token``, which must never be touched."""
    out: dict[str, tuple[str, list[str]]] = {}
    if not isinstance(remotes, list):
        return out
    for entry in remotes:
        if not isinstance(entry, dict) or not entry.get("id"):
            continue
        nodes = entry.get("nodes")
        addrs: list[str] = []
        if isinstance(nodes, list):
            for n in nodes:
                # Documented as a list of addresses; newer builds may wrap each
                # in an object with a ``hostname`` field.
                addr = n.get("hostname") if isinstance(n, dict) else n
                if isinstance(addr, str):
                    addrs.append(addr)
        out[str(entry["id"])] = (str(entry.get("type") or "pve"), addrs)
    return out


def _single_node_ip(addresses: list[str], node_count: int) -> str | None:
    """A remote with exactly one node and one literal-IP address: that IP is
    the node's. With several nodes the addresses cannot be told apart."""
    if node_count != 1 or len(addresses) != 1:
        return None
    return _address_ip(addresses[0])


def _clip(text: str) -> str:
    return text if len(text) <= _MAX_REMOTE_ERROR else text[:_MAX_REMOTE_ERROR] + "…"


def _parse_resources(
    results: list[Any],
    remote_info: dict[str, tuple[str, list[str]]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Assemble (nodes, raw guest rows, remote errors) from ``/resources/list``.

    Guest rows are returned as ``(remote, kind, raw)`` dicts so their config can
    be fetched before the final node is built."""
    hosts: list[dict[str, Any]] = []
    guests: list[dict[str, Any]] = []
    errors: list[str] = []
    for entry in results:
        if not isinstance(entry, dict):
            continue
        remote = entry.get("remote")
        if not remote:
            continue
        remote = str(remote)
        if entry.get("error"):
            errors.append(f"{remote}: {_clip(str(entry['error']))}")
        resources = [r for r in entry.get("resources") or [] if isinstance(r, dict)]
        addrs = remote_info.get(remote, ("pve", []))[1]
        pve_nodes = sum(1 for r in resources if r.get("type") == "pve-node")
        pbs_nodes = sum(1 for r in resources if r.get("type") == "pbs-node")
        for r in resources:
            kind = r.get("type")
            if kind == "pve-node":
                node = _host_node(remote, r, _single_node_ip(addrs, pve_nodes))
                if node:
                    hosts.append(node)
            elif kind == "pbs-node":
                node = _pbs_node(remote, r, _single_node_ip(addrs, pbs_nodes))
                if node:
                    hosts.append(node)
            elif kind in ("pve-qemu", "pve-lxc"):
                if r.get("template"):
                    continue  # templates are not machines
                guests.append({"remote": remote, "kind": kind[4:], "raw": r})
    return hosts, guests, errors


async def _guest_net(
    client: httpx.AsyncClient, sem: asyncio.Semaphore, remote: str, kind: str, raw: dict[str, Any]
) -> tuple[str | None, str | None]:
    """Best-effort (ip, mac) of a guest from its config. Never raises.

    The MAC comes from ``net0`` for both kinds (agent-free, works for stopped
    guests); a static IPv4 only exists for LXC. PDM exposes no guest-agent call.
    """
    vmid = raw.get("vmid")
    if vmid is None:
        return None, None
    params: dict[str, Any] = {"state": "active"}
    if raw.get("node"):
        params["node"] = raw["node"]
    try:
        async with sem:
            config = await _get_json(client, f"/pve/remotes/{remote}/{kind}/{vmid}/config", params)
    except httpx.HTTPError as exc:
        logger.debug("PDM config fetch failed for %s/%s: %s", remote, vmid, exc)
        return None, None
    if not isinstance(config, dict):
        return None, None
    ip = _extract_lxc_ip(config) if kind == "lxc" else None
    return ip, _extract_net_mac(config)


async def fetch_pdm_inventory(
    host: str,
    port: int,
    token_id: str,
    token_secret: str,
    verify_tls: bool = True,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str | None]:
    """Fetch remotes' nodes + VMs + LXC from PDM, return ``(nodes, edges, notice)``.

    ``notice`` is a non-fatal advisory (a remote that failed to answer, a token
    that sees nothing) or ``None``.

    Raises:
        ConnectionError: transport/DNS/TLS/auth failures (sanitized message).
        ValueError: malformed API response.
    """
    base_url = f"https://{host}:{port}/api2/json"
    timeout = httpx.Timeout(_READ_TIMEOUT, connect=_CONNECT_TIMEOUT)
    try:
        async with httpx.AsyncClient(
            base_url=base_url,
            headers=_auth_header(token_id, token_secret),
            verify=verify_tls,
            timeout=timeout,
        ) as client:
            try:
                remote_info = _remote_addresses(await _get_json(client, "/remotes/remote"))
            except httpx.HTTPError as exc:
                # Needs more rights than the resource list; the addresses are a
                # nicety, never a reason to fail the import.
                logger.info("PDM /remotes/remote unavailable (%r); node IPs skipped", exc)
                remote_info = {}

            results = await _get_json(client, "/resources/list")
            if not isinstance(results, list):
                raise ValueError("Malformed /resources/list response")

            hosts, guests, errors = _parse_resources(results, remote_info)
            sem = asyncio.Semaphore(_CONFIG_CONCURRENCY)
            nets = await asyncio.gather(
                *(_guest_net(client, sem, g["remote"], g["kind"], g["raw"]) for g in guests)
            )
    except httpx.HTTPError as exc:
        raise ConnectionError(_sanitize_pdm_error(exc)) from exc

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen: set[str] = set()
    for h in hosts:
        if h["id"] not in seen:
            seen.add(h["id"])
            nodes.append(h)
    for g, (ip, mac) in zip(guests, nets, strict=True):
        node = _guest_node(g["remote"], g["raw"], g["kind"], ip, mac)
        if node is None or node["id"] in seen:
            continue
        seen.add(node["id"])
        nodes.append(node)
        parent = node["parent_ieee"]
        if parent and parent in seen:
            edges.append({"source": parent, "target": node["id"]})

    return nodes, edges, _notice(results, nodes, errors)


def _notice(results: list[Any], nodes: list[dict[str, Any]], errors: list[str]) -> str | None:
    parts: list[str] = []
    if errors:
        parts.append("Some remotes could not be queried — " + "; ".join(errors))
    if not results:
        parts.append(
            "PDM returned no remotes. Add one in PDM, or grant the token the "
            "Auditor role on path '/resource'."
        )
    elif not nodes and not errors:
        parts.append(
            "Remotes were found but no node, VM or LXC was visible to the API token. "
            "Grant it the Auditor role on path '/resource' (and the user too, for a "
            "privilege-separated token)."
        )
    return " ".join(parts) or None


async def test_pdm_connection(
    host: str,
    port: int,
    token_id: str,
    token_secret: str,
    verify_tls: bool = True,
) -> tuple[bool, str]:
    """Reachability + auth check via ``GET /version``. Never raises credentials
    outward; returns ``(connected, message)``."""
    base_url = f"https://{host}:{port}/api2/json"
    timeout = httpx.Timeout(_READ_TIMEOUT, connect=_CONNECT_TIMEOUT)
    try:
        async with httpx.AsyncClient(
            base_url=base_url,
            headers=_auth_header(token_id, token_secret),
            verify=verify_tls,
            timeout=timeout,
        ) as client:
            data = await _get_json(client, "/version")
            results = None
            no_access = False
            # version answered; the import will report the real problem
            try:
                results = await _get_json(client, "/resources/list", {"resource-type": "node"})
            except httpx.HTTPStatusError as exc:
                # A token without any ACL authenticates fine (``/version`` is
                # open) and is then refused every resource: say so here rather
                # than let the import fail later on an opaque 403.
                no_access = exc.response.status_code == 403
            except httpx.HTTPError:
                pass
        version = data.get("version", "?") if isinstance(data, dict) else "?"
        message = f"Connected to {_PDM_LABEL} {version}"
        if no_access:
            message += (
                " — warning: this API token has no permission on resources, so nothing will "
                "be imported. In PDM, grant the token the Auditor role on path '/resource' "
                "(Access Control → API Token Permissions), or turn off privilege separation."
            )
        elif isinstance(results, list):
            remotes = sum(1 for r in results if isinstance(r, dict))
            message += f" — {remotes} remote{'s' if remotes != 1 else ''} visible"
            if remotes == 0:
                message += (
                    " — warning: no remote is visible to this token. Grant it the "
                    "Auditor role on path '/resource'."
                )
        return True, message
    except httpx.HTTPError as exc:
        return False, _sanitize_pdm_error(exc)
    except Exception as exc:  # noqa: BLE001 — surface a safe message, log the rest
        logger.exception("Unexpected error during PDM connection test")
        return False, _sanitize_pdm_error(exc)
