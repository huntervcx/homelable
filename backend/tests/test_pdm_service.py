"""Unit tests for the Proxmox Datacenter Manager inventory service.

The fixtures follow the documented PDM API schema (``/resources/list`` grouped
by remote, resources tagged by ``type``); no real PDM was available.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.services import pdm_service as svc

GB = 1024 ** 3


def _resources() -> list[dict]:
    return [
        {
            "remote": "lab",
            "resources": [
                {"type": "pve-node", "id": "remote/lab/node/pve1", "node": "pve1",
                 "status": "online", "maxcpu": 8, "maxmem": 16 * GB, "cpu": 0.1, "mem": GB, "uptime": 10},
                {"type": "pve-node", "id": "remote/lab/node/pve2", "node": "pve2",
                 "status": "offline", "maxcpu": 4, "maxmem": 8 * GB},
                {"type": "pve-qemu", "id": "remote/lab/qemu/101", "vmid": 101, "name": "web",
                 "node": "pve1", "status": "running", "maxcpu": 2, "maxmem": 4 * GB, "maxdisk": 32 * GB,
                 "template": False},
                {"type": "pve-qemu", "id": "remote/lab/qemu/9000", "vmid": 9000, "name": "tpl",
                 "node": "pve1", "status": "stopped", "template": True},
                {"type": "pve-lxc", "id": "remote/lab/lxc/200", "vmid": 200, "name": "db",
                 "node": "pve2", "status": "stopped", "maxcpu": 1, "maxmem": GB, "maxdisk": 8 * GB},
                {"type": "pve-storage", "id": "remote/lab/storage/pve1/local", "node": "pve1", "storage": "local"},
            ],
        },
        {
            "remote": "backup",
            "resources": [
                {"type": "pbs-node", "id": "remote/backup/node/localhost", "name": "pbs1", "maxcpu": 4, "maxmem": 8 * GB},
                {"type": "pbs-datastore", "id": "remote/backup/datastore/main", "name": "main"},
            ],
        },
    ]


REMOTES = [
    {"id": "lab", "type": "pve", "nodes": ["pve1.lan", "pve2.lan"], "authid": "root@pam!pdm"},
    {"id": "backup", "type": "pbs", "nodes": ["10.0.0.9"], "authid": "root@pam!pdm", "token": "REMOTE-SECRET"},
]


def _fake(resources, remotes=REMOTES, configs=None):
    configs = configs or {}

    async def fake_get_json(client, path: str, params=None):
        if path == "/remotes/remote":
            if remotes is None:
                raise httpx.ConnectError("denied")
            return remotes
        if path == "/resources/list":
            return resources
        if path in configs:
            value = configs[path]
            if isinstance(value, Exception):
                raise value
            return value
        return None

    return fake_get_json


def test_auth_header_uses_pdm_scheme_with_colon() -> None:
    assert svc._auth_header("root@pam!t", "sec") == {
        "Authorization": "PDMAPIToken=root@pam!t:sec"
    }


def test_synthetic_ids_are_unambiguous_and_scoped() -> None:
    assert svc._host_ieee("lab", "pve1") == "pdm-lab/node/pve1"
    assert svc._guest_ieee("lab", 101) == "pdm-lab/101"
    assert svc._pbs_ieee("backup", "pbs1") == "pdm-backup/pbs/pbs1"
    # Same VMID on two remotes never collides.
    assert svc._guest_ieee("a", 100) != svc._guest_ieee("b", 100)


def test_address_ip_accepts_literals_only() -> None:
    assert svc._address_ip("10.0.0.9") == "10.0.0.9"
    assert svc._address_ip("10.0.0.9:8006") == "10.0.0.9"
    assert svc._address_ip("[fd00::1]:8006") == "fd00::1"
    assert svc._address_ip("pve1.lan") is None
    assert svc._address_ip(None) is None


def test_remote_addresses_never_reads_the_remote_token() -> None:
    parsed = svc._remote_addresses(REMOTES)
    assert parsed == {"lab": ("pve", ["pve1.lan", "pve2.lan"]), "backup": ("pbs", ["10.0.0.9"])}
    assert "REMOTE-SECRET" not in repr(parsed)
    assert svc._remote_addresses(None) == {}


def test_node_and_guest_mapping() -> None:
    host = svc._host_node("lab", {"node": "pve1", "status": "online", "maxcpu": 8, "maxmem": 16 * GB}, "10.0.0.2")
    assert host is not None
    assert (host["type"], host["status"], host["cpu_count"], host["ram_gb"]) == ("proxmox", "online", 8, 16.0)
    assert host["ieee_address"] == "pdm-lab/node/pve1"
    assert host["ip"] == "10.0.0.2"

    vm = svc._guest_node("lab", {"vmid": 101, "name": "web", "node": "pve1", "status": "running",
                                 "maxcpu": 2, "maxmem": 4 * GB, "maxdisk": 32 * GB}, "qemu", None, "aa:bb:cc:dd:ee:ff")
    assert vm is not None
    assert (vm["type"], vm["status"], vm["model"], vm["disk_gb"]) == ("vm", "online", "QEMU", 32.0)
    assert vm["parent_ieee"] == "pdm-lab/node/pve1"

    ct = svc._guest_node("lab", {"vmid": 200, "status": "stopped", "node": "pve2"}, "lxc")
    assert ct is not None
    assert (ct["type"], ct["status"], ct["label"]) == ("lxc", "offline", "lxc-200")
    assert svc._guest_node("lab", {"name": "novmid"}, "qemu") is None
    assert svc._host_node("lab", {"status": "online"}, None) is None


def test_node_name_falls_back_to_the_resource_id() -> None:
    assert svc._node_name({"id": "remote/lab/node/pve9"}) == "pve9"
    assert svc._node_name({}) is None


def test_properties_carry_remote_and_specs_hidden_by_default() -> None:
    props = svc.build_pdm_properties(
        {"remote": "lab", "vmid": 101, "model": "QEMU", "cpu_count": 2, "ram_gb": 4.0, "disk_gb": 32.0}
    )
    keys = {p["key"]: p for p in props}
    assert set(keys) == {"Remote", "VMID", "Kind", "CPU Cores", "RAM", "Disk", "Source"}
    assert keys["Source"]["value"] == "Proxmox Datacenter Manager"
    assert all(p["visible"] is False for p in props)


def test_cluster_links_are_per_remote() -> None:
    nodes = [
        {"type": "proxmox", "ieee_address": "a1", "remote": "a"},
        {"type": "proxmox", "ieee_address": "b1", "remote": "b"},
        {"type": "proxmox", "ieee_address": "a2", "remote": "a"},
        {"type": "vm", "ieee_address": "v", "remote": "a"},
        {"type": "server", "ieee_address": "pbs", "remote": "c"},
    ]
    assert svc.build_pdm_cluster_links(nodes) == [("a1", "a2")]
    assert svc.build_pdm_cluster_links(nodes[:2]) == []


@pytest.mark.asyncio
async def test_fetch_inventory_happy_path() -> None:
    configs = {
        "/pve/remotes/lab/qemu/101/config": {"net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0"},
        "/pve/remotes/lab/lxc/200/config": {"net0": "name=eth0,hwaddr=11:22:33:44:55:66,ip=10.0.0.6/24"},
    }
    with patch.object(svc, "_get_json", new=AsyncMock(side_effect=_fake(_resources(), configs=configs))):
        nodes, edges, notice = await svc.fetch_pdm_inventory("pdm", 8443, "u@pam!t", "sec")

    by_id = {n["id"]: n for n in nodes}
    assert set(by_id) == {
        "pdm-lab/node/pve1", "pdm-lab/node/pve2", "pdm-lab/101", "pdm-lab/200", "pdm-backup/pbs/pbs1",
    }
    assert "pdm-lab/9000" not in by_id  # template skipped
    assert by_id["pdm-lab/node/pve2"]["status"] == "offline"
    assert by_id["pdm-backup/pbs/pbs1"]["type"] == "server"
    assert by_id["pdm-backup/pbs/pbs1"]["ip"] == "10.0.0.9"  # single node, literal IP
    assert by_id["pdm-lab/node/pve1"]["ip"] is None  # two nodes: addresses are ambiguous
    assert by_id["pdm-lab/101"]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert by_id["pdm-lab/200"]["ip"] == "10.0.0.6"
    assert by_id["pdm-lab/200"]["mac"] == "11:22:33:44:55:66"
    assert sorted((e["source"], e["target"]) for e in edges) == [
        ("pdm-lab/node/pve1", "pdm-lab/101"),
        ("pdm-lab/node/pve2", "pdm-lab/200"),
    ]
    assert notice is None


@pytest.mark.asyncio
async def test_fetch_inventory_survives_missing_remotes_and_config_errors() -> None:
    configs = {"/pve/remotes/lab/qemu/101/config": httpx.ReadTimeout("slow")}
    fake = _fake(_resources(), remotes=None, configs=configs)
    with patch.object(svc, "_get_json", new=AsyncMock(side_effect=fake)):
        nodes, _edges, _notice = await svc.fetch_pdm_inventory("pdm", 8443, "u@pam!t", "sec")
    vm = next(n for n in nodes if n["id"] == "pdm-lab/101")
    assert vm["mac"] is None and vm["ip"] is None
    assert next(n for n in nodes if n["id"] == "pdm-backup/pbs/pbs1")["ip"] is None


@pytest.mark.asyncio
async def test_fetch_inventory_reports_a_remote_error_as_notice() -> None:
    results = [{"remote": "down", "resources": [], "error": "connection timed out"}, *_resources()[:1]]
    with patch.object(svc, "_get_json", new=AsyncMock(side_effect=_fake(results))):
        nodes, _edges, notice = await svc.fetch_pdm_inventory("pdm", 8443, "u@pam!t", "sec")
    assert nodes  # the healthy remote still imports
    assert notice is not None and "down: connection timed out" in notice


@pytest.mark.asyncio
async def test_fetch_inventory_advises_when_nothing_is_visible() -> None:
    with patch.object(svc, "_get_json", new=AsyncMock(side_effect=_fake([{"remote": "lab", "resources": []}]))):
        nodes, _edges, notice = await svc.fetch_pdm_inventory("pdm", 8443, "u@pam!t", "sec")
    assert nodes == []
    assert notice is not None and "/resource" in notice

    with patch.object(svc, "_get_json", new=AsyncMock(side_effect=_fake([]))):
        _n, _e, notice = await svc.fetch_pdm_inventory("pdm", 8443, "u@pam!t", "sec")
    assert notice is not None and "no remotes" in notice


@pytest.mark.asyncio
async def test_fetch_inventory_rejects_a_malformed_resource_list() -> None:
    with patch.object(svc, "_get_json", new=AsyncMock(side_effect=_fake({"oops": 1}))), \
            pytest.raises(ValueError):
        await svc.fetch_pdm_inventory("pdm", 8443, "u@pam!t", "sec")


@pytest.mark.asyncio
async def test_fetch_inventory_error_is_sanitized() -> None:
    err = httpx.HTTPStatusError(
        "boom for PDMAPIToken=u@pam!t:topsecret",
        request=httpx.Request("GET", "https://h/api2/json"),
        response=httpx.Response(401),
    )

    async def boom(client, path, params=None):
        raise err

    with patch.object(svc, "_get_json", new=AsyncMock(side_effect=boom)), \
            pytest.raises(ConnectionError) as info:
        await svc.fetch_pdm_inventory("pdm", 8443, "u@pam!t", "topsecret")
    assert "topsecret" not in str(info.value)
    assert "Authentication failed" in str(info.value)


def test_sanitize_error_categories_hide_credentials() -> None:
    for exc, expected in (
        (httpx.ConnectError("[Errno -2] Name or service not known"), "could not be resolved"),
        (httpx.ConnectError("Connection refused"), "refused"),
        (httpx.ConnectError("certificate verify failed"), "TLS verification failed"),
        (httpx.ReadTimeout("timed out PDMAPIToken=x:secret"), "timed out"),
        (httpx.ConnectError("weird PDMAPIToken=x:secret"), "connection failed"),
    ):
        msg = svc._sanitize_pdm_error(exc)
        assert expected.lower() in msg.lower()
        assert "secret" not in msg


@pytest.mark.asyncio
async def test_test_connection_reports_version_and_remote_count() -> None:
    async def fake(client, path, params=None):
        if path == "/version":
            return {"version": "1.0.2", "release": "1", "repoid": "abc"}
        return [{"remote": "lab", "resources": []}, {"remote": "backup", "resources": []}]

    with patch.object(svc, "_get_json", new=AsyncMock(side_effect=fake)):
        ok, msg = await svc.test_pdm_connection("pdm", 8443, "u@pam!t", "sec")
    assert ok is True
    assert "1.0.2" in msg and "2 remotes" in msg and "warning" not in msg


@pytest.mark.asyncio
async def test_test_connection_warns_when_no_remote_is_visible() -> None:
    async def fake(client, path, params=None):
        return {"version": "1.0.2"} if path == "/version" else []

    with patch.object(svc, "_get_json", new=AsyncMock(side_effect=fake)):
        ok, msg = await svc.test_pdm_connection("pdm", 8443, "u@pam!t", "sec")
    assert ok is True and "warning" in msg and "/resource" in msg


@pytest.mark.asyncio
async def test_test_connection_warns_when_token_has_no_acl() -> None:
    """A privilege-separated token with no ACL authenticates, then gets a 403."""

    async def fake(client, path, params=None):
        if path == "/version":
            return {"version": "1.1"}
        raise httpx.HTTPStatusError(
            "forbidden", request=httpx.Request("GET", "https://pdm/x"), response=httpx.Response(403)
        )

    with patch.object(svc, "_get_json", new=AsyncMock(side_effect=fake)):
        ok, msg = await svc.test_pdm_connection("pdm", 8443, "u@pam!t", "sec")
    assert ok is True and "no permission on resources" in msg and "/resource" in msg


@pytest.mark.asyncio
async def test_test_connection_failure_is_sanitized() -> None:
    async def boom(client, path, params=None):
        raise httpx.ConnectError("Connection refused PDMAPIToken=u:secret")

    with patch.object(svc, "_get_json", new=AsyncMock(side_effect=boom)):
        ok, msg = await svc.test_pdm_connection("pdm", 8443, "u@pam!t", "sec")
    assert ok is False and "secret" not in msg


@pytest.mark.asyncio
async def test_requests_carry_the_token_header_end_to_end() -> None:
    """Drive the real httpx client through a mock transport."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("/version"):
            return httpx.Response(200, json={"data": {"version": "1.0"}})
        return httpx.Response(200, json={"data": []})

    real = httpx.AsyncClient

    def factory(**kw):
        return real(transport=httpx.MockTransport(handler), **kw)

    with patch.object(svc.httpx, "AsyncClient", side_effect=factory):
        ok, _msg = await svc.test_pdm_connection("pdm.lan", 8443, "root@pam!t", "s3cret")
    assert ok
    assert seen[0].headers["authorization"] == "PDMAPIToken=root@pam!t:s3cret"
    assert str(seen[0].url).startswith("https://pdm.lan:8443/api2/json/version")
