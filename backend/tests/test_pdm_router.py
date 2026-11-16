"""API + persistence tests for /api/v1/pdm/*."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.routes.pdm import _background_pdm_import, _persist_pending_import
from app.core.config import settings
from app.core.scheduler import _run_pdm_sync
from app.db.database import Base
from app.db.models import InventoryDevice, InventoryDeviceLink, Node, ScanRun

BODY = {"host": "pdm.lan", "token_id": "u@pam!t", "token_secret": "tok-secret-value"}
FIELDS = ("pdm_host", "pdm_port", "pdm_token_id", "pdm_token_secret", "pdm_verify_tls",
          "pdm_sync_enabled", "pdm_sync_interval")


@pytest.fixture(autouse=True)
def _clear_env():
    saved = {f: getattr(settings, f) for f in FIELDS}
    settings.pdm_host = ""
    settings.pdm_port = 8443
    settings.pdm_token_id = ""
    settings.pdm_token_secret = ""
    settings.pdm_verify_tls = True
    yield
    for field, value in saved.items():
        setattr(settings, field, value)


def _env() -> None:
    settings.pdm_host = "pdm.lan"
    settings.pdm_token_id = "env@pam!t"
    settings.pdm_token_secret = "env-secret"


def _host(name: str, remote: str = "lab", ip: str | None = None) -> dict:
    ieee = f"pdm-{remote}/node/{name}"
    return {
        "id": ieee, "label": name, "type": "proxmox", "ieee_address": ieee, "hostname": name,
        "ip": ip, "status": "online", "cpu_count": 8, "ram_gb": 16.0, "disk_gb": None,
        "vendor": "Proxmox VE", "model": None, "remote": remote, "parent_ieee": None,
    }


def _guest(vmid: int, node: str, remote: str = "lab", ip: str | None = None, mac: str | None = None,
           kind: str = "vm") -> dict:
    ieee = f"pdm-{remote}/{vmid}"
    return {
        "id": ieee, "label": f"g{vmid}", "type": kind, "ieee_address": ieee, "hostname": f"g{vmid}",
        "ip": ip, "mac": mac, "status": "online", "cpu_count": 2, "ram_gb": 4.0, "disk_gb": 32.0,
        "vendor": "Proxmox VE", "model": "QEMU", "vmid": vmid, "remote": remote,
        "parent_ieee": f"pdm-{remote}/node/{node}",
    }


def _inv(*nodes: dict) -> tuple[list[dict], list[dict]]:
    ids = {n["id"] for n in nodes}
    edges = [{"source": n["parent_ieee"], "target": n["id"]} for n in nodes
             if n.get("parent_ieee") in ids]
    return list(nodes), edges


# --- credentials / endpoints -----------------------------------------------

@pytest.mark.asyncio
async def test_requires_auth(client: AsyncClient) -> None:
    assert (await client.post("/api/v1/pdm/import", json=BODY)).status_code == 401


@pytest.mark.asyncio
async def test_custom_host_without_token_is_rejected(client: AsyncClient, headers: dict) -> None:
    _env()
    res = await client.post("/api/v1/pdm/test-connection", json={"host": "evil.lan"}, headers=headers)
    assert res.status_code == 400
    assert "explicit API token" in res.json()["detail"]


@pytest.mark.asyncio
async def test_half_a_token_is_rejected(client: AsyncClient, headers: dict) -> None:
    res = await client.post(
        "/api/v1/pdm/test-connection", json={"host": "pdm.lan", "token_id": "u@pam!t"}, headers=headers
    )
    assert res.status_code == 400


@pytest.mark.asyncio
async def test_env_token_used_for_configured_host(client: AsyncClient, headers: dict) -> None:
    _env()
    with patch("app.api.routes.pdm.test_pdm_connection", new=AsyncMock(return_value=(True, "ok"))) as t:
        res = await client.post("/api/v1/pdm/test-connection", json={"host": "PDM.lan."}, headers=headers)
    assert res.status_code == 200
    assert (t.await_args.kwargs["token_id"], t.await_args.kwargs["token_secret"]) == ("env@pam!t", "env-secret")
    assert t.await_args.kwargs["port"] == 8443


@pytest.mark.asyncio
async def test_env_token_refused_on_another_port(client: AsyncClient, headers: dict) -> None:
    _env()
    res = await client.post("/api/v1/pdm/test-connection", json={"host": "pdm.lan", "port": 9999}, headers=headers)
    assert res.status_code == 400


@pytest.mark.asyncio
async def test_env_token_refused_with_tls_verification_off(client: AsyncClient, headers: dict) -> None:
    _env()
    res = await client.post(
        "/api/v1/pdm/test-connection", json={"host": "pdm.lan", "verify_tls": False}, headers=headers
    )
    assert res.status_code == 400
    assert "TLS verification" in res.json()["detail"]


@pytest.mark.asyncio
async def test_env_host_without_token_is_a_clear_error(client: AsyncClient, headers: dict) -> None:
    settings.pdm_host = "pdm.lan"
    res = await client.post("/api/v1/pdm/test-connection", json={"host": "pdm.lan"}, headers=headers)
    assert res.status_code == 400
    assert "none configured" in res.json()["detail"]


@pytest.mark.asyncio
async def test_request_token_may_disable_tls_verification(client: AsyncClient, headers: dict) -> None:
    _env()
    with patch("app.api.routes.pdm.test_pdm_connection", new=AsyncMock(return_value=(True, "ok"))) as t:
        res = await client.post("/api/v1/pdm/test-connection", json={**BODY, "verify_tls": False}, headers=headers)
    assert res.status_code == 200
    assert t.await_args.kwargs["verify_tls"] is False
    assert t.await_args.kwargs["token_secret"] == "tok-secret-value"


@pytest.mark.asyncio
async def test_import_maps_errors_without_leaking_the_token(client: AsyncClient, headers: dict) -> None:
    with patch("app.api.routes.pdm.fetch_pdm_inventory", new=AsyncMock(side_effect=ConnectionError("Authentication failed"))):
        res = await client.post("/api/v1/pdm/import", json=BODY, headers=headers)
    assert res.status_code == 502 and "tok-secret-value" not in res.text
    with patch("app.api.routes.pdm.fetch_pdm_inventory", new=AsyncMock(side_effect=ValueError("Malformed"))):
        assert (await client.post("/api/v1/pdm/import", json=BODY, headers=headers)).status_code == 422
    with patch("app.api.routes.pdm.fetch_pdm_inventory", new=AsyncMock(side_effect=RuntimeError("tok-secret-value"))):
        res = await client.post("/api/v1/pdm/import", json=BODY, headers=headers)
    assert res.status_code == 500 and "tok-secret-value" not in res.text


@pytest.mark.asyncio
async def test_import_returns_nodes_edges_device_ids_and_notice(client: AsyncClient, headers: dict) -> None:
    nodes, edges = _inv(_host("pve1"), _guest(101, "pve1"))
    with patch("app.api.routes.pdm.fetch_pdm_inventory", new=AsyncMock(return_value=(nodes, edges, "careful"))):
        res = await client.post("/api/v1/pdm/import", json=BODY, headers=headers)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["device_count"] == 2 and data["notice"] == "careful"
    assert len(data["edges"]) == 1
    assert all(n["device_id"] for n in data["nodes"])
    assert "mac" not in data["nodes"][1]


@pytest.mark.asyncio
async def test_import_pending_creates_scan_run(client: AsyncClient, headers: dict) -> None:
    with patch("app.api.routes.pdm._background_pdm_import", new_callable=AsyncMock) as bg:
        res = await client.post("/api/v1/pdm/import-pending", json=BODY, headers=headers)
    assert res.status_code == 200
    body = res.json()
    assert body["kind"] == "pdm" and body["ranges"] == ["pdm.lan:8443"]
    assert body.get("label") == "pdm.lan"
    assert bg.await_args.args[3:5] == ("u@pam!t", "tok-secret-value")
    assert "tok-secret-value" not in res.text


@pytest.mark.asyncio
async def test_sync_now_requires_env_and_queues_a_run(client: AsyncClient, headers: dict) -> None:
    assert (await client.post("/api/v1/pdm/sync-now", headers=headers)).status_code == 400
    _env()
    with patch("app.api.routes.pdm._background_pdm_import", new_callable=AsyncMock) as bg:
        res = await client.post("/api/v1/pdm/sync-now", headers=headers)
    assert res.status_code == 200 and res.json()["kind"] == "pdm"
    assert bg.await_args.args[1:3] == ("pdm.lan", 8443)


# --- config ----------------------------------------------------------------

@pytest.mark.asyncio
async def test_config_omits_token(client: AsyncClient, headers: dict) -> None:
    _env()
    res = await client.get("/api/v1/pdm/config", headers=headers)
    assert res.status_code == 200
    assert "env-secret" not in res.text and "env@pam" not in res.text
    assert res.json()["token_configured"] is True and res.json()["port"] == 8443


@pytest.mark.asyncio
async def test_enable_sync_needs_env(client: AsyncClient, headers: dict) -> None:
    res = await client.post("/api/v1/pdm/config", json={"sync_enabled": True, "sync_interval": 600}, headers=headers)
    assert res.status_code == 400


@pytest.mark.asyncio
async def test_save_config_persists_only_sync_fields(client: AsyncClient, headers: dict) -> None:
    _env()
    with patch.object(type(settings), "save_overrides", lambda self: None), \
            patch("app.api.routes.pdm.set_pdm_sync_enabled") as enable, \
            patch("app.api.routes.pdm.reschedule_pdm_sync") as resched:
        res = await client.post(
            "/api/v1/pdm/config",
            json={"host": "attacker", "token_secret": "x", "sync_enabled": True, "sync_interval": 900},
            headers=headers,
        )
    assert res.status_code == 200
    assert settings.pdm_host == "pdm.lan" and settings.pdm_token_secret == "env-secret"
    assert (settings.pdm_sync_enabled, settings.pdm_sync_interval) == (True, 900)
    enable.assert_called_once_with(True)
    resched.assert_called_once_with(900)


@pytest.mark.asyncio
async def test_save_config_rejects_an_interval_out_of_range(client: AsyncClient, headers: dict) -> None:
    for interval in (100, 100_000):
        res = await client.post(
            "/api/v1/pdm/config", json={"sync_enabled": False, "sync_interval": interval}, headers=headers
        )
        assert res.status_code == 422, interval


def test_overrides_round_trip_only_sync_fields(tmp_path) -> None:
    import json

    saved = (settings.sqlite_path, settings.pdm_sync_enabled, settings.pdm_sync_interval)
    try:
        settings.sqlite_path = str(tmp_path / "db.sqlite")
        settings.pdm_sync_enabled, settings.pdm_sync_interval = True, 1200
        settings.pdm_token_secret = "must-not-be-written"
        settings.save_overrides()
        text = (tmp_path / "scan_config.json").read_text()
        assert "must-not-be-written" not in text and "pdm_host" not in text
        assert json.loads(text)["pdm_sync_interval"] == 1200
        settings.pdm_sync_enabled, settings.pdm_sync_interval = False, 3600
        settings.load_overrides()
        assert (settings.pdm_sync_enabled, settings.pdm_sync_interval) == (True, 1200)
    finally:
        settings.sqlite_path, settings.pdm_sync_enabled, settings.pdm_sync_interval = saved


# --- persistence -----------------------------------------------------------

@pytest.mark.asyncio
async def test_persist_creates_rows_and_links(db_session: AsyncSession) -> None:
    nodes, edges = _inv(_host("pve1"), _host("pve2"), _guest(101, "pve1", ip="10.0.0.5", mac="aa:bb:cc:dd:ee:01"))
    result = await _persist_pending_import(db_session, nodes, edges)
    assert (result.pending_created, result.pending_updated, result.links_recorded) == (3, 0, 2)

    rows = {r.ieee_address: r for r in (await db_session.execute(select(InventoryDevice))).scalars()}
    vm = rows["pdm-lab/101"]
    assert (vm.status, vm.suggested_type, vm.discovery_source, vm.ip, vm.mac) == (
        "pending", "vm", "pdm", "10.0.0.5", "aa:bb:cc:dd:ee:01")
    assert vm.discovery_sources == ["pdm"] and vm.disk_gb == 32.0
    links = {(lk.source_ieee, lk.target_ieee, lk.discovery_source)
             for lk in (await db_session.execute(select(InventoryDeviceLink))).scalars()}
    assert links == {
        ("pdm-lab/node/pve1", "pdm-lab/101", "pdm"),
        ("pdm-lab/node/pve1", "pdm-lab/node/pve2", "pdm_cluster"),
    }


@pytest.mark.asyncio
async def test_persist_is_idempotent_and_keeps_hidden_hidden(db_session: AsyncSession) -> None:
    nodes, edges = _inv(_host("pve1"), _guest(101, "pve1"))
    await _persist_pending_import(db_session, nodes, edges)
    row = (await db_session.execute(select(InventoryDevice).where(InventoryDevice.ieee_address == "pdm-lab/101"))).scalar_one()
    row.status = "hidden"
    await db_session.commit()
    result = await _persist_pending_import(db_session, nodes, edges)
    assert (result.pending_created, result.pending_updated, result.links_recorded) == (0, 2, 1)
    await db_session.refresh(row)
    assert row.status == "hidden"
    assert len((await db_session.execute(select(InventoryDevice))).scalars().all()) == 2


@pytest.mark.asyncio
async def test_persist_merges_into_a_scanned_row_by_ip(db_session: AsyncSession) -> None:
    db_session.add(InventoryDevice(ip="10.0.0.5", hostname="found-by-scan", status="pending",
                                   discovery_source="arp", discovery_sources=["arp"]))
    await db_session.commit()
    nodes, edges = _inv(_host("pve1"), _guest(101, "pve1", ip="10.0.0.5"))
    await _persist_pending_import(db_session, nodes, edges)
    rows = (await db_session.execute(select(InventoryDevice).where(InventoryDevice.ip == "10.0.0.5"))).scalars().all()
    assert len(rows) == 1
    assert rows[0].ieee_address == "pdm-lab/101" and rows[0].suggested_type == "vm"
    assert set(rows[0].discovery_sources) == {"arp", "pdm"}


@pytest.mark.asyncio
async def test_ip_never_merges_into_a_row_claimed_by_another_guest(db_session: AsyncSession) -> None:
    nodes, edges = _inv(_host("pve1"), _guest(101, "pve1", ip="172.17.0.1"), _guest(102, "pve1", ip="172.17.0.1"))
    await _persist_pending_import(db_session, nodes, edges)
    ieees = {r.ieee_address for r in (await db_session.execute(select(InventoryDevice))).scalars()}
    assert {"pdm-lab/101", "pdm-lab/102"} <= ieees


@pytest.mark.asyncio
async def test_ip_does_not_steal_a_direct_proxmox_row_but_mac_merges_it(db_session: AsyncSession) -> None:
    db_session.add(InventoryDevice(ieee_address="pve-pve1-101", ip="10.0.0.5", mac="aa:bb:cc:dd:ee:01",
                                   status="pending", discovery_source="proxmox", discovery_sources=["proxmox"]))
    await db_session.commit()
    # Same IP, other VM, no MAC: a new row, the pve- row is left alone.
    nodes, edges = _inv(_host("pve1"), _guest(555, "pve1", ip="10.0.0.5"))
    await _persist_pending_import(db_session, nodes, edges)
    ieees = {r.ieee_address for r in (await db_session.execute(select(InventoryDevice))).scalars()}
    assert {"pve-pve1-101", "pdm-lab/555"} <= ieees
    # Same MAC: the facts merge into the pve- row, which keeps its own ieee.
    nodes, edges = _inv(_host("pve1"), _guest(101, "pve1", mac="aa:bb:cc:dd:ee:01"))
    await _persist_pending_import(db_session, nodes, edges)
    row = (await db_session.execute(select(InventoryDevice).where(InventoryDevice.mac == "aa:bb:cc:dd:ee:01"))).scalars().all()
    assert len(row) == 1 and row[0].ieee_address == "pve-pve1-101"
    assert set(row[0].discovery_sources) == {"proxmox", "pdm"}


@pytest.mark.asyncio
async def test_renamed_remote_moves_the_guest_by_mac(db_session: AsyncSession) -> None:
    mac = "aa:bb:cc:dd:ee:02"
    await _persist_pending_import(db_session, *_inv(_host("pve1"), _guest(101, "pve1", mac=mac)))
    await _persist_pending_import(db_session, *_inv(_host("pve1", "lab2"), _guest(101, "pve1", "lab2", mac=mac)))
    rows = (await db_session.execute(select(InventoryDevice).where(InventoryDevice.mac == mac))).scalars().all()
    assert len(rows) == 1 and rows[0].ieee_address == "pdm-lab2/101"


@pytest.mark.asyncio
async def test_same_vmid_on_two_remotes_stays_apart(db_session: AsyncSession) -> None:
    nodes = [_host("pve1", "a"), _host("pve1", "b"), _guest(100, "pve1", "a"), _guest(100, "pve1", "b")]
    result = await _persist_pending_import(db_session, nodes, _inv(*nodes)[1])
    assert result.pending_created == 4 and result.links_recorded == 2  # no cross-remote cluster link


@pytest.mark.asyncio
async def test_approved_row_is_revived_only_when_not_drawn(db_session: AsyncSession) -> None:
    nodes, edges = _inv(_host("pve1"), _guest(101, "pve1"), _guest(102, "pve1"))
    await _persist_pending_import(db_session, nodes, edges)
    rows = {r.ieee_address: r for r in (await db_session.execute(select(InventoryDevice))).scalars()}
    for ieee in ("pdm-lab/101", "pdm-lab/102"):
        rows[ieee].status = "approved"
    db_session.add(Node(id="n1", type="vm", label="g101", pos_x=0, pos_y=0, device_id=rows["pdm-lab/101"].id))
    await db_session.commit()
    await _persist_pending_import(db_session, nodes, edges)
    await db_session.refresh(rows["pdm-lab/101"])
    await db_session.refresh(rows["pdm-lab/102"])
    assert rows["pdm-lab/101"].status == "approved"  # drawn: lifecycle untouched
    assert rows["pdm-lab/102"].status == "pending"   # not drawn: revived


@pytest.mark.asyncio
async def test_cluster_hosts_get_left_and_right_handles(db_session: AsyncSession) -> None:
    nodes, edges = _inv(_host("pve1"), _host("pve2"))
    await _persist_pending_import(db_session, nodes, edges)
    row = (await db_session.execute(select(InventoryDevice).where(InventoryDevice.ieee_address == "pdm-lab/node/pve1"))).scalar_one()
    db_session.add(Node(id="n1", type="proxmox", label="pve1", pos_x=0, pos_y=0, device_id=row.id))
    await db_session.commit()
    await _persist_pending_import(db_session, nodes, edges)
    node = await db_session.get(Node, "n1")
    assert node is not None and (node.left_handles, node.right_handles) == (1, 1)


@pytest.mark.asyncio
async def test_relinking_does_not_erase_another_remotes_links(db_session: AsyncSession) -> None:
    other = _inv(_host("x1", "other"), _guest(7, "x1", "other"))
    await _persist_pending_import(db_session, *other)
    await _persist_pending_import(db_session, *_inv(_host("pve1"), _guest(101, "pve1")))
    sources = {(lk.source_ieee, lk.target_ieee) for lk in (await db_session.execute(select(InventoryDeviceLink))).scalars()}
    assert ("pdm-other/node/x1", "pdm-other/7") in sources


# --- background + scheduler --------------------------------------------------

@pytest.mark.asyncio
async def test_background_import_done_with_notice_and_broadcast(db_session: AsyncSession) -> None:
    run = ScanRun(status="running", kind="pdm", ranges=["pdm.lan:8443"])
    db_session.add(run)
    await db_session.commit()
    nodes, edges = _inv(_host("pve1"), _guest(101, "pve1"))
    with patch("app.api.routes.pdm.fetch_pdm_inventory", new=AsyncMock(return_value=(nodes, edges, "heads up"))), \
            patch("app.api.routes.status.broadcast_scan_update", new_callable=AsyncMock) as bc:
        await _background_pdm_import(run.id, "pdm.lan", 8443, "u@pam!t", "sec", True)
    await db_session.refresh(run)
    assert (run.status, run.devices_found, run.error) == ("done", 2, "heads up")
    bc.assert_awaited_once()


@pytest.mark.asyncio
async def test_background_import_failure_marks_the_run_without_the_token(db_session: AsyncSession) -> None:
    run = ScanRun(status="running", kind="pdm", ranges=["pdm.lan:8443"])
    db_session.add(run)
    await db_session.commit()
    for exc, expected in ((ConnectionError("Connection refused by PDM host"), "refused"),
                          (RuntimeError("token tok-secret-value leaked"), "PDM import failed")):
        run.status = "running"
        await db_session.commit()
        with patch("app.api.routes.pdm.fetch_pdm_inventory", new=AsyncMock(side_effect=exc)):
            await _background_pdm_import(run.id, "pdm.lan", 8443, "u@pam!t", "tok-secret-value", True)
        await db_session.refresh(run)
        assert run.status == "error" and expected in (run.error or "")
        assert "tok-secret-value" not in (run.error or "")


@pytest.fixture
async def mem_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    await engine.dispose()


@pytest.mark.asyncio
async def test_auto_sync_records_a_run_and_imports(mem_db) -> None:
    _env()
    settings.pdm_sync_enabled = True
    with patch("app.core.scheduler.AsyncSessionLocal", mem_db), \
            patch("app.api.routes.pdm._background_pdm_import", new_callable=AsyncMock) as bg:
        await _run_pdm_sync()
    async with mem_db() as db:
        runs = (await db.execute(select(ScanRun))).scalars().all()
    assert [(r.kind, r.ranges, r.label) for r in runs] == [("pdm", ["pdm.lan:8443"], "pdm.lan")]
    assert bg.await_args.args[1:] == ("pdm.lan", 8443, "env@pam!t", "env-secret", True)


@pytest.mark.asyncio
async def test_auto_sync_is_a_noop_when_disabled_or_unconfigured(mem_db) -> None:
    with patch("app.api.routes.pdm._background_pdm_import", new_callable=AsyncMock) as bg:
        settings.pdm_sync_enabled = False
        await _run_pdm_sync()
        settings.pdm_sync_enabled = True
        await _run_pdm_sync()  # enabled but no host/token
    bg.assert_not_awaited()
