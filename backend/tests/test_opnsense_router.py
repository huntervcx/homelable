"""API + persistence tests for /api/v1/opnsense/*."""

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.routes.opnsense import _persist
from app.core.config import settings
from app.db.models import InventoryDevice, InventoryDeviceLink


@pytest.fixture(autouse=True)
def _clear_env():
    saved = (settings.opnsense_host, settings.opnsense_api_key, settings.opnsense_api_secret, list(settings.scanner_ranges))
    settings.opnsense_host = settings.opnsense_api_key = settings.opnsense_api_secret = ""
    yield
    settings.opnsense_host, settings.opnsense_api_key, settings.opnsense_api_secret = saved[:3]
    settings.scanner_ranges = saved[3]


def _dev(ieee, type_="generic", source="opnsense-client", **kw):
    return {"ieee_address": ieee, "type": type_, "source": source, "label": kw.pop("label", ieee),
            "hostname": None, "ip": None, "mac": None, "vendor": None, "model": None, "properties": [], **kw}


async def test_requires_auth(client: AsyncClient):
    assert (await client.get("/api/v1/opnsense/config")).status_code == 401
    assert (await client.post("/api/v1/opnsense/sync-now")).status_code == 401


async def test_config_never_returns_credentials(client: AsyncClient, headers: dict):
    settings.opnsense_host = "fw.lan"
    settings.opnsense_api_key = "thekey"
    settings.opnsense_api_secret = "supersecret"
    res = await client.get("/api/v1/opnsense/config", headers=headers)
    assert res.json()["credentials_configured"] is True
    assert "supersecret" not in res.text and "thekey" not in res.text


async def test_sync_now_rejected_without_config(client: AsyncClient, headers: dict):
    assert (await client.post("/api/v1/opnsense/sync-now", headers=headers)).status_code == 400


async def test_persist_creates_then_updates_and_links(db_session: AsyncSession):
    data = {
        "devices": [_dev("opnsense-fw", "firewall", "opnsense", ip="192.168.1.1"),
                    _dev("opnsense-wg-K", source="opnsense-vpn")],
        "links": [("opnsense-fw", "opnsense-wg-K")],
        "networks": [{"cidr": "10.9.0.0/24", "via": "x", "source": "route"}],
    }
    first = await _persist(db_session, data)
    assert (first.pending_created, first.pending_updated, first.links_recorded) == (2, 0, 1)
    again = await _persist(db_session, data)
    assert (again.pending_created, again.pending_updated) == (0, 2)
    assert len((await db_session.execute(select(InventoryDevice))).scalars().all()) == 2
    # Re-import replaces the links instead of stacking them.
    assert len((await db_session.execute(select(InventoryDeviceLink))).scalars().all()) == 1


async def test_foreign_row_keeps_its_type_when_seen_by_mac(db_session: AsyncSession):
    db_session.add(InventoryDevice(ieee_address="pve-1-100", mac="aa:bb:cc:00:00:01", suggested_type="lxc",
                                   hostname="ct", discovery_source="proxmox", discovery_sources=["proxmox"], status="pending"))
    await db_session.commit()
    await _persist(db_session, {"devices": [_dev("opnsense-client-aa:bb:cc:00:00:01", mac="aa:bb:cc:00:00:01",
                                                  ip="192.168.1.5")], "links": [], "networks": []})
    rows = (await db_session.execute(select(InventoryDevice))).scalars().all()
    assert len(rows) == 1
    assert rows[0].suggested_type == "lxc" and rows[0].ip == "192.168.1.5"
    assert set(rows[0].discovery_sources) == {"proxmox", "opnsense-client"}


async def test_scan_ranges_adds_valid_and_dedupes(client: AsyncClient, headers: dict):
    settings.scanner_ranges = ["192.168.1.0/24"]
    res = await client.post("/api/v1/opnsense/scan-ranges", headers=headers,
                            json={"cidrs": ["192.168.1.0/24", "10.20.0.0/16"]})
    assert res.json()["added"] == ["10.20.0.0/16"]
    bad = await client.post("/api/v1/opnsense/scan-ranges", headers=headers, json={"cidrs": ["nope"]})
    assert bad.status_code == 422
