"""FastAPI router for OPNsense import + auto-sync config."""

import ipaddress
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.scheduler import reschedule_opnsense_sync, set_opnsense_sync_enabled
from app.db.database import AsyncSessionLocal, get_db
from app.db.models import InventoryDevice, InventoryDeviceLink, ScanRun
from app.schemas.opnsense import (
    OpnsenseConfig,
    OpnsenseConnectionRequest,
    OpnsenseImportModes,
    OpnsenseImportResponse,
    OpnsenseNetwork,
    OpnsenseScanRangesRequest,
    OpnsenseScanRangesResponse,
    OpnsenseSyncConfig,
    OpnsenseTestConnectionResponse,
)
from app.services.discovery_sources import add_source
from app.services.opnsense_service import (
    SOURCE_FIREWALL,
    SOURCES,
    OpnsenseError,
    fetch_opnsense_inventory,
    merge_opnsense_properties,
    test_opnsense_connection,
)

logger = logging.getLogger(__name__)
router = APIRouter()


def _configured_modes() -> OpnsenseImportModes:
    return OpnsenseImportModes(
        clients=settings.opnsense_import_clients,
        vpn=settings.opnsense_import_vpn,
        routes=settings.opnsense_import_routes,
    )


def _resolve(payload: OpnsenseConnectionRequest) -> tuple[str, int, str, str, bool]:
    host = payload.host or settings.opnsense_host
    key = payload.api_key or settings.opnsense_api_key
    secret = payload.api_secret or settings.opnsense_api_secret
    if not host or not key or not secret:
        raise HTTPException(
            status_code=400,
            detail="No OPNsense host/API key provided and none configured on the server.",
        )
    port = payload.port if payload.host else settings.opnsense_port
    verify = payload.verify_tls if payload.host else settings.opnsense_verify_tls
    return host, port, key, secret, verify


@router.post("/test-connection", response_model=OpnsenseTestConnectionResponse)
async def test_connection_endpoint(
    payload: OpnsenseConnectionRequest,
    _: str = Depends(get_current_user),
) -> OpnsenseTestConnectionResponse:
    host, port, key, secret, verify = _resolve(payload)
    connected, message = await test_opnsense_connection(host, port, key, secret, verify)
    return OpnsenseTestConnectionResponse(connected=connected, message=message)


async def _record_run(
    db: AsyncSession,
    target: str,
    started_at: datetime,
    *,
    status: str,
    devices_found: int = 0,
    error: str | None = None,
) -> None:
    db.add(
        ScanRun(
            status=status,
            kind="opnsense",
            ranges=[target],
            devices_found=devices_found,
            started_at=started_at,
            finished_at=datetime.now(timezone.utc),
            error=error,
        )
    )
    await db.commit()


@router.post("/import-pending", response_model=OpnsenseImportResponse)
async def import_opnsense_pending(
    payload: OpnsenseConnectionRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(get_current_user),
) -> OpnsenseImportResponse:
    host, port, key, secret, verify = _resolve(payload)
    started_at = datetime.now(timezone.utc)
    target = f"{host}:{port}"
    try:
        data = await fetch_opnsense_inventory(
            host, port, key, secret, verify,
            clients=payload.modes.clients,
            vpn=payload.modes.vpn,
            routes=payload.modes.routes,
        )
    except OpnsenseError as exc:
        await _record_run(db, target, started_at, status="error", error=str(exc))
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Unexpected error during OPNsense import")
        await _record_run(db, target, started_at, status="error", error="Unexpected error during OPNsense import")
        raise HTTPException(status_code=500, detail="Unexpected error during OPNsense import") from exc

    result = await _persist(db, data)
    await _record_run(db, target, started_at, status="done", devices_found=result.device_count)
    return result


@router.post("/sync-now", response_model=OpnsenseImportResponse)
async def sync_opnsense_now(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(get_current_user),
) -> OpnsenseImportResponse:
    if not (settings.opnsense_host and settings.opnsense_api_key and settings.opnsense_api_secret):
        raise HTTPException(
            status_code=400,
            detail="Cannot sync: no OPNsense host/API key configured on the server.",
        )
    started_at = datetime.now(timezone.utc)
    target = f"{settings.opnsense_host}:{settings.opnsense_port}"
    try:
        data = await _fetch_from_env()
    except Exception as exc:
        await _record_run(db, target, started_at, status="error", error=str(exc))
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    result = await _persist(db, data)
    await _record_run(db, target, started_at, status="done", devices_found=result.device_count)
    return result


async def _fetch_from_env() -> dict[str, Any]:
    return await fetch_opnsense_inventory(
        settings.opnsense_host,
        settings.opnsense_port,
        settings.opnsense_api_key,
        settings.opnsense_api_secret,
        settings.opnsense_verify_tls,
        clients=settings.opnsense_import_clients,
        vpn=settings.opnsense_import_vpn,
        routes=settings.opnsense_import_routes,
    )


@router.post("/scan-ranges", response_model=OpnsenseScanRangesResponse)
async def add_scan_ranges(
    payload: OpnsenseScanRangesRequest,
    _: str = Depends(get_current_user),
) -> OpnsenseScanRangesResponse:
    """Add networks discovered behind the firewall to the scanner's ranges.

    Only the CIDRs the user picked, validated and de-duplicated. Nothing is
    scanned here — the next scheduled or manual scan covers them.
    """
    added: list[str] = []
    ranges = list(settings.scanner_ranges)
    for cidr in payload.cidrs:
        try:
            net = str(ipaddress.ip_network(cidr, strict=False))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"Invalid network: {cidr}") from exc
        if net not in ranges:
            ranges.append(net)
            added.append(net)
    if added:
        settings.scanner_ranges = ranges
        settings.save_overrides()
    return OpnsenseScanRangesResponse(added=added, scanner_ranges=ranges)


@router.get("/config", response_model=OpnsenseConfig)
async def get_opnsense_config(_: str = Depends(get_current_user)) -> OpnsenseConfig:
    return OpnsenseConfig(
        host=settings.opnsense_host,
        port=settings.opnsense_port,
        verify_tls=settings.opnsense_verify_tls,
        sync_enabled=settings.opnsense_sync_enabled,
        sync_interval=settings.opnsense_sync_interval,
        credentials_configured=bool(settings.opnsense_api_key and settings.opnsense_api_secret),
        modes=_configured_modes(),
    )


@router.post("/config", response_model=OpnsenseConfig)
async def save_opnsense_config(
    payload: OpnsenseSyncConfig,
    _: str = Depends(get_current_user),
) -> OpnsenseConfig:
    if payload.sync_enabled and not (
        settings.opnsense_host and settings.opnsense_api_key and settings.opnsense_api_secret
    ):
        raise HTTPException(
            status_code=400,
            detail="Cannot enable auto-sync: no OPNsense host/API key configured in the server env.",
        )
    try:
        settings.opnsense_sync_enabled = payload.sync_enabled
        settings.opnsense_sync_interval = payload.sync_interval
        settings.opnsense_import_clients = payload.modes.clients
        settings.opnsense_import_vpn = payload.modes.vpn
        settings.opnsense_import_routes = payload.modes.routes
        settings.save_overrides()
        set_opnsense_sync_enabled(payload.sync_enabled)
        if payload.sync_enabled:
            reschedule_opnsense_sync(payload.sync_interval)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return await get_opnsense_config()


async def _find_existing(db: AsyncSession, ieee: str, mac: str | None) -> InventoryDevice | None:
    """The row this record *is*: same synthetic id, else same MAC (any source)."""
    row = (
        await db.execute(select(InventoryDevice).where(InventoryDevice.ieee_address == ieee))
    ).scalars().first()
    if row is None and mac:
        row = (
            await db.execute(
                select(InventoryDevice)
                .where(InventoryDevice.mac == mac)
                .order_by(InventoryDevice.discovered_at, InventoryDevice.id)
            )
        ).scalars().first()
    return row


def _owns(row: InventoryDevice) -> bool:
    sources = {s for s in (row.discovery_sources or []) if s}
    return bool(sources) and sources <= set(SOURCES)


async def _persist(db: AsyncSession, data: dict[str, Any]) -> OpnsenseImportResponse:
    created = updated = 0
    devices: list[dict[str, Any]] = data["devices"]

    for dev in devices:
        ieee = dev["ieee_address"]
        mac = dev.get("mac")
        source = dev.get("source") or SOURCE_FIREWALL
        existing = await _find_existing(db, ieee, mac)

        if existing is None:
            db.add(
                InventoryDevice(
                    ieee_address=ieee,
                    ip=dev.get("ip"),
                    mac=mac,
                    hostname=dev.get("hostname"),
                    friendly_name=dev.get("label"),
                    suggested_type=dev.get("type"),
                    vendor=dev.get("vendor"),
                    model=dev.get("model"),
                    properties=dev.get("properties", []),
                    status="pending",
                    discovery_source=source,
                    discovery_sources=[source],
                )
            )
            created += 1
            continue

        existing.discovery_sources = add_source(list(existing.discovery_sources or []), source)
        existing.ieee_address = existing.ieee_address or ieee
        existing.ip = dev.get("ip") or existing.ip
        existing.mac = existing.mac or mac
        existing.properties = merge_opnsense_properties(
            list(existing.properties or []), dev.get("properties", [])
        )
        # A row another source owns keeps its own description (a Proxmox LXC
        # seen in the ARP table must not be retyped "generic").
        if _owns(existing):
            existing.hostname = dev.get("hostname") or existing.hostname
            existing.friendly_name = dev.get("label") or existing.friendly_name
            existing.suggested_type = dev.get("type") or existing.suggested_type
            existing.vendor = dev.get("vendor") or existing.vendor
            existing.model = dev.get("model") or existing.model
        else:
            existing.hostname = existing.hostname or dev.get("hostname")
            existing.friendly_name = existing.friendly_name or dev.get("label")
            existing.suggested_type = existing.suggested_type or dev.get("type")
            existing.vendor = existing.vendor or dev.get("vendor")
            existing.model = existing.model or dev.get("model")
        if existing.status == "hidden":
            existing.status = "pending"
        updated += 1

    await db.flush()

    # Firewall → VPN peer links. Replaced wholesale for this firewall so a peer
    # that left the tunnel list stops being linked.
    link_sources = {s for s, _ in data["links"]}
    if link_sources:
        await db.execute(
            sa_delete(InventoryDeviceLink).where(
                InventoryDeviceLink.discovery_source == "opnsense",
                InventoryDeviceLink.source_ieee.in_(link_sources),
            )
        )
    seen: set[tuple[str, str]] = set()
    for src, tgt in data["links"]:
        if (src, tgt) in seen:
            continue
        seen.add((src, tgt))
        db.add(InventoryDeviceLink(source_ieee=src, target_ieee=tgt, discovery_source="opnsense"))

    await db.commit()
    return OpnsenseImportResponse(
        device_count=len(devices),
        pending_created=created,
        pending_updated=updated,
        links_recorded=len(seen),
        networks=[OpnsenseNetwork(**n) for n in data["networks"]],
    )


async def _background_opnsense_sync(run_id: str) -> None:
    async with AsyncSessionLocal() as db:
        try:
            data = await _fetch_from_env()
            result = await _persist(db, data)
            run = await db.get(ScanRun, run_id)
            if run:
                run.status = "done"
                run.devices_found = result.device_count
                run.finished_at = datetime.now(timezone.utc)
                await db.commit()
            from app.api.routes.status import broadcast_scan_update

            await broadcast_scan_update(run_id=run_id, devices_found=result.device_count)
        except Exception as exc:
            logger.exception("OPNsense sync %s failed", run_id)
            await db.rollback()
            run = await db.get(ScanRun, run_id)
            if run:
                run.status = "error"
                run.error = str(exc)[:500]
                run.finished_at = datetime.now(timezone.utc)
                await db.commit()
