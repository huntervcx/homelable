"""FastAPI router for the Proxmox Datacenter Manager (PDM) import + auto-sync config.

Fetches the nodes, VMs and LXC of every remote PDM manages (and its PBS
servers) and upserts them into the pending inventory — the same review->approve
flow as scans and the Proxmox VE import.

Credentials: the API token comes from the request body when provided, else
falls back to the server-configured env token — only for the configured host
and port, and never with TLS verification off when the server keeps it on. The
token is never persisted by the app and never returned by any endpoint.
"""

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import delete as sa_delete
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import normalize_host, settings
from app.core.scheduler import reschedule_pdm_sync, set_pdm_sync_enabled
from app.db.database import AsyncSessionLocal, get_db
from app.db.models import InventoryDevice, InventoryDeviceLink, Node, ScanRun
from app.schemas.pdm import (
    PdmConfig,
    PdmConnectionRequest,
    PdmEdgeOut,
    PdmImportPendingResponse,
    PdmImportResponse,
    PdmNodeOut,
    PdmSyncConfig,
    PdmTestConnectionResponse,
)
from app.schemas.scan import ScanRunResponse
from app.services.device_merge import reconcile_duplicates
from app.services.discovery_sources import add_source
from app.services.inventory_sync import attach_device_ids
from app.services.mac_utils import normalize_mac
from app.services.node_dedupe import dedupe_nodes_by_device
from app.services.pdm_service import (
    build_pdm_cluster_links,
    build_pdm_properties,
    fetch_pdm_inventory,
    merge_pdm_properties,
    test_pdm_connection,
)

logger = logging.getLogger(__name__)
router = APIRouter()

# Discovery sources for the two link shapes. Host->guest links render as
# 'virtual' edges; host<->host cluster links render as 'cluster' edges.
_PDM_GUEST_SOURCE = "pdm"
_PDM_CLUSTER_SOURCE = "pdm_cluster"
# Every imported device carries a synthetic ieee under this prefix
# (``pdm-{remote}/node/{name}``, ``pdm-{remote}/{vmid}``), built in pdm_service.
_PDM_IEEE_PREFIX = "pdm-"
# Rows already claimed by a Proxmox import (PDM or direct) are not matched by IP.
_CLAIMED_PREFIXES = (_PDM_IEEE_PREFIX, "pve-")


def _resolve_credentials(payload: PdmConnectionRequest) -> tuple[str, str]:
    """Resolve ``(token_id, token_secret)`` without sending server secrets to
    custom hosts: environment credentials are only valid for the configured
    PDM host and port. A custom host must provide both token fields."""
    if payload.token_id or payload.token_secret:
        if not payload.token_id or not payload.token_secret:
            raise HTTPException(status_code=400, detail="Provide both PDM token fields")
        return payload.token_id, payload.token_secret

    configured = normalize_host(settings.pdm_host)
    if (
        not configured
        or normalize_host(payload.host) != configured
        or payload.port != settings.pdm_port
    ):
        raise HTTPException(
            status_code=400, detail="Custom PDM hosts require an explicit API token"
        )
    # Verifying more strictly than configured is fine; turning off verification
    # the server keeps on would hand the env token to an unverified peer.
    if settings.pdm_verify_tls and not payload.verify_tls:
        raise HTTPException(
            status_code=400,
            detail="The server-configured PDM token requires TLS verification",
        )
    if not (settings.pdm_token_id and settings.pdm_token_secret):
        raise HTTPException(
            status_code=400,
            detail="No PDM API token provided and none configured on the server.",
        )
    return settings.pdm_token_id, settings.pdm_token_secret


@router.post("/test-connection", response_model=PdmTestConnectionResponse)
async def test_connection_endpoint(
    payload: PdmConnectionRequest,
    _: str = Depends(get_current_user),
) -> PdmTestConnectionResponse:
    """Validate host reachability + token before importing."""
    token_id, token_secret = _resolve_credentials(payload)
    connected, message = await test_pdm_connection(
        host=payload.host,
        port=payload.port,
        token_id=token_id,
        token_secret=token_secret,
        verify_tls=payload.verify_tls,
    )
    return PdmTestConnectionResponse(connected=connected, message=message)


@router.post("/import", response_model=PdmImportResponse)
async def import_pdm(
    payload: PdmConnectionRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(get_current_user),
) -> PdmImportResponse:
    """Fetch the inventory and return nodes + edges ready for canvas drop."""
    token_id, token_secret = _resolve_credentials(payload)
    try:
        nodes_raw, edges_raw, notice = await fetch_pdm_inventory(
            host=payload.host,
            port=payload.port,
            token_id=token_id,
            token_secret=token_secret,
            verify_tls=payload.verify_tls,
        )
    except ConnectionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Unexpected error during PDM import")
        raise HTTPException(status_code=500, detail="Unexpected error during PDM import") from exc

    # A canvas import is an import: the devices land in the Device Inventory
    # too, and each node carries the id of the row it draws so the canvas save
    # links to it instead of minting a second row.
    await _persist_pending_import(db, nodes_raw, edges_raw)
    nodes_raw = await attach_device_ids(db, nodes_raw)

    return PdmImportResponse(
        nodes=[PdmNodeOut(**n) for n in nodes_raw],
        edges=[PdmEdgeOut(**e) for e in edges_raw],
        device_count=len(nodes_raw),
        notice=notice,
    )


async def create_pdm_run(db: AsyncSession, host: str, port: int) -> ScanRun:
    """A running ``kind=pdm`` scan run, labelled with the PDM host."""
    run = ScanRun(
        status="running",
        kind="pdm",
        ranges=[f"{host}:{port}"],
        label=host,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    return run


@router.post("/import-pending", response_model=ScanRunResponse)
async def import_pdm_to_pending(
    payload: PdmConnectionRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(get_current_user),
) -> ScanRun:
    """Queue a PDM pending import as a background scan run (kind=pdm)."""
    token_id, token_secret = _resolve_credentials(payload)
    run = await create_pdm_run(db, payload.host, payload.port)
    background_tasks.add_task(
        _background_pdm_import,
        run.id,
        payload.host,
        payload.port,
        token_id,
        token_secret,
        payload.verify_tls,
    )
    return run


@router.post("/sync-now", response_model=ScanRunResponse)
async def sync_pdm_now(
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(get_current_user),
) -> ScanRun:
    """Trigger an immediate PDM sync using the server env config — the manual
    counterpart to the scheduled auto-sync job."""
    if not (settings.pdm_host and settings.pdm_token_id and settings.pdm_token_secret):
        raise HTTPException(
            status_code=400,
            detail="Cannot sync: no PDM host/token configured on the server.",
        )
    run = await create_pdm_run(db, settings.pdm_host, settings.pdm_port)
    background_tasks.add_task(
        _background_pdm_import,
        run.id,
        settings.pdm_host,
        settings.pdm_port,
        settings.pdm_token_id,
        settings.pdm_token_secret,
        settings.pdm_verify_tls,
    )
    return run


async def _background_pdm_import(
    run_id: str,
    host: str,
    port: int,
    token_id: str,
    token_secret: str,
    verify_tls: bool,
) -> None:
    async with AsyncSessionLocal() as db:
        try:
            nodes_raw, edges_raw, notice = await fetch_pdm_inventory(
                host=host,
                port=port,
                token_id=token_id,
                token_secret=token_secret,
                verify_tls=verify_tls,
            )
            result = await _persist_pending_import(db, nodes_raw, edges_raw)
            run = await db.get(ScanRun, run_id)
            if run:
                run.status = "done"
                run.devices_found = result.device_count
                run.finished_at = datetime.now(timezone.utc)
                # Non-fatal advisory: the run is done, the UI shows a warning.
                run.error = notice
                await db.commit()
            # Nudge the frontend to reload the inventory (same signal the IP
            # scan emits) so imported devices appear without a manual refresh.
            from app.api.routes.status import broadcast_scan_update
            await broadcast_scan_update(run_id=run_id, devices_found=result.device_count)
        except Exception as exc:
            # ConnectionError messages are already sanitized by the service;
            # anything else is logged in full and stored truncated.
            logger.exception("PDM import %s failed", run_id)
            await db.rollback()
            run = await db.get(ScanRun, run_id)
            if run:
                run.status = "error"
                run.error = (str(exc) if isinstance(exc, ConnectionError | ValueError) else "PDM import failed")[:500]
                run.finished_at = datetime.now(timezone.utc)
                await db.commit()


async def _persist_pending_import(
    db: AsyncSession,
    nodes_raw: list[dict[str, Any]],
    edges_raw: list[dict[str, Any]],
) -> PdmImportPendingResponse:
    """Upsert PDM nodes/edges into device_inventory + device_inventory_links.

    Two-tier identity (see ``_find_pending``): the synthetic ``ieee_address``
    first, else an existing row by MAC, then IP, so a device an IP scan found
    first is merged into rather than duplicated.

    Update-in-place only. Nothing is ever deleted; hidden rows stay hidden.
    """
    await dedupe_nodes_by_device(db)

    cluster_pairs = build_pdm_cluster_links(nodes_raw)
    cluster_members = {ieee for pair in cluster_pairs for ieee in pair}

    pending_created = 0
    pending_updated = 0

    for n in nodes_raw:
        ieee = n.get("ieee_address")
        if not ieee:
            continue
        ip = n.get("ip")
        mac = normalize_mac(n.get("mac"))
        props = build_pdm_properties(n)

        pending = await _find_pending(db, ieee, ip, mac)
        if pending is None:
            db.add(_new_pending(ieee, ip, mac, n, props))
            pending_created += 1
            continue

        drawn = (
            await db.execute(select(Node.id).where(Node.device_id == pending.id).limit(1))
        ).scalar_one_or_none() is not None
        # A device already on a canvas keeps its lifecycle; otherwise a row
        # approved earlier whose node is gone is revived to pending.
        _refresh_pending(pending, ieee, ip, mac, n, props, revive=not drawn)
        pending_updated += 1

        # A cluster host needs one left + one right handle for the cluster edge
        # endpoints (both default to 0).
        if ieee in cluster_members:
            for en in (
                await db.execute(select(Node).where(Node.device_id == pending.id))
            ).scalars().all():
                en.left_handles = max(en.left_handles or 0, 1)
                en.right_handles = max(en.right_handles or 0, 1)

    # Fold in any row this import just proved to be the same device.
    await reconcile_duplicates(db)

    imported = {n["ieee_address"] for n in nodes_raw if n.get("ieee_address")}
    links_recorded = await _replace_links(db, imported, edges_raw, cluster_pairs)
    await db.commit()

    return PdmImportPendingResponse(
        pending_created=pending_created,
        pending_updated=pending_updated,
        links_recorded=links_recorded,
        device_count=len(nodes_raw),
    )


async def _find_pending(
    db: AsyncSession, ieee: str, ip: str | None, mac: str | None
) -> InventoryDevice | None:
    """The inventory row this device *is*, in strict precedence order.

    1. The synthetic ``ieee_address`` — the only key that identifies a device.
    2. Else the NIC MAC (an identity, so it may match a row already claimed by
       a Proxmox import), else the IP — but an IP is not an identity, so that
       fallback skips rows claimed by a ``pdm-``/``pve-`` device. Oldest row
       wins, so a re-import is stable.
    """
    exact = (
        await db.execute(select(InventoryDevice).where(InventoryDevice.ieee_address == ieee))
    ).scalars().first()
    if exact is not None:
        return exact

    unclaimed = or_(
        InventoryDevice.ieee_address.is_(None),
        ~or_(*(InventoryDevice.ieee_address.startswith(p) for p in _CLAIMED_PREFIXES)),
    )
    for column, value, claimed_ok in (
        (InventoryDevice.mac, mac, True),
        (InventoryDevice.ip, ip, False),
    ):
        if not value:
            continue
        where = [column == value] if claimed_ok else [column == value, unclaimed]
        row = (
            await db.execute(
                select(InventoryDevice)
                .where(*where)
                .order_by(InventoryDevice.discovered_at, InventoryDevice.id)
            )
        ).scalars().first()
        if row is not None:
            return row
    return None


def _adopted_ieee(current: str | None, ieee: str) -> str:
    """The ``ieee_address`` a row carries once this device merges into it.

    A row with none, or one that is already a PDM device (matched by MAC, so
    the same guest under a stale remote or node name), takes the fresh id.
    Anything else keeps its own: a mesh ieee is a real hardware address, and a
    ``pve-`` id belongs to the direct Proxmox import.
    """
    if not current or current.startswith(_PDM_IEEE_PREFIX):
        return ieee
    return current


def _new_pending(
    ieee: str,
    ip: str | None,
    mac: str | None,
    n: dict[str, Any],
    props: list[dict[str, Any]],
) -> InventoryDevice:
    return InventoryDevice(
        ieee_address=ieee,
        ip=ip,
        mac=mac,
        hostname=n.get("hostname"),
        friendly_name=n.get("label"),
        suggested_type=n.get("type"),
        vendor=n.get("vendor"),
        model=n.get("model"),
        properties=props,
        cpu_count=n.get("cpu_count"),
        ram_gb=n.get("ram_gb"),
        disk_gb=n.get("disk_gb"),
        status="pending",
        discovery_source=_PDM_GUEST_SOURCE,
        discovery_sources=[_PDM_GUEST_SOURCE],
    )


def _sources_after_merge(row: InventoryDevice) -> list[str]:
    """Discovery sources after a PDM import merges into ``row``. Must run
    BEFORE the ieee is adopted, so it can tell a scanned device from an
    imported one; a scanned row keeps an IP-scan source."""
    sources = add_source(row.discovery_sources, row.discovery_source)
    was_scanned = not (row.ieee_address or "").startswith(_CLAIMED_PREFIXES)
    if was_scanned and row.ip and not any(s in ("arp", "mdns") for s in sources):
        sources = add_source(sources, "arp")
    return add_source(sources, _PDM_GUEST_SOURCE)


def _refresh_pending(
    pending: InventoryDevice,
    ieee: str,
    ip: str | None,
    mac: str | None,
    n: dict[str, Any],
    props: list[dict[str, Any]],
    revive: bool,
) -> None:
    pending.discovery_sources = _sources_after_merge(pending)
    pending.ieee_address = _adopted_ieee(pending.ieee_address, ieee)
    pending.ip = ip or pending.ip
    pending.mac = pending.mac or mac
    pending.hostname = n.get("hostname") or pending.hostname
    pending.friendly_name = n.get("label") or pending.friendly_name
    pending.suggested_type = n.get("type") or pending.suggested_type
    pending.vendor = n.get("vendor") or pending.vendor
    pending.model = n.get("model") or pending.model
    pending.properties = merge_pdm_properties(list(pending.properties or []), props)
    pending.cpu_count = pending.cpu_count or n.get("cpu_count")
    pending.ram_gb = pending.ram_gb or n.get("ram_gb")
    pending.disk_gb = pending.disk_gb or n.get("disk_gb")
    if revive and pending.status == "approved":
        pending.status = "pending"
    # hidden stays hidden.


async def _replace_links(
    db: AsyncSession,
    imported: set[str],
    edges_raw: list[dict[str, Any]],
    cluster_pairs: list[tuple[str, str]],
) -> int:
    """Wipe this import's PDM links touching an imported device and re-insert
    the fresh set (host->guest ``pdm``, host<->host ``pdm_cluster``). Scoped
    to the imported ieees so another source's links are never erased."""
    await db.execute(
        sa_delete(InventoryDeviceLink).where(
            InventoryDeviceLink.discovery_source.in_([_PDM_GUEST_SOURCE, _PDM_CLUSTER_SOURCE]),
            or_(
                InventoryDeviceLink.source_ieee.in_(imported),
                InventoryDeviceLink.target_ieee.in_(imported),
            ),
        )
    )
    recorded = 0
    seen: set[tuple[str, str]] = set()

    def _add(src: str | None, tgt: str | None, source: str) -> None:
        nonlocal recorded
        if not src or not tgt or (src, tgt) in seen:
            return
        seen.add((src, tgt))
        db.add(InventoryDeviceLink(source_ieee=src, target_ieee=tgt, discovery_source=source))
        recorded += 1

    for e in edges_raw:
        _add(e.get("source"), e.get("target"), _PDM_GUEST_SOURCE)
    for src, tgt in cluster_pairs:
        _add(src, tgt, _PDM_CLUSTER_SOURCE)

    return recorded


@router.get("/config", response_model=PdmConfig)
async def get_pdm_config(_: str = Depends(get_current_user)) -> PdmConfig:
    """Return non-secret PDM config. Never includes the token — only whether
    one is configured on the server."""
    return PdmConfig(
        host=settings.pdm_host,
        port=settings.pdm_port,
        verify_tls=settings.pdm_verify_tls,
        sync_enabled=settings.pdm_sync_enabled,
        sync_interval=settings.pdm_sync_interval,
        token_configured=bool(settings.pdm_token_id and settings.pdm_token_secret),
    )


@router.post("/config", response_model=PdmConfig)
async def save_pdm_config(
    payload: PdmSyncConfig,
    _: str = Depends(get_current_user),
) -> PdmConfig:
    """Persist the auto-sync activation (enabled + interval) and apply it live.

    This is the ONLY PDM config the app writes. Connection settings (host,
    port, token, verify_tls) are env-only and never accepted or persisted here.
    """
    if payload.sync_enabled and not (
        settings.pdm_host and settings.pdm_token_id and settings.pdm_token_secret
    ):
        raise HTTPException(
            status_code=400,
            detail="Cannot enable auto-sync: no PDM host/token configured in the server env.",
        )
    try:
        settings.pdm_sync_enabled = payload.sync_enabled
        settings.pdm_sync_interval = payload.sync_interval
        settings.save_overrides()
        set_pdm_sync_enabled(payload.sync_enabled)
        if payload.sync_enabled:
            reschedule_pdm_sync(payload.sync_interval)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return await get_pdm_config()
