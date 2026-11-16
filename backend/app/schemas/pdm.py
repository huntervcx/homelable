"""Pydantic v2 schemas for the Proxmox Datacenter Manager (PDM) import.

Token fields are accepted on requests only and are optional — when omitted the
backend falls back to the server-configured token (env), for the configured
host only. No response schema ever carries a token.
"""

from pydantic import BaseModel, Field


class PdmConnectionRequest(BaseModel):
    host: str = Field(..., description="PDM host or IP")
    port: int = Field(8443, ge=1, le=65535, description="PDM API port")
    token_id: str | None = Field(
        None, description="API token id 'user@realm!tokenname' (falls back to server env)"
    )
    token_secret: str | None = Field(
        None, description="API token secret (falls back to server env)"
    )
    verify_tls: bool = Field(True, description="Verify the PDM TLS certificate")


class PdmTestConnectionResponse(BaseModel):
    connected: bool
    message: str


class PdmNodeOut(BaseModel):
    """A homelable-ready node: a PVE node, a PBS server, a VM or an LXC."""

    id: str
    label: str
    type: str  # proxmox | server | vm | lxc
    ieee_address: str
    hostname: str | None = None
    ip: str | None = None
    status: str
    cpu_count: int | None = None
    ram_gb: float | None = None
    disk_gb: float | None = None
    vendor: str | None = None
    model: str | None = None
    parent_ieee: str | None = None
    # PDM remote the device belongs to; drives per-cluster grouping.
    remote: str | None = None
    # The Device Inventory row this node draws, stamped by the import.
    device_id: str | None = None


class PdmEdgeOut(BaseModel):
    source: str
    target: str


class PdmImportResponse(BaseModel):
    nodes: list[PdmNodeOut]
    edges: list[PdmEdgeOut]
    device_count: int
    # Non-fatal advisory (a remote that failed, a token that sees nothing).
    notice: str | None = None


class PdmImportPendingResponse(BaseModel):
    """Result of importing a PDM inventory into the pending section."""

    pending_created: int
    pending_updated: int
    links_recorded: int
    device_count: int


class PdmConfig(BaseModel):
    """Non-secret PDM connection + auto-sync config (GET response).

    Connection fields are env-only and read-only here — surfaced for display.
    ``token_configured`` reflects whether a server-side token is present.
    Never carries a token itself."""

    host: str = ""
    port: int = Field(8443, ge=1, le=65535)
    verify_tls: bool = True
    sync_enabled: bool = False
    sync_interval: int = Field(3600, ge=300)
    token_configured: bool = False


class PdmSyncConfig(BaseModel):
    """User-editable auto-sync config (POST body). The ONLY persisted PDM
    settings; connection fields are env-only and deliberately not accepted."""

    sync_enabled: bool = False
    sync_interval: int = Field(3600, ge=300, le=86400)
