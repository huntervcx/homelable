"""Pydantic v2 schemas for OPNsense import."""

from pydantic import BaseModel, Field


class OpnsenseImportModes(BaseModel):
    """What to pull besides the firewall itself (always imported)."""

    clients: bool = Field(True, description="ARP table, DHCP leases and Unbound host overrides")
    vpn: bool = Field(True, description="WireGuard peers, OpenVPN sessions, IPsec tunnels")
    routes: bool = Field(True, description="Routed networks (routes, static routes, VPN allowed IPs)")


class OpnsenseConnectionRequest(BaseModel):
    host: str | None = Field(None, description="OPNsense host or IP (falls back to server env)")
    port: int = Field(443, ge=1, le=65535)
    api_key: str | None = Field(None, description="API key (falls back to server env)")
    api_secret: str | None = Field(None, description="API secret (falls back to server env)")
    verify_tls: bool = Field(False, description="Verify the TLS certificate (usually false: self-signed)")
    modes: OpnsenseImportModes = Field(default_factory=OpnsenseImportModes)


class OpnsenseTestConnectionResponse(BaseModel):
    connected: bool
    message: str


class OpnsenseNetwork(BaseModel):
    """A network seen behind the firewall but not directly attached to it."""

    cidr: str
    via: str
    source: str  # route | static | wireguard | ipsec


class OpnsenseImportResponse(BaseModel):
    device_count: int
    pending_created: int
    pending_updated: int
    links_recorded: int = 0
    networks: list[OpnsenseNetwork] = Field(default_factory=list)


class OpnsenseScanRangesRequest(BaseModel):
    cidrs: list[str] = Field(..., min_length=1, max_length=64)


class OpnsenseScanRangesResponse(BaseModel):
    added: list[str]
    scanner_ranges: list[str]


class OpnsenseConfig(BaseModel):
    host: str
    port: int
    verify_tls: bool
    sync_enabled: bool
    sync_interval: int
    credentials_configured: bool
    modes: OpnsenseImportModes


class OpnsenseSyncConfig(BaseModel):
    sync_enabled: bool
    sync_interval: int = Field(3600, ge=300)
    modes: OpnsenseImportModes = Field(default_factory=OpnsenseImportModes)
