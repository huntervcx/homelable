# OPNsense Import

Reads an OPNsense firewall through its REST API and drops what it knows into the
**Device Inventory** as pending devices: the firewall itself, the hosts on its
networks, its VPN peers and the networks routed behind it. Nothing touches a
canvas until you approve it.

## What is imported

| Source | API endpoint(s) | Becomes |
|---|---|---|
| Firewall | `core/firmware/status`, `diagnostics/system/system_information`, `interfaces/overview/interfaces_info` | a `firewall` device with its version and one property per interface |
| LAN hosts | `diagnostics/interface/search_arp`, `dhcpv4/leases/search_lease` (ISC), `kea/leases4/search`, `unbound/settings/search_host_override` | `generic` devices, merged by MAC (ARP + DHCP + DNS name = one row) |
| WireGuard | `wireguard/service/show` | one device per peer (public key, endpoint, allowed IPs, last handshake), linked to the firewall |
| OpenVPN | `openvpn/service/search_sessions` | one device per connected client, linked to the firewall |
| IPsec | `ipsec/sessions/search_phase1` | one `router` device per tunnel (remote gateway), linked to the firewall |
| Routed networks | `diagnostics/interface/get_routes`, `routes/routes/searchroute`, WireGuard allowed IPs, IPsec remote traffic selectors | a list of CIDRs, see below |

Every part except the firewall itself is optional and best-effort: a plugin that
is not installed (no WireGuard, no Kea…) or a privilege the key lacks only drops
that part, it never fails the import.

A host already known from another source (an IP scan, Proxmox, UniFi…) is
**merged by MAC** instead of duplicated, and keeps its own type and description.

## Discovering other networks

Routes through a gateway, static routes, and the subnets a VPN peer is allowed to
reach are collected as *routed networks*. After an import the dialog lists them
and lets you add the ones you want to the scanner ranges (Settings → Scanner), so
the next scan covers those networks too. Directly-attached networks are left out
(they are already your interfaces), and nothing is scanned by the import itself.

## Setup

1. In OPNsense: **System → Access → Users**, create a user (or pick an existing
   one) and add an **API key**. Download the `key`/`secret` file.
2. Give the user read access to the endpoints above. A read-only role is enough:
   Homelable only reads. Typical privileges: *Diagnostics: ARP Table*,
   *Diagnostics: Interfaces*, *Services: DHCP*, *Services: Unbound DNS*,
   *VPN: WireGuard / OpenVPN / IPsec*, *System: Routes*, *System: Firmware*,
   *Lobby: Dashboard*. A missing privilege only hides the matching part.
3. Import from the UI (**Import from… → OPNsense**), or set the server env:

```env
OPNSENSE_HOST=192.168.1.1
OPNSENSE_PORT=443
OPNSENSE_API_KEY=...
OPNSENSE_API_SECRET=...
OPNSENSE_VERIFY_TLS=false   # self-signed certificate
```

The key and secret are **env-only**: they are never written to `scan_config.json`
nor returned by any endpoint.

## Auto-sync

With the env above set, Settings can enable a scheduled re-import
(`opnsense_sync_enabled`, `opnsense_sync_interval`, floor 300 s) with the same
three source switches. Each run is recorded in Scan History as kind `opnsense`.

## Endpoints

`POST /api/v1/opnsense/test-connection`, `/import-pending`, `/sync-now`,
`/scan-ranges`, `GET|POST /api/v1/opnsense/config`.
