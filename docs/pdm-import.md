# Proxmox Datacenter Manager Import

Connects Homelable to a **Proxmox Datacenter Manager** (PDM) instance and brings
every remote it manages into the Device Inventory (and, optionally, onto the
canvas): the Proxmox VE nodes, their VMs and LXC containers, and any Proxmox
Backup Server. It can also **sync** on a schedule.

PDM already aggregates several clusters and standalone hosts behind one API, so
one URL and one token cover the whole lab. If you only run a single Proxmox VE
host or cluster and no PDM, use the [Proxmox VE import](./proxmox-import.md).

> **Server-dependent feature** - requires the Homelable backend. It is hidden in
> the no-backend standalone/demo build.

---

## What is imported

PDM calls each Proxmox VE cluster/host or Backup Server a **remote**. For every
remote the token can see:

- **Each PVE node** as a `proxmox` node: name, vCPU count, RAM and run state.
  Nodes of one remote are chained with `cluster` edges; nodes of different
  remotes are never linked to each other.
- **Each VM** as a `vm` node and **each LXC container** as an `lxc` node, linked
  to their node with a `virtual` edge, with run state, vCPUs, RAM and root disk
  size. Templates are skipped.
- **Each Proxmox Backup Server** node as a `server` node (vendor *Proxmox Backup
  Server*).
- **The remote's name** as a hidden-by-default **Remote** property, next to the
  VMID, kind and specs (all hidden by default, like the Proxmox VE import).

Identifiers are synthetic and scoped by remote, so the same VMID on two remotes
never collides, and a guest keeps its identity when it migrates between the
nodes of one remote:

| Object | Identifier |
|---|---|
| PVE node | `pdm-<remote>/node/<node>` |
| VM / LXC | `pdm-<remote>/<vmid>` |
| PBS node | `pdm-<remote>/pbs/<name>` |

### Addresses

PDM's resource list carries no network information, so the import asks for it
where it can, and never fails when it cannot:

- **MAC** of every guest, read from its `net0` configuration (works for stopped
  guests). This is what merges a guest into a device an ARP scan already found.
- **IPv4** of an LXC with a static address in `net0`. A VM's address is not
  available (PDM has no guest-agent call), and neither is a DHCP container's.
  An IP scan fills those in, and merges into the same row by MAC.
- **IP of a node** only when its remote has a single node and PDM lists that
  node by IP address.

If the token cannot read a guest's configuration, the guest is still imported,
just without a MAC/IP.

---

## Prerequisites

1. A reachable PDM instance (default API port **8443**).
2. An **API token**: *Access Control > API Tokens* in PDM. The identifier looks
   like `user@realm!tokenname`. Grant it the read-only **Auditor** role on the
   path **`/resource`** (and to the user too when the token is
   privilege-separated). The token's secret is shown only once.

   Homelable sends it as `Authorization: PDMAPIToken=<token id>:<secret>`, the
   PDM scheme (note the colon: it is not the `PVEAPIToken=...=...` form of
   Proxmox VE).
3. PDM serves a self-signed certificate by default: untick **Verify TLS
   certificate**, or install a trusted one.

---

## Importing

Open **Import** in the sidebar and pick **Proxmox Datacenter Manager**. Enter the
host, port (default `8443`) and token, **Test Connection** to check reachability,
authentication and how many remotes the token sees, then choose where devices go:

- **Device inventory only** - runs in the background; follow it in Scan
  History, then approve devices from the Device Inventory. Approving a node asks
  whether to bring its guests along, joined by virtual edges.
- **Inventory + canvas** - fetches immediately, lists nodes, VMs, LXC and backup
  servers, and adds the ones you tick to the canvas. Optionally nest each
  node's guests inside it as a container. Everything lands in the inventory too,
  including devices you untick before adding to the canvas.

Leave the token blank to use the one configured on the server (below); it is
only ever used for the configured host and port, and refused when you turn TLS
verification off while the server has it on.

If a remote could not be queried (offline, the token has no access), the others
still import and the Scan History entry (or a warning in canvas mode) names the
remote that failed.

### Re-imports and merging

Re-importing updates rows in place; nothing is ever deleted, and hidden devices
stay hidden. A device is recognised by its identifier first, then by MAC, then by
IP (an IP match never takes over a device another Proxmox import already owns).

Importing the same cluster **both** through PDM and through the direct
[Proxmox VE import](./proxmox-import.md) is not recommended: the inventory rows
merge by MAC, but the second import cannot move the first one's links, so the
host-to-guest edges of the second source stay detached. Pick one per cluster.

---

## Configuration

Connection settings are environment-only and are never stored by the app nor
returned by the API:

| Variable | Default | Meaning |
|---|---|---|
| `PDM_HOST` | | PDM host or IP |
| `PDM_PORT` | `8443` | API port |
| `PDM_TOKEN_ID` | | `user@realm!tokenname` |
| `PDM_TOKEN_SECRET` | | The token secret |
| `PDM_VERIFY_TLS` | `true` | Set `false` for a self-signed certificate |
| `PDM_SYNC_ENABLED` | `false` | Run the scheduled sync |
| `PDM_SYNC_INTERVAL` | `3600` | Seconds between syncs (minimum 300) |

Once host and token are set, **Settings > PDM auto-sync** turns the schedule on
and off, changes the interval and offers **Re-sync now**. Only the activation
and the interval are persisted by the app (in `scan_config.json`); each run is
recorded in Scan History as a `PDM` entry.

---

## API

All endpoints require authentication and live under `/api/v1/pdm`:

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/test-connection` | Check reachability, token and visible remotes |
| `POST` | `/import` | Fetch and return nodes + edges (canvas mode); also fills the inventory |
| `POST` | `/import-pending` | Queue a background import (`kind=pdm` scan run) |
| `POST` | `/sync-now` | Queue an import from the server environment config |
| `GET` / `POST` | `/config` | Read the non-secret config / save the auto-sync activation |

Responses never carry a token.

### PDM endpoints used

`GET /version`, `GET /remotes/remote` (best effort, for node addresses; only the
remote's `id`, `type` and `nodes` are read), `GET /resources/list` and
`GET /pve/remotes/{remote}/{qemu|lxc}/{vmid}/config` (best effort, one per guest).

---

## Troubleshooting

| Message | Cause |
|---|---|
| *Authentication failed* | Wrong token id/secret, or the token lacks the Auditor role on `/resource` |
| *PDM returned no remotes* / *no node, VM or LXC was visible* | The token sees nothing: grant `Auditor` on `/resource` (to the user too for a privilege-separated token) |
| *TLS verification failed* | Self-signed certificate: untick **Verify TLS certificate** |
| *Some remotes could not be queried* | A remote is offline or unreachable from PDM; the others imported |
