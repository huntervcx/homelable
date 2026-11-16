/** Shared Proxmox Datacenter Manager (PDM) import type definitions. */

/** A PVE node (`proxmox`), a PBS server (`server`), a VM or an LXC. */
export type PdmNodeType = 'proxmox' | 'server' | 'vm' | 'lxc'

export interface PdmNode {
  id: string
  label: string
  type: PdmNodeType
  ieee_address: string
  hostname?: string | null
  ip?: string | null
  status: string
  cpu_count?: number | null
  ram_gb?: number | null
  disk_gb?: number | null
  vendor?: string | null
  model?: string | null
  parent_ieee?: string | null
  /** PDM remote the device belongs to — hosts of one remote form a cluster. */
  remote?: string | null
  /** Device Inventory row this node draws — stamped by the import so the
   * canvas save links to it instead of minting a second row. */
  device_id?: string | null
}

export interface PdmEdge {
  source: string
  target: string
}

export interface PdmImportResponse {
  nodes: PdmNode[]
  edges: PdmEdge[]
  device_count: number
  /** Non-fatal advisory (a remote that failed, a token that sees nothing). */
  notice?: string | null
}
