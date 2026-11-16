/** Cluster-edge wiring for a Proxmox import.
 *
 * Proxmox host nodes discovered in the same import belong to one cluster, so we
 * chain them together with `cluster` edges. The chain uses the left/right
 * connection points (right source → left target) to keep them visually distinct
 * from the vertical host→guest `virtual` edges (bottom → top). Left/right
 * handles default to 0, so the hosts must opt into one handle per side for the
 * edge endpoints to exist (see `sideDefault` in handleUtils).
 */
import type { ProxmoxCanvasNode, ProxmoxNode } from './types'

/** Source/target handle IDs for a cluster link (see handleUtils.handleId).
 * Both are the bare slot-0 side names — the canonical stored form. React Flow
 * resolves a bare id to that side; a '-t' target id fails to resolve and falls
 * back to the top handle (which is why the target must be 'left', not 'left-t'). */
export const CLUSTER_SOURCE_HANDLE = 'right'
export const CLUSTER_TARGET_HANDLE = 'left'

export interface ClusterEdgeSpec {
  source: string
  target: string
  sourceHandle: typeof CLUSTER_SOURCE_HANDLE
  targetHandle: typeof CLUSTER_TARGET_HANDLE
}

/**
 * Chain all Proxmox host nodes (`type === 'proxmox'`) from one import into a
 * left→right cluster line. Returns `[]` when fewer than two hosts are present
 * (a single host is not a cluster). Guests (vm/lxc) are ignored.
 */
export function buildProxmoxClusterEdges(nodes: ProxmoxCanvasNode[]): ClusterEdgeSpec[] {
  // Hosts of different PDM remotes are unrelated machines: one chain per remote.
  // A plain Proxmox import carries no `remote`, so it stays a single chain.
  const chains = new Map<string, ProxmoxCanvasNode[]>()
  for (const n of nodes) {
    if (n.type !== 'proxmox') continue
    const key = n.remote ?? ''
    chains.set(key, [...(chains.get(key) ?? []), n])
  }
  const edges: ClusterEdgeSpec[] = []
  for (const hosts of chains.values()) {
    for (let i = 0; i < hosts.length - 1; i++) {
      edges.push({
        source: hosts[i].id,
        target: hosts[i + 1].id,
        sourceHandle: CLUSTER_SOURCE_HANDLE,
        targetHandle: CLUSTER_TARGET_HANDLE,
      })
    }
  }
  return edges
}

/** True when the import contains a Proxmox cluster (≥2 host nodes). */
export function isProxmoxCluster(nodes: ProxmoxNode[]): boolean {
  return nodes.filter((n) => n.type === 'proxmox').length >= 2
}
