import { describe, it, expect } from 'vitest'
import {
  buildProxmoxClusterEdges,
  isProxmoxCluster,
  CLUSTER_SOURCE_HANDLE,
  CLUSTER_TARGET_HANDLE,
} from '../clusterEdges'
import type { ProxmoxNode } from '../types'

function host(id: string): ProxmoxNode {
  return { id, label: id, type: 'proxmox', ieee_address: id, status: 'online' }
}
function guest(id: string, type: 'vm' | 'lxc' = 'vm'): ProxmoxNode {
  return { id, label: id, type, ieee_address: id, status: 'online' }
}

describe('buildProxmoxClusterEdges', () => {
  it('chains multiple hosts left→right, ignoring guests', () => {
    const nodes = [host('pve-a'), guest('vm-1'), host('pve-b'), host('pve-c'), guest('ct-1', 'lxc')]
    const edges = buildProxmoxClusterEdges(nodes)
    expect(edges.map((e) => [e.source, e.target])).toEqual([
      ['pve-a', 'pve-b'],
      ['pve-b', 'pve-c'],
    ])
    // Endpoints use the left/right handles.
    for (const e of edges) {
      expect(e.sourceHandle).toBe(CLUSTER_SOURCE_HANDLE)
      expect(e.targetHandle).toBe(CLUSTER_TARGET_HANDLE)
    }
  })

  it('returns no edges for a single host', () => {
    expect(buildProxmoxClusterEdges([host('pve-a'), guest('vm-1')])).toEqual([])
  })

  it('returns no edges when there are no hosts', () => {
    expect(buildProxmoxClusterEdges([guest('vm-1'), guest('ct-1', 'lxc')])).toEqual([])
  })

  it('isProxmoxCluster is true only with 2+ hosts', () => {
    expect(isProxmoxCluster([host('a')])).toBe(false)
    expect(isProxmoxCluster([host('a'), host('b')])).toBe(true)
    expect(isProxmoxCluster([host('a'), guest('vm-1')])).toBe(false)
  })
})

describe('buildProxmoxClusterEdges with PDM remotes', () => {
  const pdmHost = (id: string, remote: string) => ({ ...host(id), remote })

  it('chains the hosts of each remote separately', () => {
    const nodes = [pdmHost('a1', 'a'), pdmHost('b1', 'b'), pdmHost('a2', 'a'), pdmHost('b2', 'b'), pdmHost('c1', 'c')]
    expect(buildProxmoxClusterEdges(nodes).map((e) => [e.source, e.target])).toEqual([
      ['a1', 'a2'],
      ['b1', 'b2'],
    ])
  })

  it('ignores PBS servers', () => {
    const pbs = { id: 'pbs', label: 'pbs', type: 'server' as const, ieee_address: 'pbs', status: 'online', remote: 'a' }
    expect(buildProxmoxClusterEdges([pdmHost('a1', 'a'), pbs])).toEqual([])
  })
})
