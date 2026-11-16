import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { PdmImportModal } from '../PdmImportModal'

vi.mock('@/api/client', () => ({
  pdmApi: {
    testConnection: vi.fn(),
    importNetwork: vi.fn(),
    importToPending: vi.fn(),
  },
}))
vi.mock('sonner', async () => (await import('@/test/mocks')).mockSonner())

import { pdmApi } from '@/api/client'
import { toast } from 'sonner'

const defaultProps = {
  open: true,
  onClose: vi.fn(),
  onAddToCanvas: vi.fn(),
  onInventoryImported: vi.fn(),
}

const HOST_PLACEHOLDER = '192.168.1.x or pdm.local'

const sampleNodes = [
  {
    id: 'pdm-lab/node/pve1', label: 'pve1', type: 'proxmox' as const,
    ieee_address: 'pdm-lab/node/pve1', hostname: 'pve1', ip: null, status: 'online',
    cpu_count: 8, ram_gb: 16, disk_gb: null, vendor: 'Proxmox VE', model: null, parent_ieee: null, remote: 'lab',
  },
  {
    id: 'pdm-lab/101', label: 'web', type: 'vm' as const,
    ieee_address: 'pdm-lab/101', hostname: 'web', ip: '10.0.0.5', status: 'online',
    cpu_count: 2, ram_gb: 4, disk_gb: 32, vendor: 'Proxmox VE', model: 'QEMU', parent_ieee: 'pdm-lab/node/pve1', remote: 'lab',
  },
  {
    id: 'pdm-backup/pbs/pbs1', label: 'pbs1', type: 'server' as const,
    ieee_address: 'pdm-backup/pbs/pbs1', hostname: 'pbs1', ip: '10.0.0.9', status: 'online',
    cpu_count: 4, ram_gb: 8, disk_gb: null, vendor: 'Proxmox Backup Server', model: null, parent_ieee: null, remote: 'backup',
  },
]
const sampleEdges = [{ source: 'pdm-lab/node/pve1', target: 'pdm-lab/101' }]

function fillHost() {
  fireEvent.change(screen.getByPlaceholderText(HOST_PLACEHOLDER), { target: { value: 'pdm' } })
}

describe('PdmImportModal', () => {
  beforeEach(() => {
    vi.mocked(pdmApi.testConnection).mockReset()
    vi.mocked(pdmApi.importNetwork).mockReset()
    vi.mocked(pdmApi.importToPending).mockReset()
    vi.mocked(toast.success).mockReset()
    vi.mocked(toast.error).mockReset()
    vi.mocked(toast.info).mockReset()
    vi.mocked(toast.warning).mockReset()
    defaultProps.onClose.mockReset()
    defaultProps.onAddToCanvas.mockReset()
    defaultProps.onInventoryImported.mockReset()
  })

  it('renders nothing when closed', () => {
    const { container } = render(<PdmImportModal {...defaultProps} open={false} />)
    expect(container.querySelector('[role="dialog"]')).toBeNull()
  })

  it('renders token fields with a masked secret and the PDM default port', () => {
    render(<PdmImportModal {...defaultProps} />)
    expect(screen.getByText('Proxmox Datacenter Manager Import')).toBeDefined()
    expect(screen.getByDisplayValue('8443')).toBeDefined()
    expect(document.querySelector('input[type="password"]')).not.toBeNull()
  })

  it('errors when testing without a host', async () => {
    render(<PdmImportModal {...defaultProps} />)
    fireEvent.click(screen.getByRole('button', { name: /test connection/i }))
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Enter a PDM host'))
    expect(pdmApi.testConnection).not.toHaveBeenCalled()
  })

  it('shows the connection message on a successful test', async () => {
    vi.mocked(pdmApi.testConnection).mockResolvedValue({
      data: { connected: true, message: 'Connected to Proxmox Datacenter Manager 1.0.2 — 2 remotes visible' },
    } as never)
    render(<PdmImportModal {...defaultProps} />)
    fillHost()
    fireEvent.click(screen.getByRole('button', { name: /test connection/i }))
    await waitFor(() => expect(screen.getByText(/Connected to Proxmox Datacenter Manager 1\.0\.2/)).toBeDefined())
  })

  it('shows the server detail when the test request fails', async () => {
    vi.mocked(pdmApi.testConnection).mockRejectedValue({ response: { data: { detail: 'Custom PDM hosts require an explicit API token' } } })
    render(<PdmImportModal {...defaultProps} />)
    fillHost()
    fireEvent.click(screen.getByRole('button', { name: /test connection/i }))
    await waitFor(() => expect(screen.getByText('Custom PDM hosts require an explicit API token')).toBeDefined())
  })

  it('imports to pending by default and notifies the parent', async () => {
    vi.mocked(pdmApi.importToPending).mockResolvedValue({
      data: { id: 'run-1', status: 'running', kind: 'pdm', ranges: [], devices_found: 0, started_at: '', finished_at: null, error: null },
    } as never)
    render(<PdmImportModal {...defaultProps} />)
    fillHost()
    fireEvent.click(screen.getByRole('button', { name: /import to inventory/i }))
    await waitFor(() => expect(pdmApi.importToPending).toHaveBeenCalled())
    expect(defaultProps.onInventoryImported).toHaveBeenCalled()
    expect(pdmApi.importNetwork).not.toHaveBeenCalled()
  })

  it('fetches in canvas mode and groups by type, PBS included', async () => {
    vi.mocked(pdmApi.importNetwork).mockResolvedValue({
      data: { nodes: sampleNodes, edges: sampleEdges, device_count: 3 },
    } as never)
    render(<PdmImportModal {...defaultProps} />)
    fireEvent.click(screen.getByRole('radio', { name: /inventory \+ canvas/i }))
    fillHost()
    fireEvent.click(screen.getByRole('button', { name: /fetch guests/i }))
    await waitFor(() => expect(screen.getByText('pve1')).toBeDefined())
    expect(screen.getByText('web')).toBeDefined()
    expect(screen.getByText('pbs1')).toBeDefined()
    expect(screen.getByText(/Backup Servers \(1\)/)).toBeDefined()
    expect(toast.success).toHaveBeenCalledWith('Found 3 devices')
  })

  it('surfaces the import notice as a warning', async () => {
    vi.mocked(pdmApi.importNetwork).mockResolvedValue({
      data: { nodes: sampleNodes, edges: sampleEdges, device_count: 3, notice: 'Some remotes could not be queried' },
    } as never)
    render(<PdmImportModal {...defaultProps} />)
    fireEvent.click(screen.getByRole('radio', { name: /inventory \+ canvas/i }))
    fillHost()
    fireEvent.click(screen.getByRole('button', { name: /fetch guests/i }))
    await waitFor(() => expect(toast.warning).toHaveBeenCalledWith('Some remotes could not be queried'))
  })

  it("adds only the checked devices to the canvas, in 'linked' mode by default", async () => {
    vi.mocked(pdmApi.importNetwork).mockResolvedValue({
      data: { nodes: sampleNodes, edges: sampleEdges, device_count: 3 },
    } as never)
    render(<PdmImportModal {...defaultProps} />)
    fireEvent.click(screen.getByRole('radio', { name: /inventory \+ canvas/i }))
    fillHost()
    fireEvent.click(screen.getByRole('button', { name: /fetch guests/i }))
    await waitFor(() => expect(screen.getByText('pbs1')).toBeDefined())
    fireEvent.click(screen.getByText('pbs1')) // untick the PBS server
    fireEvent.click(screen.getByRole('button', { name: /add 2 to canvas/i }))
    const [nodes, edges, mode] = vi.mocked(defaultProps.onAddToCanvas).mock.calls[0]
    expect(mode).toBe('linked')
    expect(nodes.map((n: { id: string }) => n.id)).toEqual(['pdm-lab/node/pve1', 'pdm-lab/101'])
    expect(edges).toHaveLength(1)
  })

  it("passes 'container' when the nest option is ticked", async () => {
    vi.mocked(pdmApi.importNetwork).mockResolvedValue({
      data: { nodes: sampleNodes, edges: sampleEdges, device_count: 3 },
    } as never)
    render(<PdmImportModal {...defaultProps} />)
    fireEvent.click(screen.getByRole('radio', { name: /inventory \+ canvas/i }))
    fireEvent.click(screen.getByRole('checkbox', { name: /nest guests inside their host/i }))
    fillHost()
    fireEvent.click(screen.getByRole('button', { name: /fetch guests/i }))
    await waitFor(() => expect(screen.getByText('pve1')).toBeDefined())
    fireEvent.click(screen.getByRole('button', { name: /add 3 to canvas/i }))
    expect(vi.mocked(defaultProps.onAddToCanvas).mock.calls[0][2]).toBe('container')
  })

  it('sends the token from the form in the payload', async () => {
    vi.mocked(pdmApi.importNetwork).mockResolvedValue({ data: { nodes: [], edges: [], device_count: 0 } } as never)
    render(<PdmImportModal {...defaultProps} />)
    fireEvent.click(screen.getByRole('radio', { name: /inventory \+ canvas/i }))
    fillHost()
    fireEvent.change(screen.getByPlaceholderText('user@pam!tokenname'), { target: { value: 'root@pam!hl' } })
    fireEvent.click(screen.getByRole('button', { name: /fetch guests/i }))
    await waitFor(() => expect(pdmApi.importNetwork).toHaveBeenCalled())
    const payload = vi.mocked(pdmApi.importNetwork).mock.calls[0][0]
    expect(payload.token_id).toBe('root@pam!hl')
    expect(payload.port).toBe(8443)
    expect(toast.info).toHaveBeenCalledWith('No PDM devices found')
  })

  it('leaves the secret out of the payload when the field is blank', async () => {
    vi.mocked(pdmApi.importNetwork).mockResolvedValue({ data: { nodes: [], edges: [], device_count: 0 } } as never)
    render(<PdmImportModal {...defaultProps} />)
    fireEvent.click(screen.getByRole('radio', { name: /inventory \+ canvas/i }))
    fillHost()
    fireEvent.click(screen.getByRole('button', { name: /fetch guests/i }))
    await waitFor(() => expect(pdmApi.importNetwork).toHaveBeenCalled())
    const payload = vi.mocked(pdmApi.importNetwork).mock.calls[0][0]
    expect(payload.token_secret).toBeUndefined()
    expect(payload.token_id).toBeUndefined()
  })
})
