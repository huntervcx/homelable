import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { OpnsenseImportModal } from '../OpnsenseImportModal'

vi.mock('@/api/client', () => ({
  opnsenseApi: {
    testConnection: vi.fn(),
    importToPending: vi.fn(),
    addScanRanges: vi.fn(),
  },
}))
vi.mock('sonner', async () => (await import('@/test/mocks')).mockSonner())

import { opnsenseApi } from '@/api/client'

const base = { device_count: 6, pending_created: 5, pending_updated: 1, links_recorded: 1 }

describe('OpnsenseImportModal', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('imports every source by default and lets blank credentials fall back to the env', async () => {
    vi.mocked(opnsenseApi.importToPending).mockResolvedValue({ data: { ...base, networks: [] } } as never)
    const onClose = vi.fn()
    render(<OpnsenseImportModal open onClose={onClose} />)
    fireEvent.click(screen.getByRole('button', { name: /import to inventory/i }))

    await waitFor(() => expect(opnsenseApi.importToPending).toHaveBeenCalled())
    const payload = vi.mocked(opnsenseApi.importToPending).mock.calls[0][0]
    expect(payload.modes).toEqual({ clients: true, vpn: true, routes: true })
    expect(payload.host).toBeUndefined()
    expect(payload.api_key).toBeUndefined()
    expect(payload.api_secret).toBeUndefined()
    expect(payload.port).toBe(443)
    await waitFor(() => expect(onClose).toHaveBeenCalled())
  })

  it('offers the discovered networks and adds only the picked ones as scan ranges', async () => {
    vi.mocked(opnsenseApi.importToPending).mockResolvedValue({
      data: {
        ...base,
        networks: [
          { cidr: '10.20.0.0/16', via: '192.168.1.254 (lan)', source: 'route' },
          { cidr: '172.16.5.0/24', via: 'WireGuard peer laptop', source: 'wireguard' },
        ],
      },
    } as never)
    vi.mocked(opnsenseApi.addScanRanges).mockResolvedValue({ data: { added: ['10.20.0.0/16'], scanner_ranges: [] } } as never)
    const onClose = vi.fn()
    render(<OpnsenseImportModal open onClose={onClose} />)
    fireEvent.click(screen.getByRole('button', { name: /import to inventory/i }))

    await screen.findByText(/2 network\(s\) found/i)
    expect(onClose).not.toHaveBeenCalled()
    fireEvent.click(screen.getByLabelText('172.16.5.0/24'))
    fireEvent.click(screen.getByRole('button', { name: /add 1 range/i }))

    await waitFor(() => expect(opnsenseApi.addScanRanges).toHaveBeenCalledWith(['10.20.0.0/16']))
  })

  it('shows the failure message when the connection test fails', async () => {
    vi.mocked(opnsenseApi.testConnection).mockResolvedValue({
      data: { connected: false, message: 'Authentication failed — check the API key/secret and its privileges' },
    } as never)
    render(<OpnsenseImportModal open onClose={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: /test connection/i }))
    expect(await screen.findByText(/Authentication failed/)).toBeTruthy()
  })
})
