import { useState } from 'react'
import { Layers, Server, Box, Container, HardDrive, CheckCircle2, XCircle, Loader2, Plus } from 'lucide-react'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { pdmApi, type PdmConnection } from '@/api/client'
import { toast } from 'sonner'
import type { PdmNode, PdmEdge, PdmNodeType } from './types'
import type { ProxmoxCanvasMode } from '@/components/proxmox/types'

interface PdmImportModalProps {
  open: boolean
  onClose: () => void
  onAddToCanvas: (nodes: PdmNode[], edges: PdmEdge[], mode: ProxmoxCanvasMode) => void
  onInventoryImported?: () => void
}

type ImportMode = 'pending' | 'canvas'

const ACCENT = '#e57000'

interface ConnectionForm {
  host: string
  port: string
  token_id: string
  token_secret: string
  verify_tls: boolean
}

const DEFAULT_FORM: ConnectionForm = {
  host: '',
  port: '8443',
  token_id: '',
  token_secret: '',
  verify_tls: true,
}

const DEVICE_TYPE_ICON: Record<PdmNodeType, typeof Server> = {
  proxmox: Server,
  server: HardDrive,
  vm: Box,
  lxc: Container,
}

const DEVICE_TYPE_LABEL: Record<PdmNodeType, string> = {
  proxmox: 'PVE Nodes',
  server: 'Backup Servers',
  vm: 'Virtual Machines',
  lxc: 'LXC Containers',
}

const DEVICE_TYPE_COLOR: Record<PdmNodeType, string> = {
  proxmox: '#e57000',
  server: '#a855f7',
  vm: '#00d4ff',
  lxc: '#39d353',
}

export function PdmImportModal({ open, onClose, onAddToCanvas, onInventoryImported }: PdmImportModalProps) {
  const [form, setForm] = useState<ConnectionForm>(DEFAULT_FORM)
  const [connectionStatus, setConnectionStatus] = useState<'idle' | 'testing' | 'ok' | 'fail'>('idle')
  const [connectionMsg, setConnectionMsg] = useState('')
  const [loading, setLoading] = useState(false)
  const [devices, setDevices] = useState<PdmNode[]>([])
  const [edges, setEdges] = useState<PdmEdge[]>([])
  const [checked, setChecked] = useState<Set<string>>(new Set())
  const [importMode, setImportMode] = useState<ImportMode>('pending')
  // Opt-in: draw each host as a box holding its guests instead of laying them
  // out side by side and joining them with 'virtual' edges.
  const [canvasMode, setCanvasMode] = useState<ProxmoxCanvasMode>('linked')

  const updateField = (field: keyof ConnectionForm, value: string) =>
    setForm((f) => ({ ...f, [field]: value }))

  const buildPayload = (): PdmConnection => ({
    host: form.host.trim(),
    port: Number(form.port) || 8443,
    token_id: form.token_id.trim() || undefined,
    token_secret: form.token_secret || undefined,
    verify_tls: form.verify_tls,
  })

  const extractError = (err: unknown): string | undefined => {
    if (err && typeof err === 'object' && 'response' in err) {
      return (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
    }
    return undefined
  }

  const handleTestConnection = async () => {
    if (!form.host.trim()) { toast.error('Enter a PDM host'); return }
    setConnectionStatus('testing')
    try {
      const res = await pdmApi.testConnection(buildPayload())
      setConnectionStatus(res.data.connected ? 'ok' : 'fail')
      setConnectionMsg(res.data.message)
    } catch (err) {
      setConnectionStatus('fail')
      setConnectionMsg(extractError(err) ?? 'Request failed — check host address')
    }
  }

  const handleFetchDevices = async () => {
    if (!form.host.trim()) { toast.error('Enter a PDM host'); return }
    setLoading(true)
    try {
      if (importMode === 'pending') {
        await pdmApi.importToPending(buildPayload())
        toast.success('PDM import started — track progress in Scan History')
        onInventoryImported?.()
        handleClose()
      } else {
        const res = await pdmApi.importNetwork(buildPayload())
        setDevices(res.data.nodes)
        setEdges(res.data.edges)
        setChecked(new Set(res.data.nodes.map((n) => n.id)))
        if (res.data.notice) toast.warning(res.data.notice)
        if (res.data.device_count === 0) {
          toast.info('No PDM devices found')
        } else {
          toast.success(`Found ${res.data.device_count} device${res.data.device_count !== 1 ? 's' : ''}`)
        }
      }
    } catch (err: unknown) {
      toast.error(extractError(err) ?? 'Failed to fetch PDM inventory')
    } finally {
      setLoading(false)
    }
  }

  const toggleCheck = (id: string) =>
    setChecked((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })

  const toggleAll = () => {
    setChecked(checked.size === devices.length ? new Set() : new Set(devices.map((d) => d.id)))
  }

  const handleAddToCanvas = () => {
    const selectedDevices = devices.filter((d) => checked.has(d.id))
    const selectedIds = new Set(selectedDevices.map((d) => d.id))
    const selectedEdges = edges.filter((e) => selectedIds.has(e.source) && selectedIds.has(e.target))
    onAddToCanvas(selectedDevices, selectedEdges, canvasMode)
    toast.success(`Added ${selectedDevices.length} device${selectedDevices.length !== 1 ? 's' : ''} to canvas`)
    onClose()
  }

  const handleClose = () => {
    setDevices([])
    setEdges([])
    setChecked(new Set())
    setConnectionStatus('idle')
    setConnectionMsg('')
    setImportMode('pending')
    setCanvasMode('linked')
    onClose()
  }

  const groupedDevices: Record<PdmNodeType, PdmNode[]> = {
    proxmox: devices.filter((d) => d.type === 'proxmox'),
    server: devices.filter((d) => d.type === 'server'),
    vm: devices.filter((d) => d.type === 'vm'),
    lxc: devices.filter((d) => d.type === 'lxc'),
  }

  return (
    <Dialog open={open} onOpenChange={(v) => !v && handleClose()}>
      <DialogContent className="bg-popover border-border max-w-2xl max-h-[85vh] flex flex-col">
        <DialogHeader>
          <DialogTitle className="text-foreground flex items-center gap-2">
            <Layers size={16} style={{ color: ACCENT }} />
            Proxmox Datacenter Manager Import
          </DialogTitle>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto space-y-4 py-2 min-h-0">
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-x-4 gap-y-3">
              <div className="col-span-2 space-y-1">
                <Label className="text-xs text-muted-foreground">PDM Host</Label>
                <Input
                  value={form.host}
                  onChange={(e) => updateField('host', e.target.value)}
                  placeholder="192.168.1.x or pdm.local"
                  className="font-mono text-sm bg-background border-border"
                />
              </div>
              <div className="space-y-1">
                <Label className="text-xs text-muted-foreground">Port</Label>
                <Input
                  value={form.port}
                  onChange={(e) => updateField('port', e.target.value)}
                  placeholder="8443"
                  type="number"
                  className="font-mono text-sm bg-background border-border"
                />
              </div>
              <div className="space-y-1">
                <Label className="text-xs text-muted-foreground">Token ID</Label>
                <Input
                  value={form.token_id}
                  onChange={(e) => updateField('token_id', e.target.value)}
                  placeholder="user@pam!tokenname"
                  className="font-mono text-sm bg-background border-border"
                />
              </div>
              <div className="col-span-2 space-y-1">
                <Label className="text-xs text-muted-foreground">Token Secret</Label>
                <Input
                  value={form.token_secret}
                  onChange={(e) => updateField('token_secret', e.target.value)}
                  placeholder="••••••••-••••-••••-••••-••••••••••••"
                  type="password"
                  autoComplete="new-password"
                  className="text-sm bg-background border-border"
                />
              </div>
              <div className="col-span-2 flex flex-wrap items-center gap-x-6 gap-y-2 pt-1">
                <label className="flex items-center gap-1.5 text-xs text-muted-foreground cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form.verify_tls}
                    onChange={(e) => setForm((f) => ({ ...f, verify_tls: e.target.checked }))}
                    className="w-3 h-3 cursor-pointer"
                    style={{ accentColor: ACCENT }}
                  />
                  Verify TLS certificate
                </label>
              </div>
            </div>

            {connectionStatus !== 'idle' && (
              <div className={`flex items-center gap-1.5 text-xs px-2 py-1.5 rounded-md border ${
                connectionStatus === 'ok'
                  ? 'bg-success/10 border-success/30 text-success'
                  : connectionStatus === 'fail'
                  ? 'bg-destructive/10 border-destructive/30 text-destructive'
                  : 'bg-warning/10 border-warning/30 text-warning'
              }`}>
                {connectionStatus === 'testing' && <Loader2 size={12} className="animate-spin" />}
                {connectionStatus === 'ok' && <CheckCircle2 size={12} />}
                {connectionStatus === 'fail' && <XCircle size={12} />}
                <span>{connectionStatus === 'testing' ? 'Testing…' : connectionMsg}</span>
              </div>
            )}

            <div className="space-y-2 rounded-md border border-border bg-background/60 px-3 py-2.5">
              <span className="block text-xs text-muted-foreground">Send devices to</span>
              <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs">
                <label className="flex items-center gap-1.5 cursor-pointer text-foreground">
                  <input
                    type="radio"
                    name="pdm-import-mode"
                    checked={importMode === 'pending'}
                    onChange={() => setImportMode('pending')}
                    className="cursor-pointer"
                    style={{ accentColor: ACCENT }}
                  />
                  Device inventory only
                </label>
                <label className="flex items-center gap-1.5 cursor-pointer text-foreground">
                  <input
                    type="radio"
                    name="pdm-import-mode"
                    checked={importMode === 'canvas'}
                    onChange={() => setImportMode('canvas')}
                    className="cursor-pointer"
                    style={{ accentColor: ACCENT }}
                  />
                  Inventory + canvas
                </label>
              </div>
            </div>
            {importMode === 'canvas' && (
              <label className="flex items-start gap-2 rounded-md border border-border bg-background/60 px-3 py-2.5 text-xs cursor-pointer">
                <input
                  type="checkbox"
                  checked={canvasMode === 'container'}
                  onChange={(e) => setCanvasMode(e.target.checked ? 'container' : 'linked')}
                  className="w-3 h-3 mt-0.5 cursor-pointer shrink-0"
                  style={{ accentColor: ACCENT }}
                />
                <span>
                  <span className="block text-foreground">Nest guests inside their host</span>
                  <span className="block text-[11px] text-muted-foreground">
                    Container mode: each PVE node is drawn as a box holding its VMs and LXCs.
                    Off, they are separate nodes linked by virtual edges.
                  </span>
                </span>
              </label>
            )}
            <div className="flex flex-wrap gap-2 pt-1">
              <Button
                size="sm"
                variant="ghost"
                className="gap-1.5 text-muted-foreground hover:text-foreground border border-border hover:bg-secondary"
                onClick={handleTestConnection}
                disabled={connectionStatus === 'testing' || loading}
              >
                {connectionStatus === 'testing'
                  ? <Loader2 size={13} className="animate-spin" />
                  : <CheckCircle2 size={13} />}
                Test Connection
              </Button>
              <Button
                size="sm"
                style={{ background: ACCENT, color: '#0d1117' }}
                className="gap-1.5"
                onClick={handleFetchDevices}
                disabled={loading || connectionStatus === 'testing'}
              >
                {loading ? <Loader2 size={13} className="animate-spin" /> : <Server size={13} />}
                {importMode === 'pending' ? 'Import to Inventory' : 'Fetch Guests'}
              </Button>
            </div>
            <p className="text-[11px] text-muted-foreground italic">
              Leave the token blank to use the token configured on the server (.env).
              The read-only <span className="font-mono">Auditor</span> role on <span className="font-mono">/resource</span> is enough.
            </p>
          </div>

          {devices.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5">
                  <input
                    type="checkbox"
                    checked={checked.size === devices.length}
                    ref={(el) => { if (el) el.indeterminate = checked.size > 0 && checked.size < devices.length }}
                    onChange={toggleAll}
                    className="w-3 h-3 cursor-pointer"
                    style={{ accentColor: ACCENT }}
                    title="Select all"
                  />
                  <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Devices ({checked.size}/{devices.length} selected)
                  </span>
                </div>
              </div>

              {(Object.entries(groupedDevices) as [PdmNodeType, PdmNode[]][])
                .filter(([, group]) => group.length > 0)
                .map(([type, group]) => {
                  const Icon = DEVICE_TYPE_ICON[type]
                  const color = DEVICE_TYPE_COLOR[type]
                  return (
                    <div key={type}>
                      <div className="flex items-center gap-1.5 mb-1">
                        <Icon size={11} style={{ color }} />
                        <span className="text-[10px] font-medium uppercase tracking-wider" style={{ color }}>
                          {DEVICE_TYPE_LABEL[type]} ({group.length})
                        </span>
                      </div>
                      {group.map((device) => (
                        <div
                          key={device.id}
                          className={`flex items-start gap-2 p-2 mb-1 rounded-md text-xs cursor-pointer transition-colors border ${
                            checked.has(device.id)
                              ? 'bg-secondary border-[#e57000]/40'
                              : 'bg-secondary border-transparent hover:bg-border'
                          }`}
                          onClick={() => toggleCheck(device.id)}
                        >
                          <input
                            type="checkbox"
                            checked={checked.has(device.id)}
                            onChange={() => toggleCheck(device.id)}
                            onClick={(e) => e.stopPropagation()}
                            className="w-3 h-3 mt-0.5 cursor-pointer shrink-0"
                            style={{ accentColor: ACCENT }}
                          />
                          <div className="flex-1 min-w-0">
                            <div className="text-foreground font-medium truncate">{device.label}</div>
                            {device.ip && (
                              <div className="font-mono text-[10px] text-muted-foreground truncate">{device.ip}</div>
                            )}
                            <div className="text-[10px] text-muted-foreground truncate">
                              {[
                                device.cpu_count ? `${device.cpu_count} vCPU` : null,
                                device.ram_gb ? `${device.ram_gb} GB RAM` : null,
                                device.status,
                              ].filter(Boolean).join(' · ')}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )
                })}
            </div>
          )}
        </div>

        <DialogFooter className="gap-2 shrink-0 pt-2 border-t border-border">
          <Button variant="ghost" onClick={handleClose}>Cancel</Button>
          {devices.length > 0 && (
            <Button
              onClick={handleAddToCanvas}
              disabled={checked.size === 0}
              style={{ background: ACCENT, color: '#0d1117' }}
              className="gap-1.5"
            >
              <Plus size={13} />
              Add {checked.size} to Canvas
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
