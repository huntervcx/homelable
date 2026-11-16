import { useState } from 'react'
import { Shield, CheckCircle2, XCircle, Loader2, Download, Network } from 'lucide-react'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { opnsenseApi, type OpnsenseImportModes, type OpnsenseNetwork } from '@/api/client'
import { toast } from 'sonner'

const ACCENT = '#d94f00'

interface OpnsenseImportModalProps {
  open: boolean
  onClose: () => void
  onInventoryImported?: () => void
}

interface ConnectionForm {
  host: string
  port: string
  api_key: string
  api_secret: string
  verify_tls: boolean
}

const DEFAULT_FORM: ConnectionForm = { host: '', port: '443', api_key: '', api_secret: '', verify_tls: false }
const DEFAULT_MODES: OpnsenseImportModes = { clients: true, vpn: true, routes: true }

const SOURCES: { key: keyof OpnsenseImportModes; label: string; hint: string }[] = [
  {
    key: 'clients',
    label: 'LAN hosts',
    hint: 'ARP table, DHCP leases (ISC and Kea) and Unbound host overrides.',
  },
  {
    key: 'vpn',
    label: 'VPN',
    hint: 'WireGuard peers, OpenVPN sessions and IPsec tunnels, linked to the firewall.',
  },
  {
    key: 'routes',
    label: 'Routed networks',
    hint: 'Routes, static routes and VPN allowed IPs — offered as ranges to scan afterwards.',
  },
]

const SOURCE_LABEL: Record<OpnsenseNetwork['source'], string> = {
  route: 'route',
  static: 'static route',
  wireguard: 'WireGuard',
  ipsec: 'IPsec',
}

export function OpnsenseImportModal({ open, onClose, onInventoryImported }: OpnsenseImportModalProps) {
  const [form, setForm] = useState<ConnectionForm>(DEFAULT_FORM)
  const [modes, setModes] = useState<OpnsenseImportModes>(DEFAULT_MODES)
  const [connectionStatus, setConnectionStatus] = useState<'idle' | 'testing' | 'ok' | 'fail'>('idle')
  const [connectionMsg, setConnectionMsg] = useState('')
  const [importing, setImporting] = useState(false)
  const [networks, setNetworks] = useState<OpnsenseNetwork[]>([])
  const [picked, setPicked] = useState<Set<string>>(new Set())
  const [addingRanges, setAddingRanges] = useState(false)

  const updateField = (field: keyof ConnectionForm, value: string) =>
    setForm((f) => ({ ...f, [field]: value }))

  const toggleMode = (key: keyof OpnsenseImportModes) =>
    setModes((m) => ({ ...m, [key]: !m[key] }))

  // Blank fields fall back to the server env, like every other import.
  const buildPayload = () => ({
    host: form.host.trim() || undefined,
    port: Number(form.port) || 443,
    api_key: form.api_key.trim() || undefined,
    api_secret: form.api_secret || undefined,
    verify_tls: form.verify_tls,
    modes,
  })

  const handleClose = () => {
    setForm(DEFAULT_FORM)
    setModes(DEFAULT_MODES)
    setConnectionStatus('idle')
    setConnectionMsg('')
    setNetworks([])
    setPicked(new Set())
    onClose()
  }

  const handleTestConnection = async () => {
    setConnectionStatus('testing')
    try {
      const res = await opnsenseApi.testConnection(buildPayload())
      setConnectionStatus(res.data.connected ? 'ok' : 'fail')
      setConnectionMsg(res.data.message)
    } catch (e) {
      setConnectionStatus('fail')
      setConnectionMsg(e instanceof Error ? e.message : 'Connection failed')
    }
  }

  const handleImport = async () => {
    setImporting(true)
    try {
      const res = await opnsenseApi.importToPending(buildPayload())
      const { device_count, pending_created, pending_updated, links_recorded } = res.data
      toast.success(
        `Imported ${device_count} device(s) — ${pending_created} new, ${pending_updated} updated` +
        (links_recorded ? `, ${links_recorded} VPN link(s)` : ''),
      )
      onInventoryImported?.()
      if (res.data.networks.length > 0) {
        // Stay open: the networks found behind the firewall are the next step.
        setNetworks(res.data.networks)
        setPicked(new Set(res.data.networks.map((n) => n.cidr)))
      } else {
        handleClose()
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'OPNsense import failed')
    } finally {
      setImporting(false)
    }
  }

  const handleAddRanges = async () => {
    if (picked.size === 0) return
    setAddingRanges(true)
    try {
      const res = await opnsenseApi.addScanRanges([...picked])
      toast.success(
        res.data.added.length
          ? `Added ${res.data.added.length} range(s) to the scanner`
          : 'Those ranges were already in the scanner',
      )
      handleClose()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to add scan ranges')
    } finally {
      setAddingRanges(false)
    }
  }

  const togglePicked = (cidr: string) =>
    setPicked((p) => {
      const next = new Set(p)
      if (next.has(cidr)) next.delete(cidr)
      else next.add(cidr)
      return next
    })

  return (
    <Dialog open={open} onOpenChange={(v) => !v && handleClose()}>
      <DialogContent className="bg-popover border-border max-w-2xl max-h-[85vh] flex flex-col">
        <DialogHeader>
          <DialogTitle className="text-foreground flex items-center gap-2">
            <Shield size={16} style={{ color: ACCENT }} />
            OPNsense Import
          </DialogTitle>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto space-y-4 py-2 min-h-0">
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-x-4 gap-y-3">
              <div className="space-y-1">
                <Label className="text-xs text-muted-foreground">Firewall host</Label>
                <Input
                  value={form.host}
                  onChange={(e) => updateField('host', e.target.value)}
                  placeholder="192.168.1.1 or opnsense.lan"
                  className="font-mono text-sm bg-background border-border"
                />
              </div>
              <div className="space-y-1">
                <Label className="text-xs text-muted-foreground">Port</Label>
                <Input
                  value={form.port}
                  onChange={(e) => updateField('port', e.target.value)}
                  placeholder="443"
                  type="number"
                  className="font-mono text-sm bg-background border-border"
                />
              </div>
              <div className="space-y-1">
                <Label className="text-xs text-muted-foreground">API key (optional)</Label>
                <Input
                  value={form.api_key}
                  onChange={(e) => updateField('api_key', e.target.value)}
                  autoComplete="off"
                  className="font-mono text-sm bg-background border-border"
                />
              </div>
              <div className="space-y-1">
                <Label className="text-xs text-muted-foreground">API secret (optional)</Label>
                <Input
                  value={form.api_secret}
                  onChange={(e) => updateField('api_secret', e.target.value)}
                  placeholder="••••••••"
                  type="password"
                  autoComplete="new-password"
                  className="font-mono text-sm bg-background border-border"
                />
              </div>
              <p className="col-span-2 text-[11px] text-muted-foreground/60">
                Create a key under System → Access → Users → API keys. A read-only user is enough:
                the import only reads.
              </p>
              <label className="col-span-2 flex items-center gap-1.5 text-xs text-muted-foreground cursor-pointer">
                <input
                  type="checkbox"
                  checked={form.verify_tls}
                  onChange={(e) => setForm((f) => ({ ...f, verify_tls: e.target.checked }))}
                  className="w-3 h-3 cursor-pointer"
                  style={{ accentColor: ACCENT }}
                />
                Verify TLS certificate
                <span className="text-muted-foreground/50">(off for a self-signed firewall)</span>
              </label>
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
              <span className="block text-xs text-muted-foreground">
                Import the firewall, plus
              </span>
              <div className="space-y-2">
                {SOURCES.map((s) => (
                  <label key={s.key} className="flex items-start gap-2 text-xs cursor-pointer text-foreground">
                    <input
                      type="checkbox"
                      checked={modes[s.key]}
                      onChange={() => toggleMode(s.key)}
                      aria-label={s.label}
                      className="w-3 h-3 mt-0.5 cursor-pointer"
                      style={{ accentColor: ACCENT }}
                    />
                    <span className="min-w-0">
                      {s.label}
                      <span className="block text-muted-foreground/60">{s.hint}</span>
                    </span>
                  </label>
                ))}
              </div>
            </div>

            <div className="flex flex-wrap gap-2 pt-1">
              <Button
                size="sm"
                variant="ghost"
                className="gap-1.5 text-muted-foreground hover:text-foreground border border-border hover:bg-secondary"
                onClick={handleTestConnection}
                disabled={connectionStatus === 'testing' || importing}
              >
                {connectionStatus === 'testing'
                  ? <Loader2 size={13} className="animate-spin" />
                  : <CheckCircle2 size={13} />}
                Test Connection
              </Button>
              <Button
                size="sm"
                style={{ background: ACCENT, color: '#ffffff' }}
                className="gap-1.5"
                onClick={handleImport}
                disabled={importing || connectionStatus === 'testing'}
              >
                {importing ? <Loader2 size={13} className="animate-spin" /> : <Download size={13} />}
                Import to Inventory
              </Button>
            </div>
            <p className="text-[11px] text-muted-foreground italic">
              Leave the fields blank to use the OPNSENSE_* values of the server .env. Everything
              lands in the device inventory as pending, to approve onto a canvas like any other
              discovery.
            </p>

            {networks.length > 0 && (
              <div className="space-y-2 rounded-md border border-border bg-background/60 px-3 py-2.5">
                <span className="flex items-center gap-1.5 text-xs text-foreground">
                  <Network size={12} style={{ color: ACCENT }} />
                  {networks.length} network(s) found behind the firewall
                </span>
                <p className="text-[11px] text-muted-foreground/60">
                  Add the ones you want to the scanner ranges. Nothing is scanned until the next scan.
                </p>
                <div className="space-y-1.5 max-h-40 overflow-y-auto">
                  {networks.map((n) => (
                    <label key={n.cidr} className="flex items-center gap-2 text-xs cursor-pointer text-foreground">
                      <input
                        type="checkbox"
                        checked={picked.has(n.cidr)}
                        onChange={() => togglePicked(n.cidr)}
                        aria-label={n.cidr}
                        className="w-3 h-3 cursor-pointer"
                        style={{ accentColor: ACCENT }}
                      />
                      <code className="font-mono">{n.cidr}</code>
                      <span className="text-muted-foreground/70">
                        {SOURCE_LABEL[n.source]} · {n.via}
                      </span>
                    </label>
                  ))}
                </div>
                <Button
                  size="sm"
                  style={{ background: ACCENT, color: '#ffffff' }}
                  onClick={handleAddRanges}
                  disabled={picked.size === 0 || addingRanges}
                >
                  {addingRanges && <Loader2 size={13} className="animate-spin mr-1.5" />}
                  Add {picked.size} range(s) to the scanner
                </Button>
              </div>
            )}
          </div>
        </div>

        <DialogFooter className="gap-2 shrink-0 pt-2 border-t border-border">
          <Button variant="ghost" onClick={handleClose}>{networks.length > 0 ? 'Done' : 'Cancel'}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
