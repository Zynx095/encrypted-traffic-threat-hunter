import React from 'react'
import { X, ShieldAlert, ShieldCheck, Copy, Check, ExternalLink, Activity, Target, Lock, Cpu } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import type { ETTHStreamEvent, BehavioralFeature } from '../../types/api'
import { Badge } from './Badge'
import { Button } from './Button'

export interface FlowDetailDrawerProps {
  event?: ETTHStreamEvent | null
  flow?: BehavioralFeature | null
  onClose: () => void
}

export function FlowDetailDrawer({ event, flow, onClose }: FlowDetailDrawerProps) {
  const navigate = useNavigate()
  const [copiedField, setCopiedField] = React.useState<string | null>(null)

  if (!event && !flow) return null

  const handleCopy = (text: string, field: string) => {
    if (!text) return
    navigator.clipboard.writeText(text)
    setCopiedField(field)
    setTimeout(() => setCopiedField(null), 2000)
  }

  // Unified properties extraction
  const isLive = !!event
  const flowId = isLive ? event.flow?.flow_id : flow?.flow_id
  const targetId = isLive ? event.target_id || event.attribution?.target_id : undefined
  const sessionId = isLive ? event.session_id : undefined
  const sourceName = isLive ? event.source : flow?.dataset_id || flow?.source_file

  // Threat & Inference Details
  const prediction = isLive ? event.detection?.prediction : flow?.label
  const threatScore = isLive ? event.detection?.threat_score : undefined
  const track = isLive ? event.detection?.track : undefined
  const skipReason = isLive ? event.detection?.skip_reason : undefined
  const evidenceList = isLive ? event.detection?.evidence : []

  // Target Attribution Details
  const attribution = isLive ? event.attribution : undefined

  // Behavioral Details
  const duration = isLive ? event.flow?.duration : flow?.flow_duration
  const totalBytes = isLive ? event.flow?.total_bytes : flow?.total_bytes
  const totalPackets = isLive ? event.flow?.total_packets : flow?.total_packets

  // TLS Metadata & Fingerprints
  const ja3 = isLive ? event.tls?.ja3_hash : flow?.ja3_hash
  const ja3s = isLive ? event.tls?.ja3s_hash : flow?.ja3s_hash
  const ja4 = isLive ? event.tls?.ja4 : flow?.ja4
  const sni = isLive ? event.tls?.sni_present ? 'Present' : 'Absent' : flow?.sni_present ? 'Present' : 'Absent'
  const alpn = isLive ? event.tls?.alpn : flow?.alpn_value

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-lg bg-surface-800 border-l border-surface-700 shadow-2xl flex flex-col font-sans">
      {/* Header Bar */}
      <div className="px-4 py-3 border-b border-surface-700 flex items-center justify-between bg-surface-900/50 shrink-0">
        <div className="flex items-center gap-2 min-w-0">
          <Activity className="w-4 h-4 text-accent shrink-0" />
          <h2 className="text-xs font-semibold text-etth-text uppercase tracking-wider">Flow Investigation</h2>
          <span className="text-[10px] font-mono text-etth-text/40 truncate max-w-[140px]">{flowId}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Button
            size="sm"
            variant="ghost"
            onClick={() => navigate(`/flows/${flowId}`, { state: { liveEvent: event } })}
            className="text-[11px] h-7 text-etth-text/60 hover:text-etth-text"
          >
            <ExternalLink className="w-3 h-3 mr-1" /> Full Page
          </Button>
          <button
            onClick={onClose}
            className="p-1 rounded-sm text-etth-text/40 hover:text-etth-text hover:bg-surface-700/50 transition-colors"
            aria-label="Close drawer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Drawer Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
        {/* Context Strip */}
        <div className="bg-surface-900 border border-surface-700 rounded-sm p-3 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-mono text-etth-text/40">Verdict & Verdict Status</span>
            {prediction === 'MALICIOUS' ? (
              <Badge variant="danger"><ShieldAlert className="w-3 h-3 mr-1 inline" /> FLAG / MALICIOUS</Badge>
            ) : prediction === 'BENIGN' ? (
              <Badge variant="success"><ShieldCheck className="w-3 h-3 mr-1 inline" /> BENIGN</Badge>
            ) : (
              <Badge variant="secondary">{prediction || 'UNKNOWN'}</Badge>
            )}
          </div>

          <div className="grid grid-cols-2 gap-2 pt-2 border-t border-surface-700/50">
            <div>
              <div className="text-[10px] font-mono text-etth-text/40">Model Track</div>
              <div className="font-mono font-medium text-etth-text/90 mt-0.5">{track || 'Flow Feature Baseline'}</div>
            </div>
            <div>
              <div className="text-[10px] font-mono text-etth-text/40">Model Inference Score</div>
              <div className={`font-mono font-bold mt-0.5 ${threatScore && threatScore >= 0.5 ? 'text-accent' : 'text-etth-text'}`}>
                {threatScore !== undefined ? (threatScore * 100).toFixed(1) + '%' : 'N/A'}
              </div>
            </div>
          </div>

          {skipReason && (
            <div className="text-[10px] font-mono text-warning bg-warning/10 border border-warning/20 p-1.5 rounded-sm">
              Skip Reason: {skipReason}
            </div>
          )}
        </div>

        {/* Target Attribution Section */}
        <div className="border border-surface-700 rounded-sm bg-surface-900/30 p-3 space-y-2">
          <div className="flex items-center gap-1.5 text-etth-text font-medium text-[11px] uppercase tracking-wider">
            <Target className="w-3.5 h-3.5 text-accent" /> Target Attribution
          </div>
          {attribution ? (
            <div className="space-y-2 font-mono text-[11px]">
              <div className="flex justify-between items-center py-1 border-b border-surface-700/40">
                <span className="text-etth-text/40">Status</span>
                <span className={attribution.status === 'ATTRIBUTED' ? 'text-accent font-semibold' : attribution.status === 'PROBABLE' ? 'text-info font-semibold' : 'text-warning font-semibold'}>
                  {attribution.status}
                </span>
              </div>
              <div className="flex justify-between items-center py-1 border-b border-surface-700/40">
                <span className="text-etth-text/40">Confidence Score</span>
                <span className="text-etth-text font-medium">{(attribution.confidence ?? 0).toFixed(2)}</span>
              </div>
              <div className="flex justify-between items-center py-1 border-b border-surface-700/40">
                <span className="text-etth-text/40">Matched Target ID</span>
                <span className="text-etth-text font-medium">{attribution.target_id || 'None'}</span>
              </div>
              {attribution.evidence && attribution.evidence.length > 0 && (
                <div className="pt-1">
                  <div className="text-[10px] text-etth-text/40 mb-1">Attribution Evidence:</div>
                  <div className="space-y-1 bg-surface-900 p-2 rounded-sm border border-surface-700 text-[10px]">
                    {attribution.evidence.map((ev, i) => (
                      <div key={i} className="text-etth-text/70">
                        • <span className="text-accent">{ev.type}</span>: {ev.value} {ev.detail && `(${ev.detail})`}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="text-etth-text/40 font-mono text-[10px]">No target attribution available for this flow.</div>
          )}
        </div>

        {/* Behavioral Metrics */}
        <div className="border border-surface-700 rounded-sm bg-surface-900/30 p-3 space-y-2">
          <div className="flex items-center gap-1.5 text-etth-text font-medium text-[11px] uppercase tracking-wider">
            <Cpu className="w-3.5 h-3.5 text-info" /> Flow Behavior
          </div>
          <div className="grid grid-cols-3 gap-2 font-mono text-center">
            <div className="bg-surface-900 p-2 rounded-sm border border-surface-700">
              <div className="text-[9px] text-etth-text/40">Duration</div>
              <div className="text-etth-text font-semibold mt-0.5">{duration ? `${duration.toFixed(2)}s` : '0.00s'}</div>
            </div>
            <div className="bg-surface-900 p-2 rounded-sm border border-surface-700">
              <div className="text-[9px] text-etth-text/40">Packets</div>
              <div className="text-etth-text font-semibold mt-0.5">{totalPackets?.toLocaleString() || 0}</div>
            </div>
            <div className="bg-surface-900 p-2 rounded-sm border border-surface-700">
              <div className="text-[9px] text-etth-text/40">Total Bytes</div>
              <div className="text-etth-text font-semibold mt-0.5">{totalBytes?.toLocaleString() || 0} B</div>
            </div>
          </div>
        </div>

        {/* TLS Fingerprints & Identifiers */}
        <div className="border border-surface-700 rounded-sm bg-surface-900/30 p-3 space-y-2">
          <div className="flex items-center justify-between text-etth-text font-medium text-[11px] uppercase tracking-wider">
            <span className="flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-warning" /> TLS Intelligence
            </span>
            <span className="text-[10px] text-etth-text/40 font-mono">Zero Decryption</span>
          </div>

          <div className="space-y-2 font-mono text-[11px]">
            {ja3 && (
              <div>
                <div className="flex items-center justify-between text-[10px] text-etth-text/40 mb-0.5">
                  <span>JA3 Fingerprint Hash</span>
                  <button onClick={() => handleCopy(ja3, 'ja3')} className="hover:text-etth-text text-etth-text/40">
                    {copiedField === 'ja3' ? <Check className="w-3 h-3 inline text-success" /> : <Copy className="w-3 h-3 inline" />}
                  </button>
                </div>
                <div className="bg-surface-900 p-1.5 rounded-sm border border-surface-700 text-etth-text break-all text-[10px]">
                  {ja3}
                </div>
              </div>
            )}

            {ja4 && (
              <div>
                <div className="flex items-center justify-between text-[10px] text-etth-text/40 mb-0.5">
                  <span>JA4 Fingerprint</span>
                  <button onClick={() => handleCopy(ja4, 'ja4')} className="hover:text-etth-text text-etth-text/40">
                    {copiedField === 'ja4' ? <Check className="w-3 h-3 inline text-success" /> : <Copy className="w-3 h-3 inline" />}
                  </button>
                </div>
                <div className="bg-surface-900 p-1.5 rounded-sm border border-surface-700 text-etth-text break-all text-[10px]">
                  {ja4}
                </div>
              </div>
            )}

            {ja3s && (
              <div>
                <div className="flex items-center justify-between text-[10px] text-etth-text/40 mb-0.5">
                  <span>JA3S Fingerprint Hash</span>
                  <button onClick={() => handleCopy(ja3s, 'ja3s')} className="hover:text-etth-text text-etth-text/40">
                    {copiedField === 'ja3s' ? <Check className="w-3 h-3 inline text-success" /> : <Copy className="w-3 h-3 inline" />}
                  </button>
                </div>
                <div className="bg-surface-900 p-1.5 rounded-sm border border-surface-700 text-etth-text break-all text-[10px]">
                  {ja3s}
                </div>
              </div>
            )}

            <div className="grid grid-cols-2 gap-2 pt-1">
              <div className="bg-surface-900 p-1.5 rounded-sm border border-surface-700 flex justify-between">
                <span className="text-[10px] text-etth-text/40">SNI Present</span>
                <span className="text-etth-text">{sni}</span>
              </div>
              <div className="bg-surface-900 p-1.5 rounded-sm border border-surface-700 flex justify-between">
                <span className="text-[10px] text-etth-text/40">ALPN Protocol</span>
                <span className="text-etth-text">{alpn || 'None'}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Evidence List */}
        {evidenceList && evidenceList.length > 0 && (
          <div className="border border-surface-700 rounded-sm bg-surface-900/30 p-3 space-y-1.5">
            <div className="text-etth-text font-medium text-[11px] uppercase tracking-wider">Detection Evidence</div>
            <div className="space-y-1 bg-surface-900 p-2 rounded-sm border border-surface-700 font-mono text-[10px] text-etth-text/80">
              {evidenceList.map((item, idx) => (
                <div key={idx} className="flex items-start gap-1.5">
                  <span className="text-accent">•</span>
                  <span>{item}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
