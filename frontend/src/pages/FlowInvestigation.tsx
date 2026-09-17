import { useEffect, useState } from 'react'
import { useParams, useNavigate, useLocation } from 'react-router-dom'
import { etthApi } from '../lib/api'
import type { BehavioralFeature, ETTHStreamEvent } from '../types/api'
import { LoadingState, ErrorState, EmptyState } from '../components/ui/StatusStates'
import { Card, CardHeader, CardBody, CardTitle } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../components/ui/Tabs'
import { AlertTriangle, Copy, Check, ShieldAlert, Target, ShieldCheck } from 'lucide-react'
import { Button } from '../components/ui/Button'
import { BackButton } from '../components/ui/BackButton'
import { cn } from '../lib/utils'

export default function FlowInvestigation() {
  const { flowId } = useParams<{ flowId: string }>()
  const navigate = useNavigate()
  const location = useLocation()
  
  const liveEvent = location.state?.liveEvent as ETTHStreamEvent | undefined

  const [flow, setFlow] = useState<BehavioralFeature | null>(null)
  const [loading, setLoading] = useState(!liveEvent)
  const [error, setError] = useState<string | null>(null)
  const [copiedField, setCopiedField] = useState<string | null>(null)

  useEffect(() => {
    if (!liveEvent && flowId) {
      setLoading(true)
      setError(null)
      etthApi.flows.getById(flowId)
        .then(data => setFlow(data))
        .catch(err => setError(err instanceof Error ? err.message : 'Flow not found via API. If this was a live capture, the flow may not be saved permanently.'))
        .finally(() => setLoading(false))
    }
  }, [flowId, liveEvent])

  const handleCopy = (text: string, field: string) => {
    if (!text) return
    navigator.clipboard.writeText(text)
    setCopiedField(field)
    setTimeout(() => setCopiedField(null), 2000)
  }

  if (loading) return <LoadingState message="Loading flow data..." />
  if (error && !liveEvent) {
    return (
      <div className="p-6">
        <div className="mb-4"><BackButton label="THREAT HUNT" to="/threat-hunt" /></div>
        <EmptyState title="Flow Not Found" description={error} onRetry={() => navigate('/threat-hunt')} />
      </div>
    )
  }

  // Use liveEvent if available, else use static flow
  const isLive = !!liveEvent
  const displayId = isLive ? liveEvent.flow?.flow_id : flow?.flow_id
  const label = isLive ? liveEvent.detection?.prediction : flow?.label
  const tlsVersion = isLive ? undefined : flow?.tls_version
  const clientHello = isLive ? liveEvent.tls?.clienthello_present : flow?.clienthello_present
  const serverHello = isLive ? liveEvent.tls?.serverhello_present : flow?.serverhello_present
  const sniPresent = isLive ? liveEvent.tls?.sni_present : flow?.sni_present
  const alpn = isLive ? liveEvent.tls?.alpn : flow?.alpn_value
  const ja3Hash = isLive ? liveEvent.tls?.ja3_hash : flow?.ja3_hash
  const ja3sHash = isLive ? liveEvent.tls?.ja3s_hash : flow?.ja3s_hash
  const ja4Hash = isLive ? liveEvent.tls?.ja4 : flow?.ja4
  
  const totalPkts = isLive ? liveEvent.flow?.total_packets : flow?.total_packets
  const totalBytes = isLive ? liveEvent.flow?.total_bytes : flow?.total_bytes
  const fwdPkts = isLive ? undefined : flow?.forward_packets
  const revPkts = isLive ? undefined : flow?.reverse_packets
  const duration = isLive ? liveEvent.flow?.duration : flow?.flow_duration

  const attribution = liveEvent?.attribution

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans">
      <div className="flex items-center justify-between border-b border-surface-700 pb-4">
        <div>
          <div className="mb-2"><BackButton label="INVESTIGATION" to="/threat-hunt" /></div>
          <div className="flex items-center gap-3">
            <h1 className="text-base font-semibold text-etth-text">Flow Investigation</h1>
            <Button variant="secondary" size="sm" onClick={() => handleCopy(displayId || '', 'flowIdHeader')} className="h-6 text-[10px] font-mono">
              {copiedField === 'flowIdHeader' ? <Check className="w-3 h-3 mr-1 text-success" /> : <Copy className="w-3 h-3 mr-1" />}
              Copy ID
            </Button>
          </div>
          <p className="text-xs text-etth-text/50 mt-1 font-mono">{displayId}</p>
        </div>

        
        <div className="flex flex-col items-end gap-2">
          {label === 'MALICIOUS' ? (
            <Badge variant="danger" className="text-sm py-1">
              <ShieldAlert className="w-4 h-4 mr-1" /> MALICIOUS
            </Badge>
          ) : label === 'BENIGN' ? (
            <Badge variant="success" className="text-sm py-1">
              <ShieldCheck className="w-4 h-4 mr-1" /> BENIGN
            </Badge>
          ) : (
            <Badge variant="default" className="text-sm py-1">
              {label || 'UNKNOWN'}
            </Badge>
          )}
          
          {isLive && (
            <div className="flex gap-2">
              <Badge variant="accent">LIVE EVENT</Badge>
              {liveEvent.detection?.track && (
                <Badge variant="secondary">Track: {liveEvent.detection.track}</Badge>
              )}
            </div>
          )}
        </div>
      </div>

      <Tabs defaultValue="summary" className="space-y-4">
        <TabsList>
          <TabsTrigger value="summary">Summary</TabsTrigger>
          <TabsTrigger value="attribution">Attribution</TabsTrigger>
          <TabsTrigger value="tls">TLS Intelligence</TabsTrigger>
          <TabsTrigger value="fingerprints">Fingerprints</TabsTrigger>
          <TabsTrigger value="behavior">Behavior</TabsTrigger>
        </TabsList>

        <TabsContent value="summary">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="bg-surface-800 border-surface-700">
              <CardHeader>
                <CardTitle>Flow Overview</CardTitle>
              </CardHeader>
              <CardBody className="space-y-0">
                {[
                  { label: "Flow ID", value: displayId, copy: 'flow_id' },
                  { label: "Dataset / Source", value: isLive ? liveEvent.source : flow?.dataset_id },
                  { label: "Target Session ID", value: isLive ? liveEvent.session_id : 'N/A' },
                  { label: "Duration (s)", value: duration?.toFixed(3) },
                  { label: "Total Packets", value: totalPkts },
                  { label: "Total Bytes", value: totalBytes },
                  { label: "Direction", value: `${fwdPkts ?? 0} fwd / ${revPkts ?? 0} rev` }
                ].map(item => (
                  <div key={item.label} className="flex items-center justify-between py-2 border-b border-surface-700/50 last:border-0">
                    <span className="text-sm text-etth-text/60">{item.label}</span>
                    <div className="flex items-center gap-2">
                      <span className={cn('text-sm font-mono', item.value && String(item.value).length > 40 && 'max-w-[300px] truncate')}>{item.value ?? 'Not available'}</span>
                      {item.copy && (
                        <button onClick={() => handleCopy(String(item.value), item.copy as string)} className="text-etth-text/40 hover:text-etth-text">
                          <Copy className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </CardBody>
            </Card>

            <Card className="bg-surface-800 border-surface-700">
              <CardHeader>
                <CardTitle>Threat Assessment</CardTitle>
              </CardHeader>
              <CardBody className="space-y-0">
                {isLive ? (
                  <>
                    <div className="flex justify-between py-2 border-b border-surface-700/50">
                      <span className="text-sm text-etth-text/60">Prediction</span>
                      <Badge variant={label === 'MALICIOUS' ? 'danger' : 'success'}>{label}</Badge>
                    </div>
                    <div className="flex justify-between py-2 border-b border-surface-700/50">
                      <span className="text-sm text-etth-text/60">Threat Score</span>
                      <span className={`text-sm font-bold ${liveEvent.detection?.threat_score && liveEvent.detection.threat_score >= 0.5 ? 'text-danger' : 'text-success'}`}>
                        {liveEvent.detection?.threat_score ? `${(liveEvent.detection.threat_score * 100).toFixed(1)}%` : 'N/A'}
                      </span>
                    </div>
                    <div className="flex justify-between py-2 border-b border-surface-700/50">
                      <span className="text-sm text-etth-text/60">Detection Status</span>
                      <span className="text-sm font-mono text-info">{liveEvent.detection?.status}</span>
                    </div>
                    {liveEvent.detection?.skip_reason && (
                      <div className="flex justify-between py-2 border-b border-surface-700/50">
                        <span className="text-sm text-etth-text/60">Skip Reason</span>
                        <span className="text-sm font-mono text-warning">{liveEvent.detection.skip_reason}</span>
                      </div>
                    )}
                    <div className="py-2">
                      <span className="text-sm text-etth-text/60 block mb-1">Evidence</span>
                      {liveEvent.detection?.evidence && liveEvent.detection.evidence.length > 0 ? (
                        <ul className="list-disc list-inside text-sm font-mono text-etth-text/80 space-y-1">
                          {liveEvent.detection.evidence.map((ev, idx) => (
                            <li key={idx}>{ev}</li>
                          ))}
                        </ul>
                      ) : (
                        <span className="text-sm text-etth-text/50">No specific evidence provided.</span>
                      )}
                    </div>
                  </>
                ) : (
                  <div className="text-sm text-etth-text/50 p-4 text-center">
                    Detailed threat assessment is only available for live streamed events. This is a static flow.
                  </div>
                )}
              </CardBody>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="attribution">
          <Card className="bg-surface-800 border-surface-700">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Target className="w-5 h-5 text-accent" />
                Target Attribution
              </CardTitle>
            </CardHeader>
            <CardBody>
              {attribution ? (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="bg-surface-700/30 p-3 rounded-sm border border-surface-600/50">
                      <div className="text-[11px] text-etth-text/50 mb-1">Status</div>
                      <Badge variant={attribution.status === 'ATTRIBUTED' ? 'success' : attribution.status === 'PROBABLE' ? 'info' : 'warning'}>
                        {attribution.status}
                      </Badge>
                    </div>
                    <div className="bg-surface-700/30 p-3 rounded-sm border border-surface-600/50">
                      <div className="text-[11px] text-etth-text/50 mb-1">Confidence Score</div>
                      <div className="text-sm font-mono font-medium">{(attribution.confidence ?? 0).toFixed(2)}</div>
                    </div>
                    <div className="bg-surface-700/30 p-3 rounded-sm border border-surface-600/50 col-span-2">
                      <div className="text-[11px] text-etth-text/50 mb-1">Matched Target</div>
                      <div className="text-sm font-medium">{attribution.target_id || 'None'}</div>
                    </div>
                  </div>
                  
                  <div className="mt-4">
                    <h4 className="text-sm font-medium mb-2">Attribution Evidence</h4>
                    {attribution.evidence && attribution.evidence.length > 0 ? (
                      <ul className="list-disc list-inside text-sm font-mono text-etth-text/80 space-y-1 bg-surface-900 p-3 rounded-sm border border-surface-700">
                        {attribution.evidence.map((ev, idx) => (
                          <li key={idx}>{ev.type}: {ev.value} {ev.detail ? `(${ev.detail})` : ''}</li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-sm text-etth-text/50">No attribution evidence.</p>
                    )}
                  </div>
                </div>
              ) : (
                <EmptyState title="No Attribution Data" description="This flow was not processed by the target attribution engine." />
              )}
            </CardBody>
          </Card>
        </TabsContent>

        <TabsContent value="tls">
          <Card className="bg-surface-800 border-surface-700">
            <CardHeader>
              <CardTitle>TLS Metadata & Handshake Details</CardTitle>
            </CardHeader>
            <CardBody>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-0">
                  {[
                    { label: "TLS Version", value: tlsVersion ? `1.${tlsVersion}` : 'Not available' },
                    { label: "ClientHello", value: clientHello ? 'Present' : 'Absent' },
                    { label: "ServerHello", value: serverHello ? 'Present' : 'Absent' },
                    { label: "SNI Present", value: sniPresent ? 'Yes' : 'No' },
                    { label: "ALPN", value: alpn || 'Not available' }
                  ].map(item => (
                    <div key={item.label} className="flex items-center justify-between py-2 border-b border-surface-700/50 last:border-0">
                      <span className="text-sm text-etth-text/60">{item.label}</span>
                      <span className="text-sm font-mono">{item.value ?? 'Not available'}</span>
                    </div>
                  ))}
                </div>
                <div className="bg-surface-900 p-4 rounded-sm border border-surface-700">
                  <h4 className="text-[11px] font-medium text-etth-text/50 uppercase mb-2">Cipher Suite Observation</h4>
                  <p className="text-xs text-etth-text/70 mb-4">Detailed cipher suite arrays and extensions are hashed into the JA3/JA4 fingerprints. We do not retain the raw array in production memory to minimize overhead.</p>
                  <Button variant="outline" size="sm" onClick={() => navigate('/tls-intelligence')}>
                    View Global TLS Intelligence
                  </Button>
                </div>
              </div>
            </CardBody>
          </Card>
        </TabsContent>

        <TabsContent value="fingerprints">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {['ja3', 'ja3s', 'ja4'].map(fp => {
              const hashVal = fp === 'ja3' ? ja3Hash : fp === 'ja3s' ? ja3sHash : ja4Hash;
              return (
                <Card key={fp} className="bg-surface-800 border-surface-700">
                  <CardHeader>
                    <CardTitle>{fp.toUpperCase()}</CardTitle>
                  </CardHeader>
                  <CardBody>
                    {hashVal ? (
                      <div className="space-y-2">
                        <p className="font-mono text-xs break-all text-etth-text/90">{hashVal}</p>
                        <div className="flex gap-2 mt-4">
                          <Button variant="outline" size="sm" onClick={() => handleCopy(hashVal as string, fp)} className="h-8 text-xs">
                            {copiedField === fp ? <Check className="w-3 h-3 mr-1" /> : <Copy className="w-3 h-3 mr-1" />}
                            {copiedField === fp ? 'Copied' : 'Copy'}
                          </Button>
                          <Button variant="secondary" size="sm" onClick={() => navigate(`/fingerprints/${fp}/${hashVal}`)} className="h-8 text-xs">
                            Explore Fingerprint
                          </Button>
                        </div>
                      </div>
                    ) : (
                      <p className="text-sm text-etth-text/50">Not available</p>
                    )}
                  </CardBody>
                </Card>
              )
            })}
          </div>
        </TabsContent>

        <TabsContent value="behavior">
          <Card className="bg-surface-800 border-surface-700">
            <CardHeader>
              <CardTitle>Behavioral Statistics</CardTitle>
            </CardHeader>
            <CardBody>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {[
                  { label: 'Duration', value: `${(duration as number)?.toFixed(3)}s` },
                  { label: 'Total Packets', value: totalPkts?.toString() || '0' },
                  { label: 'Total Bytes', value: totalBytes?.toString() || '0' },
                  { label: 'Fwd Pkts', value: fwdPkts?.toString() || '0' },
                  { label: 'Rev Pkts', value: revPkts?.toString() || '0' }
                ].map(stat => (
                  <div key={stat.label} className="bg-surface-700/50 rounded-sm p-3 border border-surface-600/30">
                    <p className="text-[11px] text-etth-text/50 mb-1 uppercase tracking-wider">{stat.label}</p>
                    <p className="text-sm font-mono text-etth-text">{stat.value}</p>
                  </div>
                ))}
              </div>
            </CardBody>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}