import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { etthApi } from '../lib/api'
import type { BehavioralFeature } from '../types/api'
import { LoadingState, ErrorState, EmptyState } from '../components/ui/StatusStates'
import { Card, CardHeader, CardBody, CardTitle } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../components/ui/Tabs'
import { AlertTriangle, Copy, Check } from 'lucide-react'
import { Button } from '../components/ui/Button'
import { cn } from '../lib/utils'

export default function FlowInvestigation() {
  const { flowId } = useParams<{ flowId: string }>()
  const navigate = useNavigate()
  
  const [flow, setFlow] = useState<BehavioralFeature | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [copiedField, setCopiedField] = useState<string | null>(null)

  useEffect(() => {
    if (flowId) {
      setLoading(true)
      setError(null)
      etthApi.flows.getById(flowId)
        .then(data => setFlow(data))
        .catch(err => setError(err instanceof Error ? err.message : 'Flow not found'))
        .finally(() => setLoading(false))
    }
  }, [flowId])

  const handleCopy = (text: string, field: string) => {
    navigator.clipboard.writeText(text)
    setCopiedField(field)
    setTimeout(() => setCopiedField(null), 2000)
  }

  if (loading) return <LoadingState message="Loading flow data..." />
  if (error) {
    return (
      <div className="p-6">
        <Button variant="ghost" onClick={() => navigate('/threat-hunt')} className="mb-4 hover:bg-transparent">
          ← Back to Threat Hunt
        </Button>
        <EmptyState title="Flow Not Found" description={`Flow with ID "${flowId}" could not be found. ${error}`} onRetry={() => navigate('/threat-hunt')} />
      </div>
    )
  }
  if (!flow) return null

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <Button variant="ghost" onClick={() => navigate('/threat-hunt')} className="mb-2 px-0 hover:bg-transparent">
            ← Back to Threat Hunt
          </Button>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-semibold text-etth-text">Flow Investigation</h1>
            <Button variant="secondary" size="sm" onClick={() => handleCopy(flowId || '', 'flowIdHeader')} className="h-7 text-xs">
              {copiedField === 'flowIdHeader' ? <Check className="w-3 h-3 mr-1" /> : <Copy className="w-3 h-3 mr-1" />}
              Copy ID
            </Button>
          </div>
          <p className="text-sm text-etth-text/50 mt-1 font-mono">{flowId}</p>
        </div>
        <Badge variant={flow.label === 'MALICIOUS' ? 'danger' : flow.label === 'BENIGN' ? 'info' : 'default'}>
          {flow.label || 'UNKNOWN'}
        </Badge>
      </div>

      <Tabs defaultValue="summary" className="space-y-4">
        <TabsList>
          <TabsTrigger value="summary">Summary</TabsTrigger>
          <TabsTrigger value="tls">TLS Intelligence</TabsTrigger>
          <TabsTrigger value="fingerprints">Fingerprints</TabsTrigger>
          <TabsTrigger value="behavior">Behavior</TabsTrigger>
          <TabsTrigger value="provenance">Provenance</TabsTrigger>
        </TabsList>

        <TabsContent value="summary">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="bg-surface-800 border-surface-700">
              <CardHeader>
                <CardTitle>Flow Summary</CardTitle>
              </CardHeader>
              <CardBody className="space-y-0">
                {[
                  { label: "Flow ID", value: flow.flow_id, copy: 'flow_id' },
                  { label: "Dataset", value: flow.dataset_id },
                  { label: "Source File", value: flow.source_file, truncate: true },
                  { label: "Protocol", value: "TCP" },
                  { label: "Duration (s)", value: flow.flow_duration?.toFixed(3) },
                  { label: "Total Packets", value: flow.total_packets },
                  { label: "Total Bytes", value: flow.total_bytes },
                  { label: "Direction", value: `${flow.forward_packets} fwd / ${flow.reverse_packets} rev` }
                ].map(item => (
                  <div key={item.label} className="flex items-center justify-between py-2 border-b border-surface-700/50 last:border-0">
                    <span className="text-sm text-etth-text/60">{item.label}</span>
                    <div className="flex items-center gap-2">
                      <span className={cn('text-sm font-mono', item.truncate && 'max-w-[300px] truncate')}>{item.value ?? 'Not available'}</span>
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
                <CardTitle>TLS Metadata</CardTitle>
              </CardHeader>
              <CardBody className="space-y-0">
                {[
                  { label: "TLS Version", value: flow.tls_version ? `1.${flow.tls_version}` : 'Not available' },
                  { label: "ClientHello", value: flow.clienthello_present ? 'Present' : 'Absent' },
                  { label: "ServerHello", value: flow.serverhello_present ? 'Present' : 'Absent' },
                  { label: "SNI Present", value: flow.sni_present ? 'Yes' : 'No' },
                  { label: "ALPN", value: flow.alpn_value || 'Not available' }
                ].map(item => (
                  <div key={item.label} className="flex items-center justify-between py-2 border-b border-surface-700/50 last:border-0">
                    <span className="text-sm text-etth-text/60">{item.label}</span>
                    <span className="text-sm font-mono">{item.value ?? 'Not available'}</span>
                  </div>
                ))}
              </CardBody>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="tls">
          <Card className="bg-surface-800 border-surface-700">
            <CardHeader>
              <CardTitle>TLS Handshake Details</CardTitle>
            </CardHeader>
            <CardBody>
              <p className="text-sm text-etth-text/50">
                Detailed TLS metadata extraction would be displayed here. Based on the available features:
              </p>
              <div className="mt-4 space-y-0">
                {[
                  { label: "ClientHello Present", value: flow.clienthello_present ? 'Yes' : 'No' },
                  { label: "ServerHello Present", value: flow.serverhello_present ? 'Yes' : 'No' },
                  { label: "SNI", value: flow.sni_present ? 'Present' : 'Not detected' }
                ].map(item => (
                  <div key={item.label} className="flex items-center justify-between py-2 border-b border-surface-700/50 last:border-0">
                    <span className="text-sm text-etth-text/60">{item.label}</span>
                    <span className="text-sm font-mono">{item.value ?? 'Not available'}</span>
                  </div>
                ))}
              </div>
            </CardBody>
          </Card>
        </TabsContent>

        <TabsContent value="fingerprints">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {['ja3', 'ja3s', 'ja4'].map(fp => {
              const hashVal = fp === 'ja3' ? flow.ja3_hash : fp === 'ja3s' ? flow.ja3s_hash : flow.ja4;
              return (
                <Card key={fp} className="bg-surface-800 border-surface-700">
                  <CardHeader>
                    <CardTitle>{fp.toUpperCase()}</CardTitle>
                  </CardHeader>
                  <CardBody>
                    {hashVal ? (
                      <div className="space-y-2">
                        <p className="font-mono text-xs break-all">{hashVal}</p>
                        <div className="flex gap-2">
                          <Button variant="ghost" size="sm" onClick={() => handleCopy(hashVal as string, fp)}>
                            {copiedField === fp ? <Check className="w-3 h-3 mr-1" /> : <Copy className="w-3 h-3 mr-1" />}
                            {copiedField === fp ? 'Copied' : 'Copy'}
                          </Button>
                          <Button variant="secondary" size="sm" onClick={() => navigate(`/fingerprints/${fp}/${hashVal}`)}>
                            Explore
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
                  { label: 'Duration', value: `${(flow.flow_duration as number)?.toFixed(3)}s` },
                  { label: 'Total Packets', value: flow.total_packets?.toString() || '0' },
                  { label: 'Total Bytes', value: flow.total_bytes?.toString() || '0' },
                  { label: 'Pkt/s', value: (flow.packets_per_second as number)?.toFixed(2) || '0.00' },
                  { label: 'B/s', value: (flow.bytes_per_second as number)?.toFixed(2) || '0.00' },
                  { label: 'Fwd Pkts', value: flow.forward_packets?.toString() || '0' },
                  { label: 'Rev Pkts', value: flow.reverse_packets?.toString() || '0' },
                  { label: 'IAT Mean', value: (flow.iat_mean as number)?.toFixed(4) || '0.0000' }
                ].map(stat => (
                  <div key={stat.label} className="bg-surface-700/50 rounded p-3">
                    <p className="text-xs text-etth-text/50 mb-1">{stat.label}</p>
                    <p className="text-sm font-mono text-etth-text">{stat.value}</p>
                  </div>
                ))}
              </div>
            </CardBody>
          </Card>
        </TabsContent>

        <TabsContent value="provenance">
          <Card className="bg-surface-800 border-surface-700">
            <CardHeader>
              <CardTitle>Provenance & Audit</CardTitle>
            </CardHeader>
            <CardBody>
              <div className="space-y-0">
                {[
                  { label: "Flow ID (Hash)", value: flow.flow_id },
                  { label: "Dataset ID", value: flow.dataset_id },
                  { label: "Source File", value: flow.source_file },
                  { label: "Label", value: flow.label }
                ].map(item => (
                  <div key={item.label} className="flex items-center justify-between py-2 border-b border-surface-700/50 last:border-0">
                    <span className="text-sm text-etth-text/60">{item.label}</span>
                    <span className="text-sm font-mono">{item.value ?? 'Not available'}</span>
                  </div>
                ))}
              </div>
              <div className="mt-4 p-3 bg-warning/10 border border-warning/30 rounded">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-warning shrink-0 mt-0.5" />
                  <div>
                    <p className="text-xs font-medium text-warning">Provenance Notice</p>
                    <p className="text-xs text-etth-text/70 mt-1">
                      This information is for audit and reproducibility purposes only. Provenance fields are NOT included in model features.
                    </p>
                  </div>
                </div>
              </div>
            </CardBody>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}