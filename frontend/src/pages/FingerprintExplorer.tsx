import { useEffect, useState, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { etthApi } from '../lib/api'
import type { FingerprintStats } from '../types/api'
import { LoadingState, ErrorState, EmptyState } from '../components/ui/StatusStates'
import { Card, CardBody } from '../components/ui/Card'
import { Input } from '../components/ui/Input'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { PageHeader } from '../components/ui/PageHeader'
import { Search, Copy, Check, Filter } from 'lucide-react'

export default function FingerprintExplorer() {
  const { type, hash } = useParams<{ type?: string, hash?: string }>()
  const navigate = useNavigate()
  
  const [stats, setStats] = useState<FingerprintStats[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  
  const [searchTerm, setSearchTerm] = useState(hash || '')
  const [copiedFingerprint, setCopiedFingerprint] = useState<string | null>(null)
  const activeTab = (type === 'ja3' || type === 'ja3s' || type === 'ja4') ? type : 'ja4'

  const fetchStats = useCallback(async (fpType: string) => {
    setLoading(true)
    setError(null)
    try {
      const data = await etthApi.fingerprints.getStats(fpType)
      setStats(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load fingerprint stats')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchStats(activeTab)
  }, [activeTab, fetchStats])

  const filteredStats = stats.filter(f => f.hash.toLowerCase().includes(searchTerm.toLowerCase()))

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text)
    setCopiedFingerprint(key)
    setTimeout(() => setCopiedFingerprint(null), 2000)
  }

  const handleTabChange = (newType: string) => {
    setSearchTerm('')
    navigate(`/fingerprints/${newType}`)
  }

  if (error) return <ErrorState message={error} onRetry={() => fetchStats(activeTab)} />

  return (
    <div className="p-6 space-y-6">
      <PageHeader 
        title="Fingerprint Explorer" 
        description="Investigate JA3, JA3S, and JA4 fingerprints as evidence." 
      />

      <div className="flex items-center gap-2">
        <Button
          variant={activeTab === 'ja3' ? 'default' : 'secondary'}
          onClick={() => handleTabChange('ja3')}
        >
          JA3
        </Button>
        <Button
          variant={activeTab === 'ja3s' ? 'default' : 'secondary'}
          onClick={() => handleTabChange('ja3s')}
        >
          JA3S
        </Button>
        <Button
          variant={activeTab === 'ja4' ? 'default' : 'secondary'}
          onClick={() => handleTabChange('ja4')}
        >
          JA4
        </Button>
      </div>

      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-etth-text/40" />
        <Input
          placeholder={`Search ${activeTab.toUpperCase()} fingerprints...`}
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="pl-9 bg-surface-800 border-surface-700"
        />
      </div>

      {loading ? (
        <LoadingState message={`Loading ${activeTab.toUpperCase()} stats...`} />
      ) : (
        <div className="space-y-3">
          {filteredStats.length === 0 ? (
            <EmptyState title={`No ${activeTab.toUpperCase()} fingerprints found`} description="Try adjusting your search terms." />
          ) : (
            filteredStats.map((fp) => (
              <Card key={fp.hash} className="bg-surface-800 border-surface-700">
                <CardBody className="p-4">
                  <div className="flex flex-col md:flex-row items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-2 flex-wrap">
                        <Badge variant="default">{fp.type.toUpperCase()}</Badge>
                        <Badge variant="default">{fp.total_flows} observed flows</Badge>
                        {fp.malicious_flows > 0 && <Badge variant="danger">{fp.malicious_flows} malicious flows</Badge>}
                        {fp.benign_flows > 0 && <Badge variant="info">{fp.benign_flows} benign flows</Badge>}
                      </div>
                      <p className="font-mono text-sm break-all text-etth-text/80">{fp.hash}</p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleCopy(fp.hash, fp.hash)}
                        className="hover:bg-surface-700/50"
                      >
                        {copiedFingerprint === fp.hash ? (
                          <Check className="w-4 h-4 text-success mr-1" />
                        ) : (
                          <Copy className="w-4 h-4 mr-1" />
                        )}
                        {copiedFingerprint === fp.hash ? 'Copied' : 'Copy'}
                      </Button>
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => navigate(`/threat-hunt?${fp.type}=${fp.hash}`)}
                      >
                        <Filter className="w-4 h-4 mr-1" />
                        Filter Flows
                      </Button>
                    </div>
                  </div>
                </CardBody>
              </Card>
            ))
          )}
        </div>
      )}

      <div className="bg-info/10 border border-info/30 rounded-sm p-4">
        <p className="text-sm text-info/80">
          <strong>Evidence Note:</strong> Fingerprints are observable metadata — not inherently malicious. 
          Each fingerprint should be evaluated in context with behavioral patterns and model predictions.
        </p>
      </div>
    </div>
  )
}