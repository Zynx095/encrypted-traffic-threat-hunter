import { useEffect, useState, useCallback } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { etthApi } from '../lib/api'
import type { BehavioralFeature } from '../types/api'
import { LoadingState, ErrorState, EmptyState } from '../components/ui/StatusStates'
import { Table, TableHeader, TableRow, TableHeaderCell, TableBody, TableCell } from '../components/ui/Table'
import { Input } from '../components/ui/Input'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { Search } from 'lucide-react'

export default function ThreatHunt() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  
  const initialLabel = searchParams.get('label') || ''
  
  const [searchTerm, setSearchTerm] = useState('')
  const [labelFilter, setLabelFilter] = useState(initialLabel)
  const [currentPage, setCurrentPage] = useState(1)
  
  const [features, setFeatures] = useState<BehavioralFeature[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  
  const pageSize = 50

  const fetchData = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const query: Record<string, any> = {
        limit: pageSize,
        offset: (currentPage - 1) * pageSize
      }
      if (labelFilter) query.label = labelFilter
      
      const result = await etthApi.flows.search(query)
      
      setFeatures(result.features)
      setTotal(result.total)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load flows')
    } finally {
      setLoading(false)
    }
  }, [currentPage, labelFilter, pageSize])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
  }

  const handleRowClick = (flowId: string) => {
    navigate(`/flows/${flowId}`)
  }

  const totalPages = Math.ceil(total / pageSize)

  const displayedFeatures = searchTerm 
    ? features.filter(f => 
        f.flow_id?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.source_file?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.ja3_hash?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.ja4?.toLowerCase().includes(searchTerm.toLowerCase())
      )
    : features

  return (
    <div className="p-6 space-y-6 flex flex-col h-[calc(100vh-64px)] overflow-hidden">
      <div className="flex items-center justify-between shrink-0">
        <div>
          <h1 className="text-2xl font-semibold text-etth-text">Threat Hunt</h1>
          <p className="text-sm text-etth-text/50 mt-1">Search and filter reconstructed flows</p>
        </div>
        <div className="flex items-center gap-2 text-sm text-etth-text/50">
          <span>Total: {total.toLocaleString()} flows</span>
        </div>
      </div>

      <div className="flex items-center gap-4 shrink-0">
        <form onSubmit={handleSearch} className="flex-1 max-w-2xl flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-etth-text/40" />
            <Input
              placeholder="Search page by label, JA3, JA4..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-9 bg-surface-800 border-surface-700"
            />
          </div>
          <select 
            value={labelFilter}
            onChange={(e) => {
              setLabelFilter(e.target.value)
              setSearchParams(e.target.value ? { label: e.target.value } : {})
              setCurrentPage(1)
            }}
            className="bg-surface-800 border border-surface-700 text-sm rounded-md px-3 outline-none focus:border-accent"
          >
            <option value="">All Labels</option>
            <option value="MALICIOUS">Malicious</option>
            <option value="BENIGN">Benign</option>
          </select>
          <Button type="button" variant="secondary" onClick={() => {
            setSearchTerm('')
            setLabelFilter('')
            setSearchParams({})
            setCurrentPage(1)
          }}>
            Clear Filters
          </Button>
        </form>
      </div>

      <div className="flex-1 overflow-hidden flex flex-col min-h-0 bg-surface-800 border border-surface-700 rounded-lg">
        {loading ? (
          <div className="p-8"><LoadingState message="Searching flows..." /></div>
        ) : error ? (
          <div className="p-8"><ErrorState message={error} onRetry={fetchData} /></div>
        ) : displayedFeatures.length === 0 ? (
          <div className="p-8"><EmptyState title="No flows found" description="Adjust your filters and try again." /></div>
        ) : (
          <div className="flex-1 overflow-auto">
            <Table>
              <TableHeader className="sticky top-0 bg-surface-800 z-10 border-b border-surface-700">
                <TableRow>
                  <TableHeaderCell className="w-[100px]">Label</TableHeaderCell>
                  <TableHeaderCell className="w-[120px]">Dataset</TableHeaderCell>
                  <TableHeaderCell className="w-[200px]">Source File</TableHeaderCell>
                  <TableHeaderCell className="w-[80px]">TLS Ver</TableHeaderCell>
                  <TableHeaderCell className="w-[150px]">JA3</TableHeaderCell>
                  <TableHeaderCell className="w-[150px]">JA4</TableHeaderCell>
                  <TableHeaderCell className="w-[100px]">Duration</TableHeaderCell>
                  <TableHeaderCell className="w-[100px]">Packets</TableHeaderCell>
                </TableRow>
              </TableHeader>
              <TableBody>
                {displayedFeatures.map((feature) => (
                  <TableRow
                    key={feature.model_safe_index}
                    onClick={() => handleRowClick(feature.flow_id as string)}
                    className="cursor-pointer hover:bg-surface-700/20 border-b border-surface-700/50 transition-colors"
                  >
                    <TableCell>
                      <Badge variant={feature.label === 'MALICIOUS' ? 'danger' : feature.label === 'BENIGN' ? 'info' : 'default'}>
                        {feature.label || 'UNKNOWN'}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{feature.dataset_id || 'Not available'}</TableCell>
                    <TableCell className="text-xs truncate max-w-[200px]" title={feature.source_file as string}>
                      {feature.source_file || 'Not available'}
                    </TableCell>
                    <TableCell>{feature.tls_version || '—'}</TableCell>
                    <TableCell className="font-mono text-xs truncate max-w-[150px]" title={feature.ja3_hash as string}>
                      {feature.ja3_hash ? feature.ja3_hash.slice(0, 12) + '...' : '—'}
                    </TableCell>
                    <TableCell className="font-mono text-xs truncate max-w-[150px]" title={feature.ja4 as string}>
                      {feature.ja4 ? feature.ja4.slice(0, 12) + '...' : '—'}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{feature.flow_duration?.toFixed(2) || '0.00'}</TableCell>
                    <TableCell className="text-xs">{feature.total_packets || 0}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>

      {totalPages > 1 && !loading && (
        <div className="flex items-center justify-between shrink-0">
          <p className="text-sm text-etth-text/50">
            Showing {(currentPage - 1) * pageSize + 1} to {Math.min(currentPage * pageSize, total)} of {total}
          </p>
          <div className="flex items-center gap-2">
            <Button variant="secondary" size="sm" onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage === 1}>
              Previous
            </Button>
            <span className="text-sm text-etth-text/50 px-2">{currentPage} / {totalPages}</span>
            <Button variant="secondary" size="sm" onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages}>
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}