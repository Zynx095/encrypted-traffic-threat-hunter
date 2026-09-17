import React, { useEffect, useState, useCallback } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { etthApi } from '../lib/api'
import type { BehavioralFeature } from '../types/api'
import { LoadingState, ErrorState, EmptyState } from '../components/ui/StatusStates'
import { Table, TableHeader, TableRow, TableHeaderCell, TableBody, TableCell } from '../components/ui/Table'
import { Input } from '../components/ui/Input'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { PageHeader } from '../components/ui/PageHeader'
import { FlowDetailDrawer } from '../components/ui/FlowDetailDrawer'
import { Search, Filter, RefreshCw } from 'lucide-react'

export default function ThreatHunt() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()

  const initialLabel = searchParams.get('label') || ''

  const [searchTerm, setSearchTerm] = useState('')
  const [labelFilter, setLabelFilter] = useState(initialLabel)
  const [currentPage, setCurrentPage] = useState(1)
  const [selectedFlow, setSelectedFlow] = useState<BehavioralFeature | null>(null)

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
    <div className="p-4 lg:p-6 space-y-4 flex flex-col h-[calc(100vh-2.5rem)] overflow-hidden font-sans relative">
      <PageHeader
        title="Threat Hunt Workspace"
        description="Search, query, and investigate reconstructed historical flows and fingerprint records."
        actions={
          <span className="text-xs text-etth-text/50 font-mono">
            {total.toLocaleString()} total flows indexed
          </span>
        }
      />

      {/* Search & Filter Bar */}
      <div className="flex items-center gap-3 shrink-0">
        <form onSubmit={handleSearch} className="flex-1 flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-etth-text/40" />
            <Input
              placeholder="Search by flow ID, source dataset, JA3, JA4..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-9 bg-surface-800 border-surface-700 font-mono text-xs"
            />
          </div>

          <select
            value={labelFilter}
            onChange={(e) => {
              setLabelFilter(e.target.value)
              setSearchParams(e.target.value ? { label: e.target.value } : {})
              setCurrentPage(1)
            }}
            className="bg-surface-800 border border-surface-700 text-xs font-mono rounded-sm px-3 py-2 outline-none focus:border-accent"
          >
            <option value="">All Verdicts</option>
            <option value="MALICIOUS">Malicious</option>
            <option value="BENIGN">Benign</option>
          </select>

          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={() => {
              setSearchTerm('')
              setLabelFilter('')
              setSearchParams({})
              setCurrentPage(1)
            }}
          >
            Clear Filters
          </Button>

          <Button type="button" variant="ghost" size="sm" onClick={fetchData}>
            <RefreshCw className="w-3.5 h-3.5" />
          </Button>
        </form>
      </div>

      {/* Table Container */}
      <div className="flex-1 overflow-hidden flex flex-col min-h-0 bg-surface-800 border border-surface-700 rounded-sm">
        {loading ? (
          <div className="p-8"><LoadingState message="Searching flow records..." /></div>
        ) : error ? (
          <div className="p-8"><ErrorState message={error} onRetry={fetchData} /></div>
        ) : displayedFeatures.length === 0 ? (
          <div className="p-8"><EmptyState title="No Flows Found" description="Adjust your search filters and try again." /></div>
        ) : (
          <div className="flex-1 overflow-auto">
            <Table>
              <TableHeader className="sticky top-0 bg-surface-900 z-10 border-b border-surface-700 text-[10px] font-mono">
                <TableRow>
                  <TableHeaderCell className="w-[110px]">VERDICT</TableHeaderCell>
                  <TableHeaderCell className="w-[180px]">FLOW ID</TableHeaderCell>
                  <TableHeaderCell className="w-[140px]">DATASET / SOURCE</TableHeaderCell>
                  <TableHeaderCell className="w-[80px]">TLS VER</TableHeaderCell>
                  <TableHeaderCell className="w-[160px]">JA3 HASH</TableHeaderCell>
                  <TableHeaderCell className="w-[160px]">JA4 FINGERPRINT</TableHeaderCell>
                  <TableHeaderCell className="w-[90px] text-right">DURATION</TableHeaderCell>
                  <TableHeaderCell className="w-[90px] text-right">PACKETS</TableHeaderCell>
                </TableRow>
              </TableHeader>
              <TableBody className="text-xs font-mono">
                {displayedFeatures.map((feature) => {
                  const isSelected = selectedFlow?.model_safe_index === feature.model_safe_index

                  return (
                    <TableRow
                      key={feature.model_safe_index}
                      onClick={() => setSelectedFlow(feature)}
                      className={`cursor-pointer border-b border-surface-700/40 transition-colors ${
                        isSelected ? 'bg-surface-700/70 text-etth-text font-medium' : 'hover:bg-surface-700/20 text-etth-text/80'
                      }`}
                    >
                      <TableCell>
                        <Badge variant={feature.label === 'MALICIOUS' ? 'danger' : feature.label === 'BENIGN' ? 'success' : 'secondary'}>
                          {feature.label || 'UNKNOWN'}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs font-medium text-etth-text truncate max-w-[180px]">
                        {feature.flow_id || '—'}
                      </TableCell>
                      <TableCell className="text-xs truncate max-w-[140px] text-etth-text/60" title={feature.source_file as string}>
                        {feature.dataset_id || feature.source_file || '—'}
                      </TableCell>
                      <TableCell>{feature.tls_version ? `1.${feature.tls_version}` : '—'}</TableCell>
                      <TableCell className="font-mono text-xs truncate max-w-[160px] text-etth-text/60" title={feature.ja3_hash as string}>
                        {feature.ja3_hash || '—'}
                      </TableCell>
                      <TableCell className="font-mono text-xs truncate max-w-[160px] text-etth-text/60" title={feature.ja4 as string}>
                        {feature.ja4 || '—'}
                      </TableCell>
                      <TableCell className="text-right">{feature.flow_duration?.toFixed(2) || '0.00'}s</TableCell>
                      <TableCell className="text-right">{feature.total_packets || 0}</TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </div>

      {/* Pagination Bar */}
      {totalPages > 1 && !loading && (
        <div className="flex items-center justify-between shrink-0 font-mono text-xs pt-1">
          <p className="text-etth-text/50">
            Showing {(currentPage - 1) * pageSize + 1}–{Math.min(currentPage * pageSize, total)} of {total.toLocaleString()}
          </p>
          <div className="flex items-center gap-2">
            <Button variant="secondary" size="sm" onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage === 1}>
              Previous
            </Button>
            <span className="text-etth-text/60 px-2">{currentPage} / {totalPages}</span>
            <Button variant="secondary" size="sm" onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages}>
              Next
            </Button>
          </div>
        </div>
      )}

      {/* Inline Flow Detail Drawer */}
      {selectedFlow && (
        <FlowDetailDrawer
          flow={selectedFlow}
          onClose={() => setSelectedFlow(null)}
        />
      )}
    </div>
  )
}