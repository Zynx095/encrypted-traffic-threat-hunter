import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { PageHeader } from '../components/ui/PageHeader'
import { SectionHeader } from '../components/ui/SectionHeader'
import { StatGroup } from '../components/ui/StatGroup'
import { Download } from 'lucide-react'
import datasetRegistry from '../data/datasetRegistry'

export default function DatasetExplorer() {
  const { datasetId } = useParams<{ datasetId?: string }>()
  const navigate = useNavigate()
  
  const [filter, setFilter] = useState<'all' | 'active' | 'candidate' | 'rejected'>('all')

  const datasets = datasetRegistry as Array<{
    dataset_id: string
    dataset_name: string
    source: string
    verification_status: string
    planned_role: string
    suitability: string
    notes: string
    [key: string]: string
  }>

  const filteredDatasets = datasetId 
    ? datasets.filter(d => d.dataset_id === datasetId)
    : filter === 'all' 
      ? datasets 
      : datasets.filter(d => {
          if (filter === 'active') return ['VERIFIED', 'VERIFIED_YES'].includes(d.verification_status)
          if (filter === 'candidate') return ['PENDING', 'PARTIALLY_VERIFIED'].includes(d.verification_status)
          if (filter === 'rejected') return d.suitability === 'REJECTED' || d.notes?.includes('Rejected')
          return true
        })

  const getStatusVariant = (status: string) => {
    switch (status) {
      case 'VERIFIED': return 'success'
      case 'PARTIALLY_VERIFIED': return 'warning'
      case 'PENDING': return 'info'
      default: return 'default'
    }
  }

  const getSuitabilityVariant = (suitability: string) => {
    switch (suitability) {
      case 'HIGH': return 'success'
      case 'MEDIUM': return 'warning'
      case 'LOW': return 'danger'
      default: return 'default'
    }
  }

  const stats = [
    { label: "Total Datasets", value: datasets.length, mono: true },
    { label: "Verified", value: datasets.filter(d => d.verification_status === 'VERIFIED').length, mono: true, variant: 'success' as const },
    { label: "Pending", value: datasets.filter(d => d.verification_status === 'PENDING').length, mono: true, variant: 'info' as const },
    { label: "Candidates", value: datasets.filter(d => d.verification_status === 'PARTIALLY_VERIFIED').length, mono: true, variant: 'warning' as const },
  ]

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-8">
      <PageHeader 
        title="Dataset Explorer" 
        description="Research dataset registry and metadata." 
        backTo={datasetId ? { label: "All Datasets", path: "/datasets" } : undefined}
        actions={
          <Button variant="secondary" size="sm">
            <Download className="w-4 h-4 mr-2" />
            Export Registry
          </Button>
        }
      />

      <StatGroup items={stats} columns={4} className="border border-surface-700/50 bg-surface-800/20 p-4 rounded-sm" />

      <div>
        <div className="flex items-center justify-between mb-4">
          <SectionHeader title="Registry" className="mb-0" />
          {!datasetId && (
            <div className="flex items-center gap-2">
              {(['all', 'active', 'candidate', 'rejected'] as const).map((f) => (
                <Button
                  key={f}
                  variant={filter === f ? 'default' : 'secondary'}
                  size="sm"
                  onClick={() => setFilter(f)}
                  className="h-7 text-xs px-2.5"
                >
                  {f.charAt(0).toUpperCase() + f.slice(1)}
                </Button>
              ))}
            </div>
          )}
        </div>

        <div className="border border-surface-700/50 rounded-sm overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-surface-800/50 border-b border-surface-700/50">
              <tr>
                <th className="text-left py-3 px-4 font-medium text-etth-text/60">Dataset ID & Name</th>
                <th className="text-left py-3 px-4 font-medium text-etth-text/60">Source</th>
                <th className="text-left py-3 px-4 font-medium text-etth-text/60">Status</th>
                <th className="text-left py-3 px-4 font-medium text-etth-text/60">Notes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-700/50">
              {filteredDatasets.map((dataset) => (
                <tr 
                  key={dataset.dataset_id}
                  className={`hover:bg-surface-700/20 transition-colors ${!datasetId ? "cursor-pointer" : ""}`}
                  onClick={() => { if (!datasetId) navigate(`/datasets/${dataset.dataset_id}`) }}
                >
                  <td className="py-3 px-4 align-top">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-mono text-xs text-etth-text">{dataset.dataset_id}</span>
                    </div>
                    <div className="font-medium text-etth-text/90">{dataset.dataset_name}</div>
                    {dataset.planned_role && (
                      <div className="text-xs text-etth-text/50 mt-1">Role: {dataset.planned_role}</div>
                    )}
                  </td>
                  <td className="py-3 px-4 align-top text-etth-text/70">{dataset.source}</td>
                  <td className="py-3 px-4 align-top">
                    <div className="flex flex-col gap-1.5 items-start">
                      <Badge variant={getStatusVariant(dataset.verification_status)}>
                        {dataset.verification_status.replace('_', ' ')}
                      </Badge>
                      <Badge variant={getSuitabilityVariant(dataset.suitability)}>
                        {dataset.suitability} Suitability
                      </Badge>
                    </div>
                  </td>
                  <td className="py-3 px-4 align-top text-etth-text/60 text-xs max-w-xs">
                    <p className="line-clamp-3">{dataset.notes}</p>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}