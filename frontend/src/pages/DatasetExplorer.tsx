import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Card, CardHeader, CardBody, CardTitle } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
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

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'VERIFIED': return 'success'
      case 'PARTIALLY_VERIFIED': return 'warning'
      case 'PENDING': return 'info'
      default: return 'default'
    }
  }

  const getSuitabilityColor = (suitability: string) => {
    switch (suitability) {
      case 'HIGH': return 'success'
      case 'MEDIUM': return 'warning'
      case 'LOW': return 'danger'
      default: return 'default'
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          {datasetId && (
            <Button variant="ghost" onClick={() => navigate('/datasets')} className="mb-2 px-0 hover:bg-transparent">
              ← Back to All Datasets
            </Button>
          )}
          <h1 className="text-2xl font-semibold text-etth-text">Dataset Explorer</h1>
          <p className="text-sm text-etth-text/50 mt-1">Research dataset registry and metadata</p>
        </div>
        <Button variant="secondary" size="sm">
          <Download className="w-4 h-4 mr-2" />
          Export Registry
        </Button>
      </div>

      {!datasetId && (
        <div className="flex items-center gap-2">
          {(['all', 'active', 'candidate', 'rejected'] as const).map((f) => (
            <Button
              key={f}
              variant={filter === f ? 'default' : 'secondary'}
              size="sm"
              onClick={() => setFilter(f)}
            >
              {f.charAt(0).toUpperCase() + f.slice(1)}
            </Button>
          ))}
        </div>
      )}

      <div className="space-y-4">
        {filteredDatasets.map((dataset) => (
          <Card 
            key={dataset.dataset_id} 
            className={!datasetId ? "cursor-pointer bg-surface-800 border-surface-700 hover:border-accent/30 transition-colors" : "bg-surface-800 border-surface-700"} 
            onClick={() => { if (!datasetId) navigate(`/datasets/${dataset.dataset_id}`) }}
          >
            <CardBody className="p-4">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="font-mono text-sm text-etth-text">{dataset.dataset_id}</span>
                    <span className="text-sm font-medium text-etth-text">{dataset.dataset_name}</span>
                  </div>
                  <p className="text-xs text-etth-text/50 mb-3">{dataset.source}</p>
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge variant={getStatusColor(dataset.verification_status)}>
                      {dataset.verification_status.replace('_', ' ')}
                    </Badge>
                    <Badge variant={getSuitabilityColor(dataset.suitability)}>
                      {dataset.suitability}
                    </Badge>
                    {dataset.planned_role && (
                      <Badge variant="default">{dataset.planned_role}</Badge>
                    )}
                  </div>
                </div>
                <div className="text-right text-xs text-etth-text/50 max-w-xs">
                  <p className="line-clamp-3">{dataset.notes}</p>
                </div>
              </div>
            </CardBody>
          </Card>
        ))}
      </div>

      <Card className="bg-surface-800 border-surface-700">
        <CardHeader>
          <CardTitle>Registry Summary</CardTitle>
        </CardHeader>
        <CardBody>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-surface-700/50 rounded p-3 text-center">
              <p className="text-2xl font-semibold text-etth-text">{datasets.length}</p>
              <p className="text-xs text-etth-text/50 mt-1">Total Datasets</p>
            </div>
            <div className="bg-surface-700/50 rounded p-3 text-center">
              <p className="text-2xl font-semibold text-etth-text">{datasets.filter(d => d.verification_status === 'VERIFIED').length}</p>
              <p className="text-xs text-etth-text/50 mt-1">Verified</p>
            </div>
            <div className="bg-surface-700/50 rounded p-3 text-center">
              <p className="text-2xl font-semibold text-etth-text">{datasets.filter(d => d.verification_status === 'PENDING').length}</p>
              <p className="text-xs text-etth-text/50 mt-1">Pending</p>
            </div>
            <div className="bg-surface-700/50 rounded p-3 text-center">
              <p className="text-2xl font-semibold text-etth-text">{datasets.filter(d => d.verification_status === 'PARTIALLY_VERIFIED').length}</p>
              <p className="text-xs text-etth-text/50 mt-1">Candidates</p>
            </div>
          </div>
        </CardBody>
      </Card>
    </div>
  )
}