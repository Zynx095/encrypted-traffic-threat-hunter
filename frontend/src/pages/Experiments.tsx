import { useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useETTHStore } from '../store/etthStore'
import { LoadingState, ErrorState } from '../components/ui/StatusStates'
import { Card, CardHeader, CardBody, CardTitle, CardDescription } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { CHART_COLORS, RECHARTS_TOOLTIP, RECHARTS_GRID, RECHARTS_AXIS, EXPERIMENT_LABELS } from '../lib/constants'

export default function Experiments() {
  const { experimentId } = useParams<{ experimentId?: string }>()
  const navigate = useNavigate()
  
  const { pilotSummary, pilotResults, phase6Audit, fetchPilotData, fetchPhase6Audit, loading, error } = useETTHStore()

  useEffect(() => {
    if (pilotSummary === null) fetchPilotData()
    if (phase6Audit === null) fetchPhase6Audit()
  }, [pilotSummary, phase6Audit, fetchPilotData, fetchPhase6Audit])

  if (loading) return <LoadingState message="Loading experiment data..." />
  if (error) return <ErrorState message={error} />

  const summaries = pilotSummary || []
  const results = pilotResults || []

  const experimentMetrics = summaries.map(s => {
    const expResults = results.filter(r => r.experiment === s.experiment)
    const avgPR = expResults.reduce((sum, r) => sum + r.pr_auc, 0) / Math.max(expResults.length, 1)
    const avgF1 = expResults.reduce((sum, r) => sum + r.f1, 0) / Math.max(expResults.length, 1)
    const avgBalancedAcc = expResults.reduce((sum, r) => sum + r.balanced_accuracy, 0) / Math.max(expResults.length, 1)
    return {
      ...s,
      avg_pr_auc: avgPR,
      avg_f1: avgF1,
      avg_balanced_accuracy: avgBalancedAcc,
      foldCount: expResults.length,
      label: EXPERIMENT_LABELS[s.experiment as keyof typeof EXPERIMENT_LABELS] || s.experiment
    }
  })

  const audit = phase6Audit ?? { dataset_counts: { 'DS-004': 0, 'DS-008': 0 }, experiment_counts: { A: 0, B: 0, C: 0, D: 0, E: 0 } }
  
  const displayedMetrics = experimentId 
    ? experimentMetrics.filter(e => e.experiment === experimentId)
    : experimentMetrics

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          {experimentId && (
            <Button variant="ghost" onClick={() => navigate('/experiments')} className="mb-2 px-0 hover:bg-transparent">
              ← Back to All Experiments
            </Button>
          )}
          <h1 className="text-2xl font-semibold text-etth-text">Experiments</h1>
          <p className="text-sm text-etth-text/50 mt-1">Research experiment configurations and results</p>
        </div>
      </div>

      <div className="bg-warning/10 border border-warning/30 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <span className="text-warning text-sm font-medium">Controlled Pilot — Source-Confounded</span>
        </div>
        <p className="text-xs text-etth-text/70 mt-2">
          Results are from a controlled pilot with extreme class imbalance ({Math.round((audit.dataset_counts?.['DS-008'] || 0) / Math.max(audit.dataset_counts?.['DS-004'] || 1, 1))}:1). 
          Near-perfect PR-AUC scores are expected artifacts. Generalized validation pending independent benign data.
        </p>
      </div>

      <div className={experimentId ? "grid grid-cols-1 gap-6" : "grid grid-cols-1 lg:grid-cols-2 gap-6"}>
        {displayedMetrics.map((exp) => (
          <Card key={exp.experiment} className={`bg-surface-800 border-surface-700 ${!experimentId ? "cursor-pointer hover:border-accent/30 transition-colors" : ""}`} onClick={() => { if (!experimentId) navigate(`/experiments/${exp.experiment}`) }}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>{exp.label}</CardTitle>
                  <CardDescription>{exp.description}</CardDescription>
                </div>
                <Badge variant="default">{exp.samples} samples</Badge>
              </div>
            </CardHeader>
            <CardBody>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-surface-700/50 rounded p-3">
                  <p className="text-xs text-etth-text/50 mb-1">PR-AUC</p>
                  <p className="text-lg font-mono font-semibold text-etth-text">{exp.avg_pr_auc.toFixed(3)}</p>
                  <p className="text-xs text-etth-text/40 mt-1">Primary metric</p>
                </div>
                <div className="bg-surface-700/50 rounded p-3">
                  <p className="text-xs text-etth-text/50 mb-1">F1</p>
                  <p className="text-lg font-mono font-semibold text-etth-text">{exp.avg_f1.toFixed(3)}</p>
                </div>
                <div className="bg-surface-700/50 rounded p-3">
                  <p className="text-xs text-etth-text/50 mb-1">Balanced Acc</p>
                  <p className="text-lg font-mono font-semibold text-etth-text">{exp.avg_balanced_accuracy.toFixed(3)}</p>
                </div>
                <div className="bg-surface-700/50 rounded p-3">
                  <p className="text-xs text-etth-text/50 mb-1">Folds</p>
                  <p className="text-lg font-mono font-semibold text-etth-text">{exp.foldCount}</p>
                </div>
              </div>
              <div className="mt-4 pt-4 border-t border-surface-700">
                <p className="text-xs text-etth-text/50">
                  Features: {exp.features} | Best: {exp.best_model}
                </p>
              </div>
            </CardBody>
          </Card>
        ))}
      </div>

      <Card className="bg-surface-800 border-surface-700">
        <CardHeader>
          <CardTitle>PR-AUC by Experiment & Model</CardTitle>
        </CardHeader>
        <CardBody>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={results}>
              <CartesianGrid {...RECHARTS_GRID} />
              <XAxis dataKey="experiment" stroke={RECHARTS_AXIS.stroke} tick={RECHARTS_AXIS.tick} />
              <YAxis stroke={RECHARTS_AXIS.stroke} tick={RECHARTS_AXIS.tick} />
              <Tooltip {...RECHARTS_TOOLTIP} />
              <Bar dataKey="pr_auc" fill={CHART_COLORS.accent} name="PR-AUC" />
            </BarChart>
          </ResponsiveContainer>
        </CardBody>
      </Card>

      <Card className="bg-surface-800 border-surface-700">
        <CardHeader>
          <CardTitle>Evaluation Context</CardTitle>
        </CardHeader>
        <CardBody className="space-y-3 text-sm text-etth-text/70">
          <p>
            <strong className="text-etth-text">Dataset Sizes:</strong>
          </p>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Experiment A (Flow-only): {audit.experiment_counts?.A || 2068} rows</li>
            <li>Experiment B (JA3-only): {audit.experiment_counts?.B || 160} rows</li>
            <li>Experiment C (JA4-only): {audit.experiment_counts?.C || 160} rows</li>
            <li>Experiment D (JA3+Flow): {audit.experiment_counts?.D || 160} rows</li>
            <li>Experiment E (JA4+Flow): {audit.experiment_counts?.E || 160} rows</li>
          </ul>
          <p className="mt-3">
            <strong className="text-etth-text">Class Imbalance:</strong> The extreme imbalance ({Math.round((audit.dataset_counts?.['DS-008'] || 0) / Math.max(audit.dataset_counts?.['DS-004'] || 1, 1))}:1) means PR-AUC is the most appropriate metric. 
            Accuracy-based metrics would be misleading.
          </p>
          <p>
            <strong className="text-etth-text">Generalization:</strong> Results are validated only on the source-confounded dataset. 
            Independent validation requires additional benign data (currently pending).
          </p>
        </CardBody>
      </Card>
    </div>
  )
}