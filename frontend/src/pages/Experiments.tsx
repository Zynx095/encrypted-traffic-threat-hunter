import { useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useETTHStore } from '../store/etthStore'
import { LoadingState, ErrorState } from '../components/ui/StatusStates'
import { Badge } from '../components/ui/Badge'
import { PageHeader } from '../components/ui/PageHeader'
import { SectionHeader } from '../components/ui/SectionHeader'
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
    <div className="p-6 max-w-7xl mx-auto space-y-8">
      <PageHeader 
        title="Experiments" 
        description="Research experiment configurations and results." 
        backTo={experimentId ? { label: "All Experiments", path: "/experiments" } : undefined}
      />

      <div className="border-l-2 border-warning/50 bg-warning/5 px-4 py-3 text-sm text-etth-text/80">
        <span className="font-medium text-warning mr-2">Controlled Pilot — Source-Confounded:</span>
        Results are from a controlled pilot with extreme class imbalance ({Math.round((audit.dataset_counts?.['DS-008'] || 0) / Math.max(audit.dataset_counts?.['DS-004'] || 1, 1))}:1). 
        Near-perfect PR-AUC scores are expected artifacts. Generalized validation pending independent benign data.
      </div>

      <div>
        <SectionHeader title="Experiment Results" description="Aggregated metrics across folds." />
        <div className="mt-4 border border-surface-700/50 rounded-sm overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-surface-800/50 border-b border-surface-700/50">
              <tr>
                <th className="text-left py-3 px-4 font-medium text-etth-text/60">Experiment</th>
                <th className="text-left py-3 px-4 font-medium text-etth-text/60">Description</th>
                <th className="text-right py-3 px-4 font-medium text-etth-text/60">Samples</th>
                <th className="text-right py-3 px-4 font-medium text-etth-text/60">PR-AUC</th>
                <th className="text-right py-3 px-4 font-medium text-etth-text/60">F1</th>
                <th className="text-right py-3 px-4 font-medium text-etth-text/60">Bal. Acc</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-700/50">
              {displayedMetrics.map((exp) => (
                <tr 
                  key={exp.experiment} 
                  className={`hover:bg-surface-700/20 transition-colors ${!experimentId ? "cursor-pointer" : ""}`}
                  onClick={() => { if (!experimentId) navigate(`/experiments/${exp.experiment}`) }}
                >
                  <td className="py-3 px-4">
                    <div className="font-medium text-etth-text">{exp.label}</div>
                    <div className="text-xs text-etth-text/50 font-mono mt-0.5">Features: {exp.features}</div>
                  </td>
                  <td className="py-3 px-4 text-etth-text/70">{exp.description}</td>
                  <td className="py-3 px-4 text-right">
                    <Badge variant="default">{exp.samples}</Badge>
                  </td>
                  <td className="py-3 px-4 text-right font-mono text-accent">{exp.avg_pr_auc.toFixed(3)}</td>
                  <td className="py-3 px-4 text-right font-mono text-etth-text/80">{exp.avg_f1.toFixed(3)}</td>
                  <td className="py-3 px-4 text-right font-mono text-etth-text/80">{exp.avg_balanced_accuracy.toFixed(3)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div>
          <SectionHeader title="PR-AUC by Experiment & Model" />
          <div className="mt-4 border border-surface-700/50 p-4 rounded-sm bg-surface-800/20">
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={results}>
                <CartesianGrid {...RECHARTS_GRID} />
                <XAxis dataKey="experiment" stroke={RECHARTS_AXIS.stroke} tick={RECHARTS_AXIS.tick} />
                <YAxis stroke={RECHARTS_AXIS.stroke} tick={RECHARTS_AXIS.tick} />
                <Tooltip {...RECHARTS_TOOLTIP} />
                <Bar dataKey="pr_auc" fill={CHART_COLORS.accent} name="PR-AUC" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        
        <div>
          <SectionHeader title="Evaluation Context" />
          <div className="mt-4 border border-surface-700/50 p-5 rounded-sm bg-surface-800/20 space-y-4 text-sm text-etth-text/70">
            <div>
              <span className="font-medium text-etth-text">Dataset Sizes:</span>
              <ul className="list-disc list-inside mt-2 space-y-1 ml-1">
                <li>Experiment A (Flow-only): {audit.experiment_counts?.A || 2068} rows</li>
                <li>Experiment B (JA3-only): {audit.experiment_counts?.B || 160} rows</li>
                <li>Experiment C (JA4-only): {audit.experiment_counts?.C || 160} rows</li>
                <li>Experiment D (JA3+Flow): {audit.experiment_counts?.D || 160} rows</li>
                <li>Experiment E (JA4+Flow): {audit.experiment_counts?.E || 160} rows</li>
              </ul>
            </div>
            <div>
              <span className="font-medium text-etth-text">Class Imbalance:</span> The extreme imbalance ({Math.round((audit.dataset_counts?.['DS-008'] || 0) / Math.max(audit.dataset_counts?.['DS-004'] || 1, 1))}:1) means PR-AUC is the most appropriate metric. 
              Accuracy-based metrics would be misleading.
            </div>
            <div>
              <span className="font-medium text-etth-text">Generalization:</span> Results are validated only on the source-confounded dataset. 
              Independent validation requires additional benign data (currently pending).
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}