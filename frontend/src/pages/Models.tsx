import { useEffect } from 'react'
import { useETTHStore } from '../store/etthStore'
import { LoadingState, ErrorState } from '../components/ui/StatusStates'
import { PageHeader } from '../components/ui/PageHeader'
import { SectionHeader } from '../components/ui/SectionHeader'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import { CHART_COLORS, RECHARTS_TOOLTIP, RECHARTS_GRID, RECHARTS_AXIS } from '../lib/constants'

export default function Models() {
  const { pilotResults, fetchPilotData, loading, error } = useETTHStore()

  useEffect(() => {
    if (pilotResults === null) {
      fetchPilotData()
    }
  }, [pilotResults, fetchPilotData])

  if (loading) return <LoadingState message="Loading model data..." />
  if (error) return <ErrorState message={error} />

  const results = pilotResults || []

  // Aggregate by model
  const modelMetrics = ['LogisticRegression', 'RandomForest', 'XGBoost'].map(model => {
    const modelResults = results.filter(r => r.model === model)
    if (modelResults.length === 0) return null
    return {
      model,
      avg_precision: modelResults.reduce((sum, r) => sum + r.precision, 0) / modelResults.length,
      avg_recall: modelResults.reduce((sum, r) => sum + r.recall, 0) / modelResults.length,
      avg_f1: modelResults.reduce((sum, r) => sum + r.f1, 0) / modelResults.length,
      avg_pr_auc: modelResults.reduce((sum, r) => sum + r.pr_auc, 0) / modelResults.length,
      avg_balanced_accuracy: modelResults.reduce((sum, r) => sum + r.balanced_accuracy, 0) / modelResults.length,
    }
  }).filter(Boolean) as Array<{ model: string; avg_precision: number; avg_recall: number; avg_f1: number; avg_pr_auc: number; avg_balanced_accuracy: number }>

  const chartData = modelMetrics.map(m => ({
    name: m.model === 'LogisticRegression' ? 'LR' : m.model === 'RandomForest' ? 'RF' : 'XGB',
    Precision: m.avg_precision,
    Recall: m.avg_recall,
    F1: m.avg_f1,
    'PR-AUC': m.avg_pr_auc,
    'BalAcc': m.avg_balanced_accuracy,
  }))

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-8">
      <PageHeader 
        title="Model Analysis" 
        description="Model comparison and performance analysis." 
      />

      <div className="border-l-2 border-warning/50 bg-warning/5 px-4 py-3 text-sm text-etth-text/80">
        <span className="font-medium text-warning mr-2">Note:</span>
        Model metrics are from a controlled pilot with extreme class imbalance. 
        Results demonstrate pipeline functionality, not production-grade performance.
      </div>

      <div>
        <SectionHeader title="Model Performance Summary" />
        <div className="mt-4 border border-surface-700/50 rounded-sm overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-surface-800/50 border-b border-surface-700/50">
              <tr>
                <th className="text-left py-3 px-4 font-medium text-etth-text/60">Model</th>
                <th className="text-right py-3 px-4 font-medium text-etth-text/60">Precision</th>
                <th className="text-right py-3 px-4 font-medium text-etth-text/60">Recall</th>
                <th className="text-right py-3 px-4 font-medium text-etth-text/60">F1</th>
                <th className="text-right py-3 px-4 font-medium text-etth-text/60">PR-AUC</th>
                <th className="text-right py-3 px-4 font-medium text-etth-text/60">Balanced Acc</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-700/50">
              {modelMetrics.map((m) => (
                <tr key={m.model} className="hover:bg-surface-700/20 transition-colors">
                  <td className="py-3 px-4 font-medium text-etth-text">{m.model}</td>
                  <td className="py-3 px-4 text-right font-mono text-etth-text/80">{m.avg_precision.toFixed(3)}</td>
                  <td className="py-3 px-4 text-right font-mono text-etth-text/80">{m.avg_recall.toFixed(3)}</td>
                  <td className="py-3 px-4 text-right font-mono text-etth-text/80">{m.avg_f1.toFixed(3)}</td>
                  <td className="py-3 px-4 text-right font-mono">
                    <span className={m.avg_pr_auc >= 0.99 ? 'text-accent' : 'text-etth-text/80'}>
                      {m.avg_pr_auc.toFixed(3)}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right font-mono text-etth-text/80">{m.avg_balanced_accuracy.toFixed(3)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div>
          <SectionHeader title="Metric Comparison" />
          <div className="mt-4 border border-surface-700/50 p-4 rounded-sm bg-surface-800/20">
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={chartData}>
                <CartesianGrid {...RECHARTS_GRID} />
                <XAxis dataKey="name" stroke={RECHARTS_AXIS.stroke} tick={RECHARTS_AXIS.tick} />
                <YAxis stroke={RECHARTS_AXIS.stroke} tick={RECHARTS_AXIS.tick} domain={[0, 1]} />
                <Tooltip {...RECHARTS_TOOLTIP} />
                <Legend />
                <Bar dataKey="Precision" fill={CHART_COLORS.info} name="Precision" />
                <Bar dataKey="Recall" fill={CHART_COLORS.success} name="Recall" />
                <Bar dataKey="F1" fill={CHART_COLORS.warning} name="F1" />
                <Bar dataKey="PR-AUC" fill={CHART_COLORS.accent} name="PR-AUC" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div>
          <SectionHeader title="Interpretation Guidelines" />
          <div className="mt-4 border border-surface-700/50 p-5 rounded-sm bg-surface-800/20 space-y-4 text-sm text-etth-text/70">
            <div>
              <span className="font-medium text-etth-text">PR-AUC is primary:</span> With extreme class imbalance, PR-AUC provides the most meaningful assessment of model performance on the minority class.
            </div>
            <div>
              <span className="font-medium text-etth-text">Balanced Accuracy:</span> This metric accounts for class imbalance by averaging recall per class. Values near 0.5 indicate performance no better than random.
            </div>
            <div>
              <span className="font-medium text-etth-text">Caution:</span> All models show near-perfect metrics due to the source-confounded nature of the pilot dataset. This is expected and documented.
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}