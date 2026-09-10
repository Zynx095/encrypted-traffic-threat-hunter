import { useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useETTHStore } from '../store/etthStore'
import { LoadingState, ErrorState } from '../components/ui/StatusStates'
import { Card, CardHeader, CardBody, CardTitle } from '../components/ui/Card'
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
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-etth-text">Model Analysis</h1>
        <p className="text-sm text-etth-text/50 mt-1">Model comparison and performance analysis</p>
      </div>

      <div className="bg-warning/10 border border-warning/30 rounded-lg p-4">
        <p className="text-sm text-warning">
          <strong>Note:</strong> Model metrics are from a controlled pilot with extreme class imbalance. 
          Results demonstrate pipeline functionality, not production-grade performance.
        </p>
      </div>

      <Card className="bg-surface-800 border-surface-700">
        <CardHeader>
          <CardTitle>Model Performance Summary</CardTitle>
        </CardHeader>
        <CardBody>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-surface-700">
                  <th className="text-left py-2 px-3 text-etth-text/60">Model</th>
                  <th className="text-right py-2 px-3 text-etth-text/60">Precision</th>
                  <th className="text-right py-2 px-3 text-etth-text/60">Recall</th>
                  <th className="text-right py-2 px-3 text-etth-text/60">F1</th>
                  <th className="text-right py-2 px-3 text-etth-text/60">PR-AUC</th>
                  <th className="text-right py-2 px-3 text-etth-text/60">Balanced Acc</th>
                </tr>
              </thead>
              <tbody>
                {modelMetrics.map((m) => (
                  <tr key={m.model} className="border-b border-surface-700/50 hover:bg-surface-700/20">
                    <td className="py-3 px-3 font-medium">{m.model}</td>
                    <td className="py-3 px-3 text-right font-mono">{m.avg_precision.toFixed(3)}</td>
                    <td className="py-3 px-3 text-right font-mono">{m.avg_recall.toFixed(3)}</td>
                    <td className="py-3 px-3 text-right font-mono">{m.avg_f1.toFixed(3)}</td>
                    <td className="py-3 px-3 text-right font-mono">
                      <span className={m.avg_pr_auc >= 0.99 ? 'text-warning' : 'text-etth-text'}>
                        {m.avg_pr_auc.toFixed(3)}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-right font-mono">{m.avg_balanced_accuracy.toFixed(3)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardBody>
      </Card>

      <Card className="bg-surface-800 border-surface-700">
        <CardHeader>
          <CardTitle>Metric Comparison</CardTitle>
        </CardHeader>
        <CardBody>
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
        </CardBody>
      </Card>

      <Card className="bg-surface-800 border-surface-700">
        <CardHeader>
          <CardTitle>Interpretation Guidelines</CardTitle>
        </CardHeader>
        <CardBody className="space-y-3 text-sm text-etth-text/70">
          <p>
            <strong className="text-etth-text">PR-AUC is primary:</strong> With extreme class imbalance, PR-AUC provides the most meaningful assessment of model performance on the minority class.
          </p>
          <p>
            <strong className="text-etth-text">Balanced Accuracy:</strong> This metric accounts for class imbalance by averaging recall per class. Values near 0.5 indicate performance no better than random.
          </p>
          <p>
            <strong className="text-etth-text">Caution:</strong> All models show near-perfect metrics due to the source-confounded nature of the pilot dataset. This is expected and documented.
          </p>
        </CardBody>
      </Card>
    </div>
  )
}