import { EmptyState } from '../components/ui/StatusStates'
import { Card, CardHeader, CardBody, CardTitle } from '../components/ui/Card'

export default function Explainability() {
  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-etth-text">Explainability</h1>
        <p className="text-sm text-etth-text/50 mt-1">Feature importance and model interpretation</p>
      </div>

      <div className="py-12">
        <EmptyState 
          title="Explainability artifacts are not currently available." 
          description="Explainability and feature importance analysis requires completed models and an unbiased baseline. Feature importance must not be inferred from the current source-confounded pilot data."
        />
      </div>

      <Card className="bg-surface-800 border-surface-700">
        <CardHeader>
          <CardTitle>Scientific Interpretation Guidelines (Pending)</CardTitle>
        </CardHeader>
        <CardBody className="space-y-3 text-sm text-etth-text/70">
          <p>
            <strong className="text-etth-text">Feature Importance ≠ Causality:</strong> Once explainability artifacts become available, remember that feature importance indicates which features the model considers most discriminative to reduce loss. It does not establish causal relationships or underlying adversary intent.
          </p>
          <p>
            <strong className="text-etth-text">Prerequisites:</strong> Meaningful interpretation relies heavily on the quality of independent benign data to ensure the model isn't simply learning the characteristics of the benign collection environment.
          </p>
        </CardBody>
      </Card>
    </div>
  )
}