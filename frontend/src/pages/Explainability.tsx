import { EmptyState } from '../components/ui/StatusStates'
import { PageHeader } from '../components/ui/PageHeader'
import { SectionHeader } from '../components/ui/SectionHeader'

export default function Explainability() {
  return (
    <div className="p-6 max-w-7xl mx-auto space-y-8">
      <PageHeader 
        title="Explainability" 
        description="Feature importance and model interpretation." 
      />

      <div className="py-12 border border-surface-700/50 rounded-sm bg-surface-800/20">
        <EmptyState 
          title="Explainability artifacts are not currently available." 
          description="Explainability and feature importance analysis requires completed models and an unbiased baseline. Feature importance must not be inferred from the current source-confounded pilot data."
        />
      </div>

      <div>
        <SectionHeader title="Scientific Interpretation Guidelines (Pending)" />
        <div className="mt-4 border border-surface-700/50 p-5 rounded-sm bg-surface-800/20 space-y-4 text-sm text-etth-text/70">
          <div>
            <span className="font-medium text-etth-text">Feature Importance ≠ Causality:</span> Once explainability artifacts become available, remember that feature importance indicates which features the model considers most discriminative to reduce loss. It does not establish causal relationships or underlying adversary intent.
          </div>
          <div>
            <span className="font-medium text-etth-text">Prerequisites:</span> Meaningful interpretation relies heavily on the quality of independent benign data to ensure the model isn't simply learning the characteristics of the benign collection environment.
          </div>
        </div>
      </div>
    </div>
  )
}