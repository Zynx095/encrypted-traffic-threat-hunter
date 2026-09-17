import { useEffect } from 'react'
import { useETTHStore } from '../store/etthStore'
import { LoadingState, ErrorState } from '../components/ui/StatusStates'
import { Card, CardHeader, CardBody, CardTitle } from '../components/ui/Card'
import { PageHeader } from '../components/ui/PageHeader'
import { cn } from '../lib/utils'

export default function ResearchView() {
  const { phase6Audit, loading, error, fetchPhase6Audit } = useETTHStore()

  useEffect(() => {
    fetchPhase6Audit()
  }, [fetchPhase6Audit])

  if (loading) return <LoadingState message="Loading research context..." />
  if (error) return <ErrorState message={error} />

  // Fix fallback typing issue by providing a more complete structure or using any for safety if needed
  const audit = (phase6Audit || { 
    dataset_counts: {}, 
    fingerprint_counts: {}, 
    experiment_counts: {}, 
    total_rows: 0 
  }) as any

  return (
    <div className="p-6 space-y-6">
      <PageHeader 
        title="Research Methodology" 
        description="Data provenance, pipeline architecture, and experiment design." 
      />

      {/* Methodology Pipeline */}
      <Card className="bg-surface-800 border-surface-700">
        <CardHeader>
          <CardTitle>Data Processing Pipeline (Phase 6)</CardTitle>
        </CardHeader>
        <CardBody>
          <div className="flex flex-col items-center space-y-4 py-6">
            <div className={cn('px-4 py-3 rounded-sm border text-center', 'bg-success/20 border-success/50 text-success')}>
              <div className="text-xs font-mono opacity-75">1</div>
              <div className="text-sm font-medium">Dataset Selection</div>
              <div className="text-xs opacity-75 mt-1">Benign (DS-004) & Malicious (DS-008) PCAPs</div>
            </div>
            
            <div className="text-etth-text/30">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 5v14M5 12l7 7 7-7" />
              </svg>
            </div>
            
            <div className={cn('px-4 py-3 rounded-sm border text-center', 'bg-success/20 border-success/50 text-success')}>
              <div className="text-xs font-mono opacity-75">2</div>
              <div className="text-sm font-medium">Flow Reconstruction</div>
              <div className="text-xs opacity-75 mt-1">Zeek connection logging</div>
            </div>
            
            <div className="text-etth-text/30">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 5v14M5 12l7 7 7-7" />
              </svg>
            </div>
            
            <div className={cn('px-4 py-3 rounded-sm border text-center', 'bg-success/20 border-success/50 text-success')}>
              <div className="text-xs font-mono opacity-75">3</div>
              <div className="text-sm font-medium">Traffic Labeling</div>
              <div className="text-xs opacity-75 mt-1">Source-based implicit labeling</div>
            </div>
            
            <div className="text-etth-text/30">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 5v14M5 12l7 7 7-7" />
              </svg>
            </div>
            
            <div className={cn('px-4 py-3 rounded-sm border text-center', 'bg-success/20 border-success/50 text-success')}>
              <div className="text-xs font-mono opacity-75">4</div>
              <div className="text-sm font-medium">Feature Extraction</div>
              <div className="text-xs opacity-75 mt-1">Behavioral + TLS features</div>
            </div>
            
            <div className="text-etth-text/30">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 5v14M5 12l7 7 7-7" />
              </svg>
            </div>
            
            <div className={cn('px-4 py-3 rounded-sm border text-center', 'bg-success/20 border-success/50 text-success', 'border-accent/50')}>
              <div className="text-xs font-mono opacity-75">5</div>
              <div className="text-sm font-medium">Leakage-Safe Preprocessing</div>
              <div className="text-xs opacity-75 mt-1">Identifier removal, duplicate grouping</div>
            </div>
            
            <div className="text-etth-text/30">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 5v14M5 12l7 7 7-7" />
              </svg>
            </div>
            
            <div className="flex gap-4 flex-wrap justify-center">
              {['A', 'B', 'C', 'D', 'E'].map(exp => (
                <div key={exp} className={cn('px-4 py-3 rounded-sm border text-center', 'bg-success/20 border-success/50 text-success', exp === 'E' && 'border-accent/50')}>
                  <div className="text-xs font-mono opacity-75">6{exp.toLowerCase()}</div>
                  <div className="text-sm font-medium">Exp {exp}</div>
                  <div className="text-xs opacity-75 mt-1">
                    {exp === 'A' ? 'Flow-only' : exp === 'B' ? 'JA3-only' : exp === 'C' ? 'JA4-only' : exp === 'D' ? 'JA3+Flow' : 'JA4+Flow'}
                  </div>
                </div>
              ))}
            </div>
            
            <div className="text-etth-text/30">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 5v14M5 12l7 7 7-7" />
              </svg>
            </div>
            
            <div className={cn('px-4 py-3 rounded-sm border text-center', 'bg-warning/20 border-warning/50 text-warning')}>
              <div className="text-xs font-mono opacity-75">7</div>
              <div className="text-sm font-medium">Model Evaluation</div>
              <div className="text-xs opacity-75 mt-1">CV, metrics, statistical analysis</div>
            </div>
            
            <div className="text-etth-text/30">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 5v14M5 12l7 7 7-7" />
              </svg>
            </div>
            
            <div className={cn('px-4 py-3 rounded-sm border text-center', 'bg-surface-700 border-surface-600 text-etth-text/50')}>
              <div className="text-xs font-mono opacity-75">8</div>
              <div className="text-sm font-medium">Interpretation</div>
              <div className="text-xs opacity-75 mt-1">Feature importance, explanations</div>
            </div>
          </div>
        </CardBody>
      </Card>

      {/* Key Facts */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="bg-surface-800 border-surface-700">
          <CardHeader>
            <CardTitle>Dataset Composition</CardTitle>
          </CardHeader>
          <CardBody className="space-y-2 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-etth-text/50">DS-008 (Malicious)</span>
              <span className="font-mono text-etth-text/70">{audit.dataset_counts?.['DS-008']?.toLocaleString() || 0} flows</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-etth-text/50">DS-004 (Benign)</span>
              <span className="font-mono text-etth-text/70">{audit.dataset_counts?.['DS-004']?.toLocaleString() || 0} flows</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-etth-text/50">Total</span>
              <span className="font-mono text-etth-text/70">{(audit.total_rows || 0).toLocaleString()} flows</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-etth-text/50">Class Ratio</span>
              <span className="font-mono text-danger">{Math.round((audit.dataset_counts?.['DS-008'] || 0) / Math.max(audit.dataset_counts?.['DS-004'] || 1, 1))}:1</span>
            </div>
          </CardBody>
        </Card>

        <Card className="bg-surface-800 border-surface-700">
          <CardHeader>
            <CardTitle>TLS Intelligence</CardTitle>
          </CardHeader>
          <CardBody className="space-y-2 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-etth-text/50">TLS Flows</span>
              <span className="font-mono text-etth-text/70">{audit.fingerprint_counts?.TLS?.toLocaleString() || '0'}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-etth-text/50">JA3 Coverage</span>
              <span className="font-mono text-etth-text/70">{audit.fingerprint_counts?.JA3?.toLocaleString() || '0'} ({Math.round((audit.fingerprint_counts?.JA3 || 0) / Math.max(audit.fingerprint_counts?.TLS || 1, 1) * 100)}%)</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-etth-text/50">JA3S Coverage</span>
              <span className="font-mono text-etth-text/70">{audit.fingerprint_counts?.JA3S?.toLocaleString() || '0'} ({Math.round((audit.fingerprint_counts?.JA3S || 0) / Math.max(audit.fingerprint_counts?.TLS || 1, 1) * 100)}%)</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-etth-text/50">JA4 Coverage</span>
              <span className="font-mono text-etth-text/70">{audit.fingerprint_counts?.JA4?.toLocaleString() || '0'} ({Math.round((audit.fingerprint_counts?.JA4 || 0) / Math.max(audit.fingerprint_counts?.TLS || 1, 1) * 100)}%)</span>
            </div>
          </CardBody>
        </Card>

        <Card className="bg-surface-800 border-surface-700">
          <CardHeader>
            <CardTitle>Experimental Status</CardTitle>
          </CardHeader>
          <CardBody className="space-y-2 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-etth-text/50">Experiments</span>
              <span className="font-mono text-etth-text/70">{Object.keys(audit.experiment_counts || {}).length} (A-E)</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-etth-text/50">Models</span>
              <span className="font-mono text-etth-text/70">3 (LR, RF, XGB)</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-etth-text/50">Folds</span>
              <span className="font-mono text-etth-text/70">5</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-etth-text/50">Status</span>
              <span className="font-mono text-warning">Pilot Only</span>
            </div>
          </CardBody>
        </Card>
      </div>

      {/* Limitations */}
      <Card className="bg-surface-800 border-surface-700">
        <CardHeader>
          <CardTitle>Known Limitations</CardTitle>
        </CardHeader>
        <CardBody className="space-y-3 text-sm text-etth-text/70">
          {[
            {
              title: "Source Confounding",
              description: "DS-004 (benign) and DS-008 (malicious) come from different capture environments, making it difficult to distinguish between traffic characteristics and environment artifacts."
            },
            {
              title: "Extreme Class Imbalance",
              description: "The 424:1 ratio means models can achieve high accuracy by predicting all samples as malicious. PR-AUC is the recommended metric for evaluation."
            },
            {
              title: "Limited Benign Validation",
              description: "Only 6 benign validation flows are available. A larger, independent benign dataset is required for robust generalization claims."
            },
            {
              title: "Pilot-Only Results",
              description: "All metrics reported are from a controlled pilot. Results should not be interpreted as production-grade performance."
            }
          ].map((limit, idx) => (
            <div key={idx} className="p-3 bg-surface-700/30 rounded-sm border border-surface-700">
              <p className="text-sm font-medium text-etth-text">{limit.title}</p>
              <p className="text-xs text-etth-text/60 mt-1">{limit.description}</p>
            </div>
          ))}
        </CardBody>
      </Card>
    </div>
  )
}