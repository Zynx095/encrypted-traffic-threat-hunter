import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useETTHStore } from '../store/etthStore'
import { MetricCard } from '../components/ui/MetricCard'
import { LoadingState, ErrorState } from '../components/ui/StatusStates'
import { Card, CardHeader, CardTitle, CardBody } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { cn } from '../lib/utils'
import {
  Activity,
  Lock,
  Fingerprint,
  TrendingUp,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  ShieldAlert,
  ArrowRight,
  ExternalLink,
} from 'lucide-react'
import { EXPERIMENT_LABELS } from '../lib/constants'
import type { Phase6Audit } from '../types/api'

export default function Overview() {
  const navigate = useNavigate()
  const {
    phase6Audit,
    pilotSummary,
    fetchPhase6Audit,
    fetchPilotData,
    loading,
    error,
  } = useETTHStore()

  useEffect(() => {
    fetchPhase6Audit()
    fetchPilotData()
  }, [fetchPhase6Audit, fetchPilotData])

  if (loading && !phase6Audit) return <LoadingState message="Loading ETTH data..." />
  if (error) return <ErrorState message={error} onRetry={() => { fetchPhase6Audit(); fetchPilotData() }} />

  const audit = (phase6Audit || {}) as Partial<Phase6Audit>
  const summaries = pilotSummary || []

  const handleRefresh = () => {
    fetchPhase6Audit()
    fetchPilotData()
  }

  return (
    <div className="p-4 lg:p-6 space-y-6 max-w-[1400px]">
      {/* ── Header ──────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-etth-text">
            Encrypted Traffic Threat Hunter
          </h1>
          <p className="text-sm text-etth-text/40 mt-0.5">
            Security research platform — encrypted traffic analysis
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={handleRefresh}>
          <RefreshCw className={cn('w-3.5 h-3.5 mr-1.5', loading && 'animate-spin')} />
          Refresh
        </Button>
      </div>

      {/* ── Pilot Warning ───────────────────────────────── */}
      <div className="bg-warning/5 border border-warning/20 rounded-lg px-4 py-3 flex items-start gap-3">
        <ShieldAlert className="w-4 h-4 text-warning shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-medium text-warning">
            Controlled Pilot — Source-Confounded
          </p>
          <p className="text-xs text-etth-text/50 mt-1 leading-relaxed">
            Results are from a controlled pilot with extreme class imbalance
            (2,543:6 malicious:benign). Near-perfect metrics are expected
            artifacts of dataset composition, not production performance.
            Generalized validation pending independent benign data.
          </p>
        </div>
      </div>

      {/* ── Key Metrics ─────────────────────────────────── */}
      <div>
        <SectionLabel>Research Metrics</SectionLabel>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mt-2">
          <div onClick={() => navigate('/threat-hunt')} className="cursor-pointer">
            <MetricCard
              label="Total Flows"
              value={(audit.total_rows || 0).toLocaleString()}
              subtitle="Reconstructed from PCAPs"
              icon={<Activity className="w-4 h-4" />}
            />
          </div>
          <div onClick={() => navigate('/tls')} className="cursor-pointer">
            <MetricCard
              label="TLS Flows"
              value={(audit.fingerprint_counts?.JA3 || 0).toLocaleString()}
              subtitle={`${(((audit.fingerprint_counts?.JA3 || 0) / Math.max(audit.total_rows || 1, 1)) * 100).toFixed(1)}% of total`}
              icon={<Lock className="w-4 h-4" />}
            />
          </div>
          <div onClick={() => navigate('/fingerprints')} className="cursor-pointer">
            <MetricCard
              label="JA3 Coverage"
              value={(audit.fingerprint_counts?.JA3 || 0).toLocaleString()}
              subtitle="Fingerprints extracted"
              icon={<Fingerprint className="w-4 h-4" />}
            />
          </div>
          <div onClick={() => navigate('/fingerprints')} className="cursor-pointer">
            <MetricCard
              label="JA4 Coverage"
              value={(audit.fingerprint_counts?.JA4 || 0).toLocaleString()}
              subtitle={`${(((audit.fingerprint_counts?.JA4 || 0) / Math.max(audit.fingerprint_counts?.JA3 || 1, 1)) * 100).toFixed(1)}% of TLS`}
              icon={<TrendingUp className="w-4 h-4" />}
            />
          </div>
        </div>
      </div>

      {/* ── Dataset Composition + Model-Safe ─────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle>Dataset Composition</CardTitle>
          </CardHeader>
          <CardBody className="space-y-2.5">
            <DataRow
              label="DS-008 (Malicious)"
              value={`${(audit.dataset_counts?.['DS-008'] || 0).toLocaleString()} flows`}
              onClick={() => navigate('/datasets/DS-008')}
            />
            <DataRow
              label="DS-004 (Benign Validation)"
              value={`${(audit.dataset_counts?.['DS-004'] || 0).toLocaleString()} flows`}
              onClick={() => navigate('/datasets/DS-004')}
            />
            <div className="pt-2.5 border-t border-surface-700">
              <DataRow
                label="Class Imbalance Ratio"
                value={`~${Math.round((audit.dataset_counts?.['DS-008'] || 0) / Math.max(audit.dataset_counts?.['DS-004'] || 1, 1))}:1`}
                variant="danger"
              />
            </div>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Model-Safe Dataset</CardTitle>
          </CardHeader>
          <CardBody className="space-y-2.5">
            <DataRow
              label="Total Model-Safe Rows"
              value={(audit.total_rows || 0).toLocaleString()}
            />
            <DataRow
              label="Duplicate Groups"
              value={(audit.duplicate_counts?.duplicate_groups || 0).toLocaleString()}
            />
            <div className="pt-2.5 border-t border-surface-700">
              <div className="flex items-center gap-2 text-sm text-success">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Leakage violations: 0</span>
              </div>
            </div>
          </CardBody>
        </Card>
      </div>

      {/* ── Experiment Results ────────────────────────────── */}
      <Card>
        <CardHeader className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <CardTitle>Experiment Results</CardTitle>
            <Badge variant="warning">Pilot</Badge>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => navigate('/experiments')}
          >
            View Details
            <ArrowRight className="w-3.5 h-3.5 ml-1" />
          </Button>
        </CardHeader>
        <CardBody>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-surface-700">
                  <th className="text-left py-2 px-3 text-etth-text/40 font-medium text-xs uppercase tracking-wider">Experiment</th>
                  <th className="text-left py-2 px-3 text-etth-text/40 font-medium text-xs uppercase tracking-wider">Description</th>
                  <th className="text-right py-2 px-3 text-etth-text/40 font-medium text-xs uppercase tracking-wider">Samples</th>
                  <th className="text-right py-2 px-3 text-etth-text/40 font-medium text-xs uppercase tracking-wider">Features</th>
                  <th className="text-right py-2 px-3 text-etth-text/40 font-medium text-xs uppercase tracking-wider">Best PR-AUC</th>
                  <th className="text-right py-2 px-3 text-etth-text/40 font-medium text-xs uppercase tracking-wider">Best Model</th>
                </tr>
              </thead>
              <tbody>
                {summaries.map((exp) => (
                  <tr
                    key={exp.experiment}
                    className="border-b border-surface-700/50 hover:bg-surface-700/20 cursor-pointer transition-colors"
                    onClick={() => navigate(`/experiments/${exp.experiment}`)}
                  >
                    <td className="py-2.5 px-3">
                      <span className="font-mono text-xs text-accent">{exp.experiment}</span>
                    </td>
                    <td className="py-2.5 px-3 text-etth-text/60 text-xs">
                      {EXPERIMENT_LABELS[exp.experiment] || exp.description}
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono text-xs">{exp.samples}</td>
                    <td className="py-2.5 px-3 text-right font-mono text-xs">{exp.features}</td>
                    <td className="py-2.5 px-3 text-right font-mono text-xs">
                      <span className={exp.best_avg_pr_auc >= 0.99 ? 'text-warning' : ''}>
                        {exp.best_avg_pr_auc.toFixed(4)}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-right text-xs text-etth-text/60">
                      {exp.best_model}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {summaries.length > 0 && (
            <p className="text-[11px] text-etth-text/30 mt-3 text-right">
              Pilot metrics — imbalance distorts evaluation
            </p>
          )}
        </CardBody>
      </Card>

      {/* ── Status Grid ──────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card>
          <CardHeader>
            <CardTitle>Research Status</CardTitle>
          </CardHeader>
          <CardBody className="space-y-2">
            <StatusRow label="Phase 5 — Verification" status="complete" />
            <StatusRow label="Phase 6 — Audit" status="complete" />
            <StatusRow label="Stage 6.5 — Pilot" status="complete" />
            <StatusRow label="Phase 7 — Validation" status="not-started" />
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Pipeline Status</CardTitle>
          </CardHeader>
          <CardBody className="space-y-2">
            <StatusRow label="Ingestion" status="complete" />
            <StatusRow label="Validation" status="complete" />
            <StatusRow label="Feature Extraction" status="complete" />
            <StatusRow label="Model-Safe Generation" status="complete" />
            <StatusRow label="Experimental Construction" status="complete" />
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Known Limitations</CardTitle>
          </CardHeader>
          <CardBody className="space-y-3">
            <LimitationRow text="Extreme class imbalance (2,543:6)" />
            <LimitationRow text="Dataset-source confounding" />
            <LimitationRow text="Pilot-only model evaluation" />
            <LimitationRow text="Independent benign data required" />
          </CardBody>
        </Card>
      </div>
    </div>
  )
}

// ── Helper Components ───────────────────────────────────────

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <span className="text-[10px] font-medium uppercase tracking-widest text-etth-text/30">
      {children}
    </span>
  )
}

function DataRow({
  label,
  value,
  variant = 'default',
  onClick,
}: {
  label: string
  value: string
  variant?: 'default' | 'danger' | 'warning' | 'success'
  onClick?: () => void
}) {
  const valueColors = {
    default: 'text-etth-text/80',
    danger: 'text-danger',
    warning: 'text-warning',
    success: 'text-success',
  }

  return (
    <div
      className={cn(
        'flex items-center justify-between text-sm',
        onClick && 'cursor-pointer hover:bg-surface-700/20 -mx-2 px-2 py-1 rounded transition-colors'
      )}
      onClick={onClick}
    >
      <span className="text-etth-text/50">{label}</span>
      <span className={cn('font-mono text-xs', valueColors[variant])}>
        {value}
      </span>
    </div>
  )
}

function StatusRow({
  label,
  status,
}: {
  label: string
  status: 'complete' | 'in-progress' | 'not-started' | 'blocked'
}) {
  const config = {
    complete: { color: 'bg-success', text: 'text-success', label: 'Complete' },
    'in-progress': { color: 'bg-info', text: 'text-info', label: 'In Progress' },
    'not-started': { color: 'bg-surface-500', text: 'text-etth-text/40', label: 'Not Started' },
    blocked: { color: 'bg-danger', text: 'text-danger', label: 'Blocked' },
  }
  const c = config[status]

  return (
    <div className="flex items-center justify-between">
      <span className="text-sm text-etth-text/60">{label}</span>
      <div className="flex items-center gap-1.5">
        <span className={cn('w-1.5 h-1.5 rounded-full', c.color)} />
        <span className={cn('text-xs font-medium', c.text)}>{c.label}</span>
      </div>
    </div>
  )
}

function LimitationRow({ text }: { text: string }) {
  return (
    <div className="flex items-start gap-2 text-sm text-etth-text/50">
      <AlertTriangle className="w-3.5 h-3.5 text-warning/60 shrink-0 mt-0.5" />
      <span className="leading-tight">{text}</span>
    </div>
  )
}