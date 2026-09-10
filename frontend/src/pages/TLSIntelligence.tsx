import { useEffect } from 'react'
import { useETTHStore } from '../store/etthStore'
import { LoadingState, ErrorState } from '../components/ui/StatusStates'
import { Card, CardHeader, CardTitle, CardBody } from '../components/ui/Card'
import { MetricCard } from '../components/ui/MetricCard'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import { CHART_COLORS, RECHARTS_TOOLTIP, RECHARTS_GRID, RECHARTS_AXIS } from '../lib/constants'
import type { Phase6Audit } from '../types/api'

export default function TLSIntelligence() {
  const { phase6Audit, loading, error, fetchPhase6Audit } = useETTHStore()

  useEffect(() => {
    fetchPhase6Audit()
  }, [fetchPhase6Audit])

  if (loading) return <LoadingState message="Loading TLS intelligence..." />
  if (error) return <ErrorState message={error} />

  const audit = (phase6Audit || {}) as Partial<Phase6Audit>
  const auditFp = (audit.fingerprint_counts as any) || {}

  const tlsVersionData = [
    { name: 'TLS 1.2', value: 0, color: CHART_COLORS.info },
    { name: 'TLS 1.3', value: auditFp?.TLS || 0, color: CHART_COLORS.success },
  ]

  const fingerprintCoverage = [
    { name: 'JA3', available: auditFp?.JA3 || 0, total: auditFp?.TLS || 0 },
    { name: 'JA3S', available: auditFp?.JA3S || 0, total: auditFp?.TLS || 0 },
    { name: 'JA4', available: auditFp?.JA4 || 0, total: auditFp?.TLS || 0 },
  ]

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-etth-text">TLS Intelligence</h1>
        <p className="text-sm text-etth-text/50 mt-1">TLS protocol analysis and fingerprint coverage</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <MetricCard label="Total Flows" value={audit.total_rows || 0} />
        <MetricCard label="TLS Flows" value={auditFp?.TLS || 0} />
        <MetricCard label="TLS 1.2" value={0} />
        <MetricCard label="TLS 1.3" value={auditFp?.TLS || 0} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="bg-surface-800 border-surface-700">
          <CardHeader>
            <CardTitle>TLS Version Distribution</CardTitle>
          </CardHeader>
          <CardBody>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={tlsVersionData.filter(d => d.value > 0)}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {tlsVersionData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip {...RECHARTS_TOOLTIP} />
              </PieChart>
            </ResponsiveContainer>
            <div className="flex justify-center gap-6 mt-4">
              {tlsVersionData.map((item) => (
                <div key={item.name} className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full" style={{ backgroundColor: item.color }} />
                  <span className="text-sm text-etth-text/70">{item.name}</span>
                  <span className="text-sm font-mono">{item.value === 0 ? 'Not available' : item.value}</span>
                </div>
              ))}
            </div>
          </CardBody>
        </Card>

        <Card className="bg-surface-800 border-surface-700">
          <CardHeader>
            <CardTitle>Fingerprint Coverage</CardTitle>
          </CardHeader>
          <CardBody>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={fingerprintCoverage}>
                <CartesianGrid {...RECHARTS_GRID} />
                <XAxis dataKey="name" stroke={RECHARTS_AXIS.stroke} tick={RECHARTS_AXIS.tick} />
                <YAxis stroke={RECHARTS_AXIS.stroke} tick={RECHARTS_AXIS.tick} />
                <Tooltip {...RECHARTS_TOOLTIP} />
                <Bar dataKey="available" fill={CHART_COLORS.accent} name="Available" />
                <Bar dataKey="total" fill={CHART_COLORS.info} name="Total TLS" />
              </BarChart>
            </ResponsiveContainer>
            <div className="mt-4 space-y-2">
              {fingerprintCoverage.map((fp) => (
                <div key={fp.name} className="flex items-center justify-between text-sm">
                  <span className="text-etth-text/70">{fp.name}</span>
                  <span className="font-mono">
                    {fp.available} / {fp.total}{' '}
                    <span className="text-etth-text/40">
                      ({Math.round((fp.available / Math.max(fp.total, 1)) * 100)}%)
                    </span>
                  </span>
                </div>
              ))}
            </div>
          </CardBody>
        </Card>
      </div>

      <Card className="bg-surface-800 border-surface-700">
        <CardHeader>
          <CardTitle>Analysis Notes</CardTitle>
        </CardHeader>
        <CardBody className="space-y-3 text-sm text-etth-text/70">
          <p>
            <strong className="text-etth-text">ClientHello Availability:</strong> Only {auditFp?.TLS || 0} out of {audit.total_rows || 0} flows contain TLS records necessary for fingerprinting.
          </p>
          <p>
            <strong className="text-etth-text">Coverage Gap:</strong> The gap between total flows and TLS-capable flows indicates significant non-TLS traffic in the dataset, including TCP noise and application-layer protocols.
          </p>
          <p>
            <strong className="text-etth-text">Fingerprint Utility:</strong> With ~{Math.round(((auditFp?.JA4 || 0) / Math.max(auditFp?.TLS || 1, 1)) * 100)}% coverage on TLS flows, fingerprint-based experiments (B, C, D, E) have substantially smaller sample sizes than flow-only experiments.
          </p>
        </CardBody>
      </Card>
    </div>
  )
}