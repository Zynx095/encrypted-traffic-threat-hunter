import React, { useEffect } from 'react'
import { useETTHStore } from '../store/etthStore'
import { LoadingState, ErrorState } from '../components/ui/StatusStates'
import { PageHeader } from '../components/ui/PageHeader'
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
    <div className="p-4 lg:p-6 space-y-6 max-w-[1600px] mx-auto font-sans">
      <PageHeader
        title="TLS Intelligence & Fingerprints"
        description="Global TLS protocol distribution and fingerprint coverage across operational data streams."
      />

      {/* Typographic Grouped Summary Strip */}
      <div className="bg-surface-800 border border-surface-700 rounded-sm p-4">
        <div className="flex flex-wrap items-center justify-between gap-6 text-xs font-mono">
          <div>
            <span className="text-etth-text/40 text-[10px] block uppercase">TOTAL FLOW RECORDS</span>
            <span className="text-xl font-bold text-etth-text mt-0.5 block">{(audit.total_rows || 0).toLocaleString()}</span>
          </div>

          <div className="h-8 w-px bg-surface-700 hidden sm:block" />

          <div>
            <span className="text-etth-text/40 text-[10px] block uppercase">TLS OBSERVABLE FLOWS</span>
            <span className="text-xl font-bold text-success mt-0.5 block">{(auditFp?.TLS || 0).toLocaleString()}</span>
          </div>

          <div className="h-8 w-px bg-surface-700 hidden sm:block" />

          <div>
            <span className="text-etth-text/40 text-[10px] block uppercase">JA3 FINGERPRINTS</span>
            <span className="text-xl font-bold text-accent mt-0.5 block">{(auditFp?.JA3 || 0).toLocaleString()}</span>
          </div>

          <div className="h-8 w-px bg-surface-700 hidden sm:block" />

          <div>
            <span className="text-etth-text/40 text-[10px] block uppercase">JA4 FINGERPRINTS</span>
            <span className="text-xl font-bold text-info mt-0.5 block">{(auditFp?.JA4 || 0).toLocaleString()}</span>
          </div>
        </div>
      </div>

      {/* Analytical Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="border border-surface-700 rounded-sm bg-surface-800 p-4 space-y-4">
          <div className="text-xs font-semibold text-etth-text uppercase tracking-wider">TLS Version Distribution</div>
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie
                data={tlsVersionData.filter(d => d.value > 0)}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={90}
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
          <div className="flex justify-center gap-6 text-xs">
            {tlsVersionData.map((item) => (
              <div key={item.name} className="flex items-center gap-2 font-mono">
                <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                <span className="text-etth-text/70">{item.name}:</span>
                <span className="text-etth-text font-bold">{item.value === 0 ? 'UNAVAILABLE' : item.value.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="border border-surface-700 rounded-sm bg-surface-800 p-4 space-y-4">
          <div className="text-xs font-semibold text-etth-text uppercase tracking-wider">Fingerprint Coverage</div>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={fingerprintCoverage}>
              <CartesianGrid {...RECHARTS_GRID} />
              <XAxis dataKey="name" stroke={RECHARTS_AXIS.stroke} tick={RECHARTS_AXIS.tick} />
              <YAxis stroke={RECHARTS_AXIS.stroke} tick={RECHARTS_AXIS.tick} />
              <Tooltip {...RECHARTS_TOOLTIP} />
              <Bar dataKey="available" fill={CHART_COLORS.accent} name="Available" />
              <Bar dataKey="total" fill={CHART_COLORS.info} name="Total TLS" />
            </BarChart>
          </ResponsiveContainer>
          <div className="space-y-2 pt-2 border-t border-surface-700/50 text-xs font-mono">
            {fingerprintCoverage.map((fp) => (
              <div key={fp.name} className="flex items-center justify-between">
                <span className="text-etth-text/70">{fp.name} Coverage:</span>
                <span className="text-etth-text font-semibold">
                  {fp.available.toLocaleString()} / {fp.total.toLocaleString()}{' '}
                  <span className="text-etth-text/40">
                    ({Math.round((fp.available / Math.max(fp.total, 1)) * 100)}%)
                  </span>
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Analysis Notes */}
      <div className="border border-surface-700 rounded-sm bg-surface-800 p-4 space-y-2 text-xs">
        <div className="text-xs font-semibold text-etth-text uppercase tracking-wider mb-2">Protocol Analysis Notes</div>
        <div className="text-etth-text/70 space-y-1.5 leading-relaxed">
          <p>
            <strong className="text-etth-text">ClientHello Availability:</strong> Only {auditFp?.TLS || 0} out of {audit.total_rows || 0} flows contain TLS records necessary for fingerprinting.
          </p>
          <p>
            <strong className="text-etth-text">Coverage Gap:</strong> The gap between total flows and TLS-capable flows indicates non-TLS traffic in the dataset, including raw TCP handshakes and application-layer noise.
          </p>
          <p>
            <strong className="text-etth-text">Fingerprint Utility:</strong> With ~{Math.round(((auditFp?.JA4 || 0) / Math.max(auditFp?.TLS || 1, 1)) * 100)}% coverage on TLS flows, fingerprint-based experiments (B, C, D, E) operate on precise sub-samples compared to flow-only feature baselines.
          </p>
        </div>
      </div>
    </div>
  )
}