import { useCallback, useEffect, useMemo, useState } from 'react'
import { etthApi } from '../lib/api'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { PageHeader } from '../components/ui/PageHeader'
import { SectionHeader } from '../components/ui/SectionHeader'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/Tabs'
import { EmptyState, ErrorState, LoadingState } from '../components/ui/StatusStates'
import type {
  BenchmarkRow,
  DatasetSummary,
  InferenceStatus,
  JobRecord,
  JobType,
  LatestBenchmarks,
  ModelRegistryView,
  PairedContrast,
  ResearchDocument,
} from '../types/research'

// Every value on this page comes from persisted research artefacts served by /api/research.
// Missing artefacts are shown as NOT_RUN / NOT_AVAILABLE; nothing is filled in client-side.

function useResource<T>(loader: () => Promise<T>, pollMs?: number) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const load = useCallback(async () => {
    try {
      const d = await loader()
      setData(d)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  useEffect(() => {
    load()
    if (!pollMs) return
    const t = setInterval(load, pollMs)
    return () => clearInterval(t)
  }, [load, pollMs])
  return { data, error, loading, reload: load }
}

const fmt = (v: number | null | undefined, digits = 3) => (v === null || v === undefined || Number.isNaN(v) ? '—' : v.toFixed(digits))
const pct = (v: number | null | undefined) => (v === null || v === undefined ? '—' : `${(v * 100).toFixed(1)}%`)

function stateVariant(state: string): 'success' | 'warning' | 'danger' | 'info' | 'default' {
  if (['ADMITTED', 'COMPLETED', 'AVAILABLE', 'LOADED', 'ACTIVE', 'SUPPORTED', 'OK'].includes(state)) return 'success'
  if (['BLOCKED', 'REJECTED', 'FAILED', 'LOAD_FAILED', 'CONTRADICTED', 'INSUFFICIENT_GROUPS'].includes(state)) return 'danger'
  if (['ACCESS_PENDING', 'RUNNING', 'QUEUED', 'PRELIMINARY', 'FEW_GROUPS', 'CANDIDATE', 'INSUFFICIENT_EVIDENCE'].includes(state)) return 'warning'
  if (['NOT_RUN', 'NO_ACTIVE_MODEL', 'UNTESTED', 'NOT_AVAILABLE'].includes(state)) return 'info'
  return 'default'
}

function DocGate({ doc, children }: { doc: ResearchDocument | null; children: (data: Record<string, any>) => React.ReactNode }) {
  if (!doc) return null
  if (doc.status !== 'AVAILABLE' || !doc.data) {
    return <EmptyState title={doc.status} description={doc.detail ?? `Source: ${doc.source ?? 'unknown'}`} />
  }
  return <>{children(doc.data)}</>
}

const th = 'text-left py-2 px-3 font-medium text-etth-text/60 whitespace-nowrap'
const td = 'py-2 px-3 text-etth-text/80 align-top'

// ------------------------------------------------------------------------ corpus --
function CorpusTab() {
  const datasets = useResource<DatasetSummary[]>(etthApi.research.datasets)
  const admission = useResource<ResearchDocument>(etthApi.research.admission)
  const sufficiency = useResource<ResearchDocument>(etthApi.research.sufficiency)
  if (datasets.loading) return <LoadingState message="Loading dataset registry..." />
  if (datasets.error) return <ErrorState message={datasets.error} onRetry={datasets.reload} />
  return (
    <div className="space-y-8">
      <div>
        <SectionHeader title="Dataset registry" description="Lifecycle states are evidence-based; unknown facts stay UNKNOWN." />
        <div className="border border-surface-700/50 rounded-sm overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-surface-800/50 border-b border-surface-700/50">
              <tr><th className={th}>ID</th><th className={th}>Name</th><th className={th}>State</th><th className={th}>Access</th><th className={th}>Flows</th><th className={th}>Last evidence</th></tr>
            </thead>
            <tbody className="divide-y divide-surface-700/50">
              {(datasets.data ?? []).map((d) => (
                <tr key={d.dataset_id}>
                  <td className={`${td} font-mono text-xs`}>{d.dataset_id}</td>
                  <td className={td}>{d.name}</td>
                  <td className={td}><Badge variant={stateVariant(d.state)}>{d.state}</Badge></td>
                  <td className={`${td} text-xs`}>{d.access_category}</td>
                  <td className={`${td} font-mono text-xs`}>{typeof d.flow_count === 'number' ? d.flow_count.toLocaleString() : 'UNKNOWN'}</td>
                  <td className={`${td} text-xs text-etth-text/50 max-w-md`}>{d.last_transition?.evidence ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div>
        <SectionHeader title="Admission funnel" description="Counts computed from data at each processing step." />
        <DocGate doc={admission.data}>
          {(a) => (
            <div className="border border-surface-700/50 rounded-sm overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-surface-800/50 border-b border-surface-700/50">
                  <tr>{['Dataset', 'Listed', 'Planned', 'Present', 'Verified', 'Valid PCAP', 'In corpus', 'Flows', 'JA3', 'JA4'].map((h) => <th key={h} className={th}>{h}</th>)}</tr>
                </thead>
                <tbody className="divide-y divide-surface-700/50">
                  {Object.entries<any>(a.funnel_by_dataset ?? {}).map(([ds, f]) => (
                    <tr key={ds} className="font-mono text-xs">
                      <td className={td}>{ds}</td><td className={td}>{f.captures_listed}</td><td className={td}>{f.captures_included_in_plan}</td>
                      <td className={td}>{f.captures_present}</td><td className={td}>{f.captures_checksum_verified_or_observed}</td>
                      <td className={td}>{f.captures_pcap_valid}</td><td className={td}>{f.captures_in_corpus}</td>
                      <td className={td}>{f.flows_in_corpus.toLocaleString()}</td><td className={td}>{f.ja3_flows.toLocaleString()}</td><td className={td}>{f.ja4_flows.toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <ul className="p-4 text-xs text-etth-text/60 list-disc list-inside space-y-1">
                {(a.known_limitations ?? []).map((l: string) => <li key={l}>{l}</li>)}
              </ul>
            </div>
          )}
        </DocGate>
      </div>

      <div>
        <SectionHeader title="Benign corpus sufficiency" description="A: pipeline executes · B: preliminary evaluation · C: generalisation study · D: publication claim" />
        <DocGate doc={sufficiency.data}>
          {(s) => (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
              {Object.entries<any>(s.levels ?? {}).map(([level, v]) => (
                <div key={level} className="border border-surface-700/50 rounded-sm p-3 bg-surface-800/20">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-medium text-etth-text">{level}</span>
                    <Badge variant={v.met ? 'success' : 'danger'}>{v.met ? 'MET' : 'NOT MET'}</Badge>
                  </div>
                  <ul className="text-[11px] text-etth-text/60 space-y-0.5">
                    {Object.entries<boolean>(v.checks ?? {}).map(([k, ok]) => <li key={k}>{ok ? '✓' : '✗'} {k.split('_').join(' ')}</li>)}
                  </ul>
                </div>
              ))}
            </div>
          )}
        </DocGate>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------- coverage --
function CoverageTab() {
  const cov = useResource<ResearchDocument>(etthApi.research.coverage)
  if (cov.loading) return <LoadingState message="Loading coverage report..." />
  if (cov.error) return <ErrorState message={cov.error} onRetry={cov.reload} />
  return (
    <DocGate doc={cov.data}>
      {(c) => (
        <div className="space-y-8">
          <div>
            <SectionHeader title="Track coverage" description="Share of each class that a track can score. Fingerprint tracks only see flows with a parsed ClientHello." />
            <table className="w-full text-sm border border-surface-700/50">
              <thead className="bg-surface-800/50"><tr>{['Track', 'Population', 'Rows', 'All', 'Malicious', 'Benign'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
              <tbody className="divide-y divide-surface-700/50">
                {Object.entries<any>(c.track_coverage ?? {}).map(([t, v]) => (
                  <tr key={t} className="font-mono text-xs"><td className={td}>{t}</td><td className={td}>{v.population}</td><td className={td}>{v.rows.toLocaleString()}</td>
                    <td className={td}>{pct(v.coverage_all)}</td><td className={td}>{pct(v.coverage_malicious)}</td><td className={td}>{pct(v.coverage_benign)}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
          <div>
            <SectionHeader title="Availability by source and label" />
            <table className="w-full text-sm border border-surface-700/50">
              <thead className="bg-surface-800/50"><tr>{['Source | label', 'Flows', 'TLS handshake', 'JA3', 'JA4', 'Neither', 'Truncated-CH fingerprints'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
              <tbody className="divide-y divide-surface-700/50">
                {Object.entries<any>(c.by_source_and_label ?? {}).map(([k, v]) => (
                  <tr key={k} className="font-mono text-xs"><td className={td}>{k}</td><td className={td}>{v.flows.toLocaleString()}</td><td className={td}>{v.tls_handshake_flows.toLocaleString()}</td>
                    <td className={td}>{v.ja3_computable.toLocaleString()} ({pct(v.ja3_rate)})</td><td className={td}>{v.ja4_computable.toLocaleString()} ({pct(v.ja4_rate)})</td>
                    <td className={td}>{v.neither.toLocaleString()}</td><td className={td}>{v.fingerprints_from_truncated_clienthello}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="text-xs text-etth-text/60 border-l-2 border-warning/50 bg-warning/5 px-4 py-3">
            Fingerprint overlap between classes — JA3: {c.fingerprint_overlap?.ja3?.distinct_shared} shared of {c.fingerprint_overlap?.ja3?.distinct_values} distinct values;
            JA4: {c.fingerprint_overlap?.ja4?.distinct_shared} shared of {c.fingerprint_overlap?.ja4?.distinct_values}. Zero overlap means fingerprints identify the
            client stack of each source; it is not evidence that they identify maliciousness.
          </div>
        </div>
      )}
    </DocGate>
  )
}

// -------------------------------------------------------------------- benchmarks --
function ContrastTable({ contrasts }: { contrasts: PairedContrast[] }) {
  return (
    <table className="w-full text-sm border border-surface-700/50">
      <thead className="bg-surface-800/50"><tr>{['Contrast', 'Shared rows', 'AP A', 'AP B', 'Δ AP [95% CI]', 'Holm p', 'Interpretation'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
      <tbody className="divide-y divide-surface-700/50">
        {contrasts.map((c) => (
          <tr key={c.contrast} className="text-xs">
            <td className={td}>{c.contrast}<div className="font-mono text-etth-text/40">{c.track_a} → {c.track_b}</div></td>
            <td className={`${td} font-mono`}>{c.shared_rows?.toLocaleString() ?? '—'}</td>
            <td className={`${td} font-mono`}>{fmt(c.average_precision?.metric_a)}</td>
            <td className={`${td} font-mono`}>{fmt(c.average_precision?.metric_b)}</td>
            <td className={`${td} font-mono`}>{fmt(c.average_precision?.difference)} [{fmt(c.average_precision?.ci_low)}, {fmt(c.average_precision?.ci_high)}]</td>
            <td className={`${td} font-mono`}>{fmt(c.holm?.p_holm)}</td>
            <td className={td}>{c.interpretation ?? c.status}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function BenchmarksTab() {
  const res = useResource<LatestBenchmarks>(etthApi.research.latestBenchmarks)
  const names = useMemo(() => Object.keys(res.data?.suites ?? {}), [res.data])
  const [selected, setSelected] = useState<string>('')
  useEffect(() => { if (!selected && names.length) setSelected(names.includes('pooled_capture_cv') ? 'pooled_capture_cv' : names[0]) }, [names, selected])
  if (res.loading) return <LoadingState message="Loading benchmark results..." />
  if (res.error) return <ErrorState message={res.error} onRetry={res.reload} />
  const entry = res.data?.suites[selected]
  const rows: BenchmarkRow[] = entry?.summary?.experiments ?? []
  return (
    <div className="space-y-6">
      <div className="border-l-2 border-warning/50 bg-warning/5 px-4 py-3 text-xs text-etth-text/80">
        All suites are <b>EXPLORATORY</b>. Confirmatory evaluation: <Badge variant="danger">{res.data?.confirmatory_policy.status}</Badge> — {res.data?.confirmatory_policy.reason}
      </div>
      <div className="flex flex-wrap gap-2 items-center">
        {names.map((n) => (
          <Button key={n} size="sm" variant={n === selected ? 'default' : 'secondary'} onClick={() => setSelected(n)}>{n}</Button>
        ))}
        {(res.data?.not_run ?? []).map((n) => <Badge key={n} variant="info">{n}: NOT_RUN</Badge>)}
      </div>
      {!entry ? <EmptyState title="NOT_RUN" description="No completed suite yet. Submit one from the Jobs tab." /> : (
        <>
          <div className="text-xs text-etth-text/50 font-mono">
            suite {entry.suite.suite_id} · {entry.suite.status} · population {entry.suite.evaluation_population ? JSON.stringify(entry.suite.evaluation_population.rows_by_dataset) : '—'}
          </div>
          {rows.length > 0 && (
            <div className="border border-surface-700/50 rounded-sm overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-surface-800/50 border-b border-surface-700/50">
                  <tr>{['Track', 'Model', 'Enc.', 'Status', 'Pos / Neg', 'AP [95% CI]', 'CI status', 'ROC-AUC', 'Recall @ val-FPR 1%', 'Test FPR', 'ECE', 'ms/flow'].map((h) => <th key={h} className={th}>{h}</th>)}</tr>
                </thead>
                <tbody className="divide-y divide-surface-700/50">
                  {rows.map((r) => (
                    <tr key={r.experiment_id} className="text-xs font-mono">
                      <td className={td}>{r.track}</td><td className={td}>{r.model}</td><td className={td}>{r.encoding}</td>
                      <td className={td}><Badge variant={stateVariant(r.status)}>{r.status}</Badge>{r.error && <div className="text-danger/70 max-w-xs whitespace-normal">{r.error}</div>}</td>
                      <td className={td}>{r.n_pos ?? '—'} / {r.n_neg ?? '—'}</td>
                      <td className={td}>{fmt(r.average_precision)} [{fmt(r.ap_ci?.[0])}, {fmt(r.ap_ci?.[1])}]</td>
                      <td className={td}>{r.ap_ci_status ? <Badge variant={stateVariant(r.ap_ci_status)}>{r.ap_ci_status}</Badge> : '—'}</td>
                      <td className={td}>{fmt(r.roc_auc)}</td><td className={td}>{pct(r['recall_at_val_fpr_0.01'])}</td>
                      <td className={td}>{pct(r['test_fpr_at_val_fpr_0.01'])}</td><td className={td}>{fmt(r.ece_15bin)}</td><td className={td}>{fmt(r.latency_ms_per_flow, 4)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {entry.summary?.paired_contrasts && Object.entries(entry.summary.paired_contrasts).map(([model, fam]) => (
            <div key={model}>
              <SectionHeader title={`Paired incremental-value contrasts · ${model}`} description="Same rows, same folds; capture-level paired bootstrap; Holm over 4 pre-declared contrasts." />
              <ContrastTable contrasts={fam.contrasts} />
            </div>
          ))}
          {entry.summary?.contrasts && (
            <div>
              <SectionHeader title="Sequence vs tabular contrasts" />
              <ContrastTable contrasts={entry.summary.contrasts} />
            </div>
          )}
          {entry.summary?.models && (
            <table className="w-full text-sm border border-surface-700/50">
              <thead className="bg-surface-800/50"><tr>{['Model', 'Status', 'AP', 'AP CI', 'Recall @ val-FPR 1%', 'Test FPR', 'Fit s (mean)', 'Params'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
              <tbody className="divide-y divide-surface-700/50">
                {Object.entries<any>(entry.summary.models).map(([m, v]) => (
                  <tr key={m} className="text-xs font-mono"><td className={td}>{m}</td><td className={td}>{v.status}</td><td className={td}>{fmt(v.average_precision)}</td>
                    <td className={td}>[{fmt(v.ap_bootstrap?.ci_low)}, {fmt(v.ap_bootstrap?.ci_high)}] {v.ap_bootstrap?.status}</td>
                    <td className={td}>{pct(v['recall_at_val_fpr_0.01'])}</td><td className={td}>{pct(v['test_fpr_at_val_fpr_0.01'])}</td>
                    <td className={td}>{fmt(v.cost?.fit_seconds_mean?.mean, 1)}</td><td className={td}>{v.cost?.parameters ?? '—'}</td></tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  )
}

// ------------------------------------------------------------------------ models --
function ModelsTab() {
  const reg = useResource<ModelRegistryView>(etthApi.research.models)
  const inf = useResource<InferenceStatus>(etthApi.research.inference, 5000)
  const [msg, setMsg] = useState<string | null>(null)
  const act = async (modelId: string, version: number) => {
    const reason = window.prompt(`Reason for activating ${modelId} v${version}?`)
    if (!reason) return
    try { await etthApi.research.activate(modelId, version, reason); setMsg(`Activated ${modelId} v${version}`); reg.reload(); inf.reload() }
    catch (e) { setMsg(e instanceof Error ? e.message : String(e)) }
  }
  const rollback = async (track: string) => {
    try { await etthApi.research.rollback(track); setMsg(`Rolled back ${track}`); reg.reload(); inf.reload() }
    catch (e) { setMsg(e instanceof Error ? e.message : String(e)) }
  }
  if (reg.loading) return <LoadingState message="Loading model registry..." />
  if (reg.error) return <ErrorState message={reg.error} onRetry={reg.reload} />
  return (
    <div className="space-y-8">
      {msg && <div className="text-xs text-etth-text/70 border border-surface-700 px-3 py-2">{msg}</div>}
      <div>
        <SectionHeader title="Live inference status" description="Operational metrics measured in the API process (not model quality)." />
        {inf.data ? (
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
            {Object.entries(inf.data.tracks).map(([t, s]) => (
              <div key={t} className="border border-surface-700/50 rounded-sm p-3">
                <div className="text-xs font-mono text-etth-text">{t}</div>
                <Badge variant={stateVariant(s.status)}>{s.status}</Badge>
                <div className="text-[11px] text-etth-text/50 mt-1 font-mono">{s.model_id ? `${s.model_id} v${s.version}` : ''}{s.error ? ` ${s.error}` : ''}</div>
                {s.status === 'LOADED' && <Button size="sm" variant="ghost" className="mt-2" onClick={() => rollback(t)}>Roll back</Button>}
              </div>
            ))}
            <div className="md:col-span-5 text-xs font-mono text-etth-text/60">
              requests {inf.data.metrics.total_requests} · latency p50 {fmt(inf.data.metrics.latency_ms.p50, 3)} ms · p95 {fmt(inf.data.metrics.latency_ms.p95, 3)} ms · skips {JSON.stringify(inf.data.metrics.skip_reasons)}
            </div>
          </div>
        ) : <LoadingState />}
      </div>
      <div>
        <SectionHeader title="Registered model versions" description="Artefacts are pickle-free and checksum-pinned; one ACTIVE version per track." />
        {reg.data && reg.data.models.length === 0 ? <EmptyState title="No registered models" description="Train one with: python -m ml train-deployable --suite-id <ID> --track <TRACK> --model random_forest" /> : (
          <table className="w-full text-sm border border-surface-700/50">
            <thead className="bg-surface-800/50"><tr>{['Model', 'Ver.', 'Track', 'Status', 'Research status', 'Calibration', 'Threshold (FPR≤1%)', 'Training rows', ''].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
            <tbody className="divide-y divide-surface-700/50">
              {reg.data?.models.map((m) => (
                <tr key={`${m.model_id}:${m.version}`} className="text-xs">
                  <td className={`${td} font-mono`}>{m.model_id}</td><td className={td}>{m.version}</td><td className={`${td} font-mono`}>{m.track}</td>
                  <td className={td}><Badge variant={stateVariant(m.status)}>{m.status}</Badge></td><td className={td}>{m.research_status}</td>
                  <td className={td}>{m.calibration?.status ?? '—'}</td><td className={`${td} font-mono`}>{fmt(m.thresholds?.['fpr<=0.01'] ?? null, 4)}</td>
                  <td className={`${td} font-mono`}>{m.training?.rows?.toLocaleString() ?? '—'}</td>
                  <td className={td}>{m.status !== 'ACTIVE' && <Button size="sm" variant="secondary" onClick={() => act(m.model_id, m.version)}>Activate</Button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

// -------------------------------------------------------------------------- jobs --
const SUITE_NAMES = ['pooled_capture_cv', 'matched_lab_capture_cv', 'leave_one_source_out', 'leave_one_family_out', 'legacy_behavioral_holdout', 'encoding_ablation', 'source_identifiability']

function JobsTab() {
  const jobs = useResource<JobRecord[]>(etthApi.research.jobs, 3000)
  const [type, setType] = useState<JobType>('coverage')
  const [suite, setSuite] = useState(SUITE_NAMES[0])
  const [msg, setMsg] = useState<string | null>(null)
  const [logs, setLogs] = useState<{ id: string; lines: string[] } | null>(null)
  const submit = async () => {
    const params = type === 'benchmark_suite' ? { suite, n_boot: 1000 } : type === 'sequence_suite' ? { epochs: 30 } : {}
    try { const j = await etthApi.research.submitJob(type, params); setMsg(`Submitted ${j.job_id}`); jobs.reload() }
    catch (e) { setMsg(e instanceof Error ? e.message : String(e)) }
  }
  const showLogs = async (id: string) => {
    try { const l = await etthApi.research.jobLogs(id, 200); setLogs({ id, lines: l.lines }) }
    catch (e) { setMsg(e instanceof Error ? e.message : String(e)) }
  }
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end gap-3 border border-surface-700/50 rounded-sm p-3">
        <label className="text-xs text-etth-text/60">Job type
          <select className="block mt-1 bg-surface-800 border border-surface-600 rounded-sm px-2 py-1 text-sm" value={type} onChange={(e) => setType(e.target.value as JobType)}>
            {['coverage', 'benchmark_suite', 'sequence_suite', 'report', 'corpus_admission', 'replay_set'].map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>
        {type === 'benchmark_suite' && (
          <label className="text-xs text-etth-text/60">Suite
            <select className="block mt-1 bg-surface-800 border border-surface-600 rounded-sm px-2 py-1 text-sm" value={suite} onChange={(e) => setSuite(e.target.value)}>
              {SUITE_NAMES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
        )}
        <Button onClick={submit}>Submit job</Button>
        <span className="text-xs text-etth-text/50">Jobs run as separate low-priority processes, one at a time; live detection is not blocked.</span>
      </div>
      {msg && <div className="text-xs text-etth-text/70">{msg}</div>}
      {jobs.loading ? <LoadingState /> : jobs.error ? <ErrorState message={jobs.error} onRetry={jobs.reload} /> : (jobs.data ?? []).length === 0 ? <EmptyState title="No jobs yet" /> : (
        <table className="w-full text-sm border border-surface-700/50">
          <thead className="bg-surface-800/50"><tr>{['Job', 'Type', 'Params', 'Status', 'Progress', 'Started', 'Finished', 'Result', ''].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
          <tbody className="divide-y divide-surface-700/50">
            {jobs.data!.map((j) => (
              <tr key={j.job_id} className="text-xs">
                <td className={`${td} font-mono`}>{j.job_id}</td><td className={td}>{j.type}</td><td className={`${td} font-mono`}>{JSON.stringify(j.params)}</td>
                <td className={td}><Badge variant={stateVariant(j.status)}>{j.status}</Badge></td>
                <td className={td}>{j.progress === null ? '—' : pct(j.progress)}<div className="text-etth-text/40 max-w-xs truncate">{j.progress_detail}</div></td>
                <td className={`${td} font-mono`}>{j.started_at ?? '—'}</td><td className={`${td} font-mono`}>{j.finished_at ?? '—'}</td>
                <td className={td}>{j.error ? <span className="text-danger/80">{j.error}</span> : (j.artifacts?.suite_id ?? '—')}</td>
                <td className={`${td} whitespace-nowrap`}>
                  <Button size="sm" variant="ghost" onClick={() => showLogs(j.job_id)}>Logs</Button>
                  {(j.status === 'QUEUED' || j.status === 'RUNNING') && <Button size="sm" variant="danger" onClick={() => etthApi.research.cancelJob(j.job_id).then(jobs.reload)}>Cancel</Button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {logs && (
        <div>
          <SectionHeader title={`Log tail · ${logs.id}`} actions={<Button size="sm" variant="ghost" onClick={() => setLogs(null)}>Close</Button>} />
          <pre className="text-[11px] bg-surface-900 border border-surface-700 p-3 max-h-80 overflow-auto whitespace-pre-wrap">{logs.lines.join('\n') || '(empty)'}</pre>
        </div>
      )}
    </div>
  )
}

// ------------------------------------------------------------------------ claims --
function ClaimsTab() {
  const claims = useResource<ResearchDocument>(etthApi.research.claims)
  if (claims.loading) return <LoadingState message="Loading claim ledger..." />
  if (claims.error) return <ErrorState message={claims.error} onRetry={claims.reload} />
  return (
    <DocGate doc={claims.data}>
      {(c) => (
        <table className="w-full text-sm border border-surface-700/50">
          <thead className="bg-surface-800/50"><tr>{['ID', 'Claim', 'Status', 'Evidence', 'Limitations'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
          <tbody className="divide-y divide-surface-700/50">
            {(c.claims ?? []).map((cl: any) => (
              <tr key={cl.claim_id} className="text-xs">
                <td className={`${td} font-mono`}>{cl.claim_id}</td><td className={`${td} max-w-md`}>{cl.claim}</td>
                <td className={td}><Badge variant={stateVariant(cl.status)}>{cl.status}</Badge></td>
                <td className={`${td} max-w-md text-etth-text/60`}>{cl.evidence_summary}</td>
                <td className={`${td} max-w-sm text-etth-text/50`}>{(cl.limitations ?? []).join(' · ')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </DocGate>
  )
}

export default function ResearchWorkbench() {
  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <PageHeader title="Research Workbench" description="Phases 8–10: corpus admission, fingerprint coverage, benchmarks, model registry, jobs and claims — all from persisted artefacts." />
      <Tabs defaultValue="corpus">
        <TabsList>
          <TabsTrigger value="corpus">Corpus</TabsTrigger>
          <TabsTrigger value="coverage">Coverage</TabsTrigger>
          <TabsTrigger value="benchmarks">Benchmarks</TabsTrigger>
          <TabsTrigger value="models">Models</TabsTrigger>
          <TabsTrigger value="jobs">Jobs</TabsTrigger>
          <TabsTrigger value="claims">Claims</TabsTrigger>
        </TabsList>
        <TabsContent value="corpus"><CorpusTab /></TabsContent>
        <TabsContent value="coverage"><CoverageTab /></TabsContent>
        <TabsContent value="benchmarks"><BenchmarksTab /></TabsContent>
        <TabsContent value="models"><ModelsTab /></TabsContent>
        <TabsContent value="jobs"><JobsTab /></TabsContent>
        <TabsContent value="claims"><ClaimsTab /></TabsContent>
      </Tabs>
    </div>
  )
}
