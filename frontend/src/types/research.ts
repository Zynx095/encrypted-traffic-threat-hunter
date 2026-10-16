// Types for /api/research (Phases 8-10). Shapes mirror backend/research/schemas.py.

export type DocumentStatus = 'AVAILABLE' | 'NOT_RUN' | 'NOT_AVAILABLE'

export interface ResearchDocument<T = Record<string, any>> {
  status: DocumentStatus
  source: string | null
  generated_at: string | null
  data: T | null
  detail: string | null
}

export interface DatasetSummary {
  dataset_id: string
  name: string
  state: string
  access_category: string
  license: unknown
  composition: unknown
  flow_count: unknown
  research_role: unknown
  exclusion_reasons: string[]
  last_transition: { from_state: string | null; to_state: string; timestamp: string; evidence: string } | null
}

export interface SuiteSummary {
  suite_id: string
  name: string
  phase: string
  stage: string
  status: string
  created_at: string | null
  finished_at: string | null
  experiments: number
  statuses: Record<string, number>
  evaluation_population: Record<string, any> | null
}

export interface BenchmarkRow {
  experiment_id: string
  status: string
  error: string | null
  track: string
  model: string
  encoding: string
  protocol: string
  population_rows: number | null
  coverage: number | null
  n_pos: number | null
  n_neg: number | null
  average_precision: number | null
  ap_ci: [number | null, number | null]
  ap_ci_status: string | null
  roc_auc: number | null
  brier: number | null
  ece_15bin: number | null
  'recall_at_val_fpr_0.01': number | null
  'test_fpr_at_val_fpr_0.01': number | null
  per_source: Record<string, any> | null
  latency_ms_per_flow: number | null
}

export interface PairedContrast {
  contrast: string
  track_a: string
  track_b: string
  status: string
  shared_rows?: number
  average_precision?: { metric_a: number | null; metric_b: number | null; difference: number | null; ci_low: number | null; ci_high: number | null; p_value_bootstrap: number | null; status: string }
  holm?: { p: number | null; p_holm: number | null; reject: boolean | null } | null
  interpretation?: string
}

export interface LatestBenchmarks {
  suites: Record<string, { suite: SuiteSummary; summary: { experiments?: BenchmarkRow[]; paired_contrasts?: Record<string, { contrasts: PairedContrast[] }>; models?: Record<string, any>; contrasts?: PairedContrast[] } | null }>
  not_run: string[]
  confirmatory_policy: { status: string; rule: string; reason: string }
}

export type JobType = 'benchmark_suite' | 'sequence_suite' | 'coverage' | 'report' | 'corpus_admission' | 'replay_set'
export type JobStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED'

export interface JobRecord {
  job_id: string
  type: JobType
  params: Record<string, any>
  status: JobStatus
  created_at: string
  started_at: string | null
  finished_at: string | null
  progress: number | null
  progress_detail: string | null
  exit_code: number | null
  error: string | null
  artifacts: Record<string, any>
  resources: Record<string, any>
}

export interface ModelVersion {
  model_id: string
  version: number
  track: string
  estimator: string
  status: string
  research_status: string | null
  created_at: string | null
  calibration: Record<string, any>
  thresholds: Record<string, number | null>
  training: Record<string, any>
  evaluation: Record<string, any>
  feature_schema: Record<string, any>
  limitations: string[]
  artifact: Record<string, any>
  missing_feature_policy: string | null
}

export interface ModelRegistryView {
  models: ModelVersion[]
  activation_history: Array<Record<string, any>>
  active_by_track: Record<string, string>
}

export interface InferenceStatus {
  tracks: Record<string, { status: string; model_id?: string; version?: number; error?: string }>
  metrics: {
    total_requests: number
    by_status: Record<string, number>
    skip_reasons: Record<string, number>
    latency_ms: { n: number; p50: number | null; p95: number | null; p99: number | null; max: number | null }
  }
}
