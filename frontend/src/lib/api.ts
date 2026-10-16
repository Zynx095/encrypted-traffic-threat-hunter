import type { 
  PilotSummary, 
  PilotFoldResult, 
  Phase6Audit, 
  ExperimentalManifest, 
  ModelSafeFlow, 
  BehavioralFeature, 
  DatasetRegistryEntry, 
  FingerprintStats, 
  LiveCaptureStatusResponse,
  Target,
  CreateTargetRequest,
  UpdateTargetRequest,
  Session,
  CreateSessionRequest
} from '../types/api'
import type {
  DatasetSummary,
  InferenceStatus,
  JobRecord,
  JobType,
  LatestBenchmarks,
  ModelRegistryView,
  ResearchDocument,
  SuiteSummary,
} from '../types/research'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, options)
  if (!response.ok) {
    let detail = ''
    try {
      const body = await response.json()
      detail = typeof body?.detail === 'string' ? `: ${body.detail}` : ''
    } catch {
      detail = ''
    }
    throw new Error(`API error: ${response.status} ${response.statusText}${detail}`)
  }
  return response.json()
}

const json = (body: unknown): RequestInit => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

export const etthApi = {
  health: () => request<{ status: string; service: string }>('/api/health'),
  
  pilot: {
    summary: async () => {
      const data = await request<Record<string, any>>('/api/pilot/summary')
      return Object.entries(data).map(([key, value]) => {
        let bestPr = 0
        let bestModel = 'N/A'
        if (value.models) {
          for (const [mName, mData] of Object.entries<any>(value.models)) {
            if (mData.avg_pr_auc > bestPr) {
              bestPr = mData.avg_pr_auc
              bestModel = mName
            }
          }
        }
        return {
          experiment: key,
          description: key.split('_').slice(1).join(' ').toUpperCase(),
          samples: value.sample_count,
          features: value.feature_count,
          best_avg_pr_auc: bestPr,
          best_model: bestModel
        } as PilotSummary
      })
    },
    foldResults: () => request<PilotFoldResult[]>('/api/pilot/fold-results'),
  },

  manifests: {
    phase6Audit: () => request<Phase6Audit>('/api/manifests/phase6-audit'),
    experimental: () => request<ExperimentalManifest>('/api/manifests/experimental'),
    statisticalAudit: () => request<Record<string, unknown>>('/api/manifests/statistical-audit'),
  },

  flows: {
    modelSafe: (limit = 100, offset = 0) => 
      request<{ total: number; limit: number; offset: number; flows: ModelSafeFlow[] }>(
        `/api/flows/model-safe?limit=${limit}&offset=${offset}`
      ),
    behavioral: (limit = 100, offset = 0) => 
      request<{ total: number; limit: number; offset: number; features: BehavioralFeature[] }>(
        `/api/flows/behavioral?limit=${limit}&offset=${offset}`
      ),
    search: (params: Record<string, string | number>) => {
      const query = new URLSearchParams(params as any).toString()
      return request<{ total: number; limit: number; offset: number; features: BehavioralFeature[] }>(
        `/api/flows/behavioral?${query}`
      )
    },
    getById: (id: string) => request<BehavioralFeature>(`/api/flows/behavioral/${id}`),
  },

  fingerprints: {
    getStats: (type: string = 'ja3') => request<FingerprintStats[]>(`/api/fingerprints/stats?fp_type=${type}`),
    getByHash: (type: string, hash: string) => request<FingerprintStats>(`/api/fingerprints/${type}/${hash}`),
  },

  liveStream: {
    interfaces: () => request<LiveCaptureStatusResponse>('/api/live-stream/interfaces'),
    status: () => request<LiveCaptureStatusResponse>('/api/live-stream/status'),
  },

  targets: {
    list: (includeDisabled = false) => request<Target[]>(`/api/targets?include_disabled=${includeDisabled}`),
    create: (data: CreateTargetRequest) => request<Target>('/api/targets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    }),
    get: (targetId: string) => request<Target>(`/api/targets/${targetId}`),
    update: (targetId: string, data: UpdateTargetRequest) => request<Target>(`/api/targets/${targetId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    }),
    delete: (targetId: string) => request<{ status: string; target_id: string; disabled: boolean }>(`/api/targets/${targetId}`, {
      method: 'DELETE',
    }),
  },

  dns: {
    addObservation: (data: { hostname: string; resolved_ip: string; ttl?: number; source?: string }) =>
      request<{ status: string; hostname: string; resolved_ip: string }>('/api/dns/observations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      }),
  },

  sessions: {
    list: () => request<Session[]>('/api/sessions'),
    listByTarget: (targetId: string) => request<Session[]>(`/api/targets/${targetId}/sessions`),
    createForTarget: (targetId: string, data: CreateSessionRequest) => request<Session>(`/api/targets/${targetId}/sessions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    }),
    get: (sessionId: string) => request<Session>(`/api/sessions/${sessionId}`),
    stop: (sessionId: string) => request<Session>(`/api/sessions/${sessionId}/stop`, {
      method: 'POST',
    }),
  },

  datasets: {
    registry: async (): Promise<DatasetRegistryEntry[]> => {
      const fs = await import('../data/datasetRegistry')
      return fs.default
    },
  },

  research: {
    datasets: () => request<DatasetSummary[]>('/api/research/datasets'),
    dataset: (id: string) => request<Record<string, any>>(`/api/research/datasets/${encodeURIComponent(id)}`),
    admission: () => request<ResearchDocument>('/api/research/corpus/admission'),
    sufficiency: () => request<ResearchDocument>('/api/research/corpus/sufficiency'),
    governance: () => request<ResearchDocument>('/api/research/features/governance'),
    coverage: () => request<ResearchDocument>('/api/research/features/coverage'),
    suites: () => request<SuiteSummary[]>('/api/research/suites'),
    suite: (id: string) => request<Record<string, any>>(`/api/research/suites/${encodeURIComponent(id)}`),
    latestBenchmarks: () => request<LatestBenchmarks>('/api/research/benchmarks/latest'),
    models: () => request<ModelRegistryView>('/api/research/models'),
    activate: (modelId: string, version: number, reason: string) =>
      request<Record<string, any>>(`/api/research/models/${encodeURIComponent(modelId)}/versions/${version}/activate`, json({ reason })),
    rollback: (track: string) => request<Record<string, any>>(`/api/research/models/rollback/${encodeURIComponent(track)}`, { method: 'POST' }),
    inference: () => request<InferenceStatus>('/api/research/inference/status'),
    jobs: () => request<JobRecord[]>('/api/research/jobs'),
    submitJob: (type: JobType, params: Record<string, unknown> = {}) => request<JobRecord>('/api/research/jobs', json({ type, params })),
    cancelJob: (jobId: string) => request<JobRecord>(`/api/research/jobs/${encodeURIComponent(jobId)}/cancel`, { method: 'POST' }),
    jobLogs: (jobId: string, tail = 200) => request<{ job_id: string; lines: string[]; truncated: boolean }>(`/api/research/jobs/${encodeURIComponent(jobId)}/logs?tail=${tail}`),
    claims: () => request<ResearchDocument>('/api/research/claims'),
    report: () => request<ResearchDocument>('/api/research/reports/latest'),
  },
}
