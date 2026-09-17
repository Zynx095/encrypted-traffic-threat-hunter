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

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, options)
  if (!response.ok) {
    throw new Error(`API error: ${response.status} ${response.statusText}`)
  }
  return response.json()
}

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
}