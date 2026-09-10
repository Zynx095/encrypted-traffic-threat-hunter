import type { PilotSummary, PilotFoldResult, Phase6Audit, ExperimentalManifest, ModelSafeFlow, BehavioralFeature, DatasetRegistryEntry, FingerprintStats } from '../types/api'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

async function request<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`)
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

  datasets: {
    registry: async (): Promise<DatasetRegistryEntry[]> => {
      const fs = await import('../data/datasetRegistry')
      return fs.default
    },
  },
}