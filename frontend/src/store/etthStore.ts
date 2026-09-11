import { create } from 'zustand'
import { etthApi } from '../lib/api'
import type { PilotSummary, PilotFoldResult, Phase6Audit, ModelSafeFlow, BehavioralFeature, LiveFlowEvent } from '../types/api'

interface ETTHStore {
  // Pilot data
  pilotSummary: PilotSummary[] | null
  pilotResults: PilotFoldResult[] | null
  phase6Audit: Phase6Audit | null
  
  // Flow data
  modelSafeFlows: ModelSafeFlow[] | null
  behavioralFeatures: BehavioralFeature[] | null
  totalFlows: number
  totalBehavioralFeatures: number

  // Real-Time Stream State
  wsConnected: boolean
  latestLiveEvent: LiveFlowEvent | null
  liveThreatCount: number
  
  // Loading states
  loading: boolean
  error: string | null
  
  // Actions
  fetchPilotData: () => Promise<void>
  fetchPhase6Audit: () => Promise<void>
  fetchFlows: (limit?: number, offset?: number) => Promise<void>
  setWSConnected: (connected: boolean) => void
  addLiveEvent: (event: LiveFlowEvent) => void
  setLoading: (loading: boolean) => void
  setError: (error: string) => void
}

export const useETTHStore = create<ETTHStore>((set) => ({
  pilotSummary: null,
  pilotResults: null,
  phase6Audit: null,
  modelSafeFlows: null,
  behavioralFeatures: null,
  totalFlows: 0,
  totalBehavioralFeatures: 0,
  wsConnected: false,
  latestLiveEvent: null,
  liveThreatCount: 0,
  loading: false,
  error: null,

  fetchPilotData: async () => {
    set({ loading: true, error: null })
    try {
      const [summary, results] = await Promise.all([
        etthApi.pilot.summary(),
        etthApi.pilot.foldResults(),
      ])
      set({ pilotSummary: summary, pilotResults: results, loading: false })
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to fetch pilot data', loading: false })
    }
  },

  fetchPhase6Audit: async () => {
    set({ loading: true, error: null })
    try {
      const audit = await etthApi.manifests.phase6Audit()
      set({ phase6Audit: audit, loading: false })
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to fetch phase 6 audit', loading: false })
    }
  },

  fetchFlows: async (limit = 100, offset = 0) => {
    set({ loading: true, error: null })
    try {
      const [flowsResult, featuresResult] = await Promise.all([
        etthApi.flows.modelSafe(limit, offset),
        etthApi.flows.behavioral(limit, offset),
      ])
      set({
        modelSafeFlows: flowsResult.flows,
        behavioralFeatures: featuresResult.features,
        totalFlows: flowsResult.total,
        totalBehavioralFeatures: featuresResult.total,
        loading: false,
      })
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to fetch flows', loading: false })
    }
  },

  setWSConnected: (connected) => set({ wsConnected: connected }),
  addLiveEvent: (event) => set((state) => ({
    latestLiveEvent: event,
    liveThreatCount: event.prediction === 'MALICIOUS' ? state.liveThreatCount + 1 : state.liveThreatCount
  })),
  setLoading: (loading) => set({ loading }),
  setError: (error) => set({ error }),
}))