export interface PilotSummary {
  experiment: string
  description: string
  samples: number
  features: number
  best_avg_pr_auc: number
  best_model: string
}

export interface PilotFoldResult {
  precision: number
  recall: number
  f1: number
  balanced_accuracy: number
  pr_auc: number
  roc_auc: number
  confusion_matrix: string
  experiment: string
  model: string
  fold: number
  train_samples: number
  test_samples: number
}

export interface Phase6Audit {
  audit_version: string
  phase: number
  step: number
  audit_date: string
  test_count: number
  tests_passed: number
  tests_failed: number
  total_rows: number
  dataset_counts: {
    'DS-004': number
    'DS-008': number
  }
  fingerprint_counts: {
    JA3: number
    JA3S: number
    JA4: number
    TLS?: number
  }
  duplicate_counts: {
    exact_duplicates: number
    duplicate_groups: number
    cross_pcap: number
    cross_label: number
  }
  experiment_counts: {
    A: number
    B: number
    C: number
    D: number
    E: number
  }
  experiment_statuses: {
    A: string
    B: string
    C: string
    D: string
    E: string
  }
  leakage_status: string
  reproducibility_status: string
  engineering_readiness: string
  scientific_readiness: string
  phase6_status: string
}

export interface DuplicateStats {
  exact_duplicate_count: number
  duplicate_groups: number
  cross_pcap_duplicate_groups: number
  cross_label_duplicate_groups: number
}

export interface ExperimentalManifest {
  schema_version: string
  pipeline_version: string
  generated_at: string
  input_rows: number
  output_rows: number
  total_columns: number
  model_safe_columns: number
  excluded_columns: string[]
  duplicate_count: number
  missing_value_policy: string
  leakage_check: string
}

export interface ModelSafeFlow {
  model_safe_index: number
  label: string
  flow_duration: number
  total_packets: number
  total_bytes: number
  forward_packets: number
  reverse_packets: number
  forward_bytes: number
  reverse_bytes: number
  packets_per_second: number
  bytes_per_second: number
  packet_length_mean: number
  packet_length_std: number
  iat_mean: number
  iat_std: number
  ja3_hash: string | null
  ja3s_hash: string | null
  ja4: string | null
  tls_version: number | null
  [key: string]: unknown
}

export interface BehavioralFeature {
  model_safe_index: number
  label: string
  flow_id: string
  dataset_id: string
  source_file: string
  tls_version: number | null
  clienthello_present: boolean
  serverhello_present: boolean
  sni_present: boolean
  alpn_value: string | null
  ja3_hash: string | null
  ja3_string: string | null
  ja3s_hash: string | null
  ja3s_string: string | null
  ja4: string | null
  flow_duration: number
  total_packets: number
  total_bytes: number
  [key: string]: unknown
}

export interface DatasetRegistryEntry {
  dataset_id: string
  dataset_name: string
  publication_year: string
  source: string
  official_url: string
  paper_url: string
  raw_pcap: string
  bidirectional_pcap: string
  tls_versions: string
  tls_1_3: string
  quic: string
  clienthello_available: string
  serverhello_available: string
  ja3_available: string
  ja3_computable: string
  ja3s_computable: string
  ja4_available: string
  ja4_computable: string
  flow_features_available: string
  packet_lengths_available: string
  iat_available: string
  benign_traffic: string
  malware_traffic: string
  c2_traffic: string
  label_quality: string
  class_balance: string
  capture_environment: string
  temporal_information: string
  dataset_size: string
  license_or_access: string
  download_status: string
  verification_status: string
  planned_role: string
  suitability: string
  known_leakage: string
  known_limitations: string
  evidence_source: string
  notes: string
}

export interface FingerprintStats {
  hash: string
  type: string
  total_flows: number
  malicious_flows: number
  benign_flows: number
  datasets?: string[]
}

export interface LiveFlowEvent {
  event_id: string
  timestamp: string
  flow_id: string
  dataset_id?: string
  protocol: 'TCP' | 'UDP'
  forward_endpoint: string
  reverse_endpoint: string
  clienthello_present: boolean
  serverhello_present: boolean
  ja3_hash?: string | null
  ja3s_hash?: string | null
  ja4?: string | null
  sni_present: boolean
  alpn_value?: string | null
  duration: number
  total_packets: number
  total_bytes: number
  packets_per_second: number
  bytes_per_second: number
  prediction: 'MALICIOUS' | 'BENIGN' | 'UNKNOWN'
  threat_score: number
  model_name: string
  confidence: number
  label_ground_truth?: string
}

export type WSClientMessage =
  | { action: 'START_REPLAY'; speed?: number; threats_only?: boolean }
  | { action: 'PAUSE_REPLAY' }
  | { action: 'RESUME_REPLAY' }
  | { action: 'SET_SPEED'; speed: number }
  | { action: 'STOP_REPLAY' }

export type WSServerMessage =
  | { type: 'CONNECTED'; connection_id: string; state: string; speed: number }
  | { type: 'STREAM_STATE'; state: 'RUNNING' | 'PAUSED' | 'STOPPED'; speed: number; threats_only?: boolean }
  | { type: 'FLOW_EVENT'; data: LiveFlowEvent }
  | { type: 'ERROR'; message: string }