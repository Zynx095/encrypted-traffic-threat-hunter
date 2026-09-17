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

export interface FlowDetails {
  flow_id: string
  protocol: 'TCP' | 'UDP'
  forward_endpoint: string
  reverse_endpoint: string
  duration: number
  total_packets: number
  total_bytes: number
  packets_per_second: number
  bytes_per_second: number
}

export interface TLSDetails {
  clienthello_present: boolean
  serverhello_present: boolean
  ja3_hash: string | null
  ja3s_hash: string | null
  ja4: string | null
  sni_present: boolean
  sni_value?: string | null
  alpn: string | null
}

export type ModelTrack = 'A_FLOW' | 'B_JA3' | 'C_JA4' | 'D_JA3_FLOW' | 'E_JA4_FLOW'

export interface DetectionDetails {
  prediction: 'MALICIOUS' | 'BENIGN' | 'UNKNOWN'
  threat_score: number
  model_name: string
  confidence: number
  track?: ModelTrack
  status?: 'COMPLETED' | 'SKIPPED' | 'ERROR'
  skip_reason?: string | null
  evidence?: string[]
  inference_type?: string
}

export interface ProvenanceDetails {
  dataset_id: string
  source_file: string | null
  label_ground_truth: string
  caveat: string
}

export type StreamState = 'IDLE' | 'PLAYING' | 'PAUSED' | 'COMPLETED' | 'STOPPED' | 'ERROR'

export interface StreamLifecycleMetadata {
  speed?: number
  threats_only?: boolean
  total_events?: number | null
  state?: StreamState
  error_message?: string | null
}

export interface StreamTelemetry {
  stream_id: string
  target_id?: string | null
  session_id?: string | null
  mode: 'REPLAY' | 'LIVE'
  source: string
  state: StreamState
  selected_track: ModelTrack
  playback_speed: number
  total_events: number
  processed_events: number
  flow_events: number
  malicious_events: number
  benign_events: number
  skipped_events: number
  error_events: number
  events_per_second: number | null
  elapsed_seconds: number
  progress_percentage: number
  connected_clients: number
  processing_duration_ms: number | null
  inference_duration_ms: number | null
}

export type EventType =
  | 'stream.started'
  | 'flow.detected'
  | 'stream.paused'
  | 'stream.resumed'
  | 'stream.completed'
  | 'stream.stopped'
  | 'stream.error'
  | 'stream.telemetry'

export type AttributionStatus = 'ATTRIBUTED' | 'PROBABLE' | 'UNKNOWN' | 'NOT_MATCHED'

export type EvidenceType =
  | 'SNI_EXACT'
  | 'SNI_SUBDOMAIN'
  | 'DNS_MATCH'
  | 'DESTINATION_IP_MATCH'
  | 'HOSTNAME_MATCH'
  | 'TARGET_METADATA_MATCH'
  | 'NO_EVIDENCE'
  | 'CONFLICTING_EVIDENCE'

export interface AttributionEvidence {
  type: EvidenceType
  value: string
  detail?: string | null
}

export interface TargetAttribution {
  status: AttributionStatus
  confidence: number
  target_id?: string | null
  evidence: AttributionEvidence[]
  resolver_version: string
}

export interface ETTHStreamEvent {
  event_id: string
  sequence: number
  timestamp: string
  stream_id: string
  target_id?: string | null
  session_id?: string | null
  source: string
  mode: 'REPLAY' | 'LIVE'
  event_type: EventType
  flow?: FlowDetails | null
  tls?: TLSDetails | null
  attribution?: TargetAttribution | null
  detection?: DetectionDetails | null
  provenance?: ProvenanceDetails | null
  metadata?: StreamLifecycleMetadata | null
  telemetry?: StreamTelemetry | null
}

export type WSClientMessage =
  | { action: 'START_REPLAY'; speed?: number; threats_only?: boolean; track?: ModelTrack; target_id?: string; session_id?: string }
  | { action: 'START_LIVE'; interface?: string; track?: ModelTrack; target_id?: string; session_id?: string }
  | { action: 'PAUSE_REPLAY' }
  | { action: 'RESUME_REPLAY' }
  | { action: 'SET_SPEED'; speed: number }
  | { action: 'SET_TRACK'; track: ModelTrack }
  | { action: 'STOP_REPLAY' }
  | { action: 'STOP_LIVE' }
  | { action: 'STOP_STREAM' }
  | { action: 'SELECT_INTERFACE'; interface: string }

export type CaptureStatus = 'CAPTURE_UNAVAILABLE' | 'READY' | 'CAPTURING' | 'STOPPED' | 'ERROR'

export interface NetworkInterface {
  id: string
  name: string
  win_name: string
  ip: string
}

export interface LiveCaptureStatusResponse {
  available: boolean
  status: CaptureStatus
  selected_interface?: string | null
  packets_observed: number
  active_flows: number
  finalized_flows: number
  capture_errors: number
  error_message?: string | null
  interfaces: NetworkInterface[]
}

export type TargetType = 'WEB' | 'CUSTOM' | string

export interface TargetLogo {
  type: string
  reference: string
}

export interface Target {
  target_id: string
  name: string
  hostname: string
  display_name: string
  target_type: TargetType
  logo?: TargetLogo | null
  aliases?: string[]
  enabled: boolean
  created_at: string
  metadata?: Record<string, unknown>
}

export interface CreateTargetRequest {
  hostname: string
  display_name?: string
  target_type?: TargetType
  logo?: TargetLogo
  aliases?: string[]
  metadata?: Record<string, unknown>
}

export interface UpdateTargetRequest {
  display_name?: string
  target_type?: TargetType
  logo?: TargetLogo
  aliases?: string[]
  enabled?: boolean
  metadata?: Record<string, unknown>
}

export type SessionStatus = 'CREATED' | 'ACTIVE' | 'PAUSED' | 'COMPLETED' | 'STOPPED' | 'ERROR'

export interface Session {
  session_id: string
  target_id: string
  status: SessionStatus
  started_at: string
  ended_at?: string | null
  source_mode: 'REPLAY' | 'LIVE'
  interface_id?: string | null
  flow_count: number
  threat_count: number
  approved_flow_count: number
  skipped_flow_count: number
  metadata?: Record<string, unknown>
}

export interface CreateSessionRequest {
  source_mode?: 'REPLAY' | 'LIVE'
  interface_id?: string
  metadata?: Record<string, unknown>
}