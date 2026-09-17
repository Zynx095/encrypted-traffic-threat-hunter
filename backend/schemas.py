from pydantic import BaseModel, Field
from typing import Optional, Literal

class FlowDetails(BaseModel):
    flow_id: str
    protocol: Literal["TCP", "UDP"] = "TCP"
    forward_endpoint: str
    reverse_endpoint: str
    duration: float = 0.0
    total_packets: int = 0
    total_bytes: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0

class TLSDetails(BaseModel):
    clienthello_present: bool = False
    serverhello_present: bool = False
    ja3_hash: Optional[str] = None
    ja3s_hash: Optional[str] = None
    ja4: Optional[str] = None
    sni_present: bool = False
    sni_value: Optional[str] = None
    alpn: Optional[str] = None

ModelTrack = Literal["A_FLOW", "B_JA3", "C_JA4", "D_JA3_FLOW", "E_JA4_FLOW"]

class DetectionDetails(BaseModel):
    prediction: Literal["MALICIOUS", "BENIGN", "UNKNOWN"] = "UNKNOWN"
    threat_score: float = 0.0
    model_name: str = "RandomForest"
    confidence: float = 0.0
    track: ModelTrack = "A_FLOW"
    status: Literal["COMPLETED", "SKIPPED", "ERROR"] = "COMPLETED"
    skip_reason: Optional[str] = None
    evidence: list[str] = []
    inference_type: str = "REAL_TIME_ENGINEERING_INFERENCE"

class ProvenanceDetails(BaseModel):
    dataset_id: str = "UNKNOWN"
    source_file: Optional[str] = None
    label_ground_truth: str = "UNKNOWN"
    caveat: str = "Source-confounding limitation: DS-008 malicious vs DS-004 benign split."

StreamState = Literal["IDLE", "PLAYING", "PAUSED", "COMPLETED", "STOPPED", "ERROR"]

class StreamLifecycleMetadata(BaseModel):
    speed: float = 1.0
    threats_only: bool = False
    total_events: Optional[int] = None
    state: StreamState = "STOPPED"
    error_message: Optional[str] = None

TargetType = Literal["WEB", "CUSTOM"]

class TargetLogo(BaseModel):
    type: str = "favicon"
    reference: str = ""

class Target(BaseModel):
    target_id: str
    name: str
    hostname: str
    display_name: str
    target_type: TargetType = "WEB"
    logo: Optional[TargetLogo] = None
    aliases: list[str] = []
    enabled: bool = True
    created_at: str
    metadata: Optional[dict] = {}

class CreateTargetRequest(BaseModel):
    hostname: str
    display_name: Optional[str] = None
    target_type: TargetType = "WEB"
    logo: Optional[TargetLogo] = None
    aliases: list[str] = []
    metadata: Optional[dict] = None

class UpdateTargetRequest(BaseModel):
    display_name: Optional[str] = None
    target_type: Optional[TargetType] = None
    logo: Optional[TargetLogo] = None
    aliases: Optional[list[str]] = None
    enabled: Optional[bool] = None
    metadata: Optional[dict] = None

AttributionStatus = Literal["ATTRIBUTED", "PROBABLE", "UNKNOWN", "NOT_MATCHED"]
EvidenceType = Literal[
    "SNI_EXACT",
    "SNI_SUBDOMAIN",
    "DNS_MATCH",
    "DESTINATION_IP_MATCH",
    "HOSTNAME_MATCH",
    "TARGET_METADATA_MATCH",
    "NO_EVIDENCE",
    "CONFLICTING_EVIDENCE"
]

class AttributionEvidence(BaseModel):
    type: EvidenceType
    value: str
    detail: Optional[str] = None

class TargetAttribution(BaseModel):
    status: AttributionStatus = "UNKNOWN"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    target_id: Optional[str] = None
    evidence: list[AttributionEvidence] = []
    resolver_version: str = "7.6.1"

SessionStatus = Literal["CREATED", "ACTIVE", "PAUSED", "COMPLETED", "STOPPED", "ERROR"]

class Session(BaseModel):
    session_id: str
    target_id: Optional[str] = None
    status: SessionStatus = "CREATED"
    started_at: str
    ended_at: Optional[str] = None
    source_mode: Literal["REPLAY", "LIVE"] = "REPLAY"
    interface_id: Optional[str] = None
    flow_count: int = 0
    threat_count: int = 0
    approved_flow_count: int = 0
    skipped_flow_count: int = 0
    metadata: Optional[dict] = {}

class CreateSessionRequest(BaseModel):
    target_id: Optional[str] = None
    source_mode: Literal["REPLAY", "LIVE"] = "REPLAY"
    interface_id: Optional[str] = None
    metadata: Optional[dict] = None

class StreamTelemetry(BaseModel):
    """
    Canonical Operational Telemetry for ETTH Stream & Replay Pipeline.
    Strictly operational engineering metrics; not scientific model performance metrics.
    """
    stream_id: str
    target_id: Optional[str] = None
    session_id: Optional[str] = None
    mode: Literal["REPLAY", "LIVE"] = "REPLAY"
    source: str = "DS-008"
    state: StreamState = "IDLE"
    selected_track: ModelTrack = "A_FLOW"
    playback_speed: float = 1.0
    total_events: int = 0
    processed_events: int = 0
    flow_events: int = 0
    malicious_events: int = 0
    benign_events: int = 0
    skipped_events: int = 0
    error_events: int = 0
    events_per_second: Optional[float] = None
    elapsed_seconds: float = 0.0
    progress_percentage: float = 0.0
    connected_clients: int = 0
    processing_duration_ms: Optional[float] = None
    inference_duration_ms: Optional[float] = None

EventType = Literal[
    "stream.started",
    "flow.detected",
    "stream.paused",
    "stream.resumed",
    "stream.completed",
    "stream.stopped",
    "stream.error",
    "stream.telemetry"
]

class ETTHStreamEvent(BaseModel):
    """
    Canonical Event Envelope for ETTH Real-Time Engine.
    All WebSocket events emitted to clients must conform to this schema.
    """
    event_id: str
    sequence: int = Field(ge=1)
    timestamp: str
    stream_id: str
    target_id: Optional[str] = None
    session_id: Optional[str] = None
    source: str = "DS-008"
    mode: Literal["REPLAY", "LIVE"] = "REPLAY"
    event_type: EventType
    
    flow: Optional[FlowDetails] = None
    tls: Optional[TLSDetails] = None
    attribution: Optional[TargetAttribution] = None
    detection: Optional[DetectionDetails] = None
    provenance: Optional[ProvenanceDetails] = None
    metadata: Optional[StreamLifecycleMetadata] = None
    telemetry: Optional[StreamTelemetry] = None

CaptureStatus = Literal["CAPTURE_UNAVAILABLE", "READY", "CAPTURING", "STOPPED", "ERROR"]

class NetworkInterface(BaseModel):
    id: str
    name: str
    win_name: str
    ip: str = "0.0.0.0"

class LiveCaptureStatusResponse(BaseModel):
    available: bool
    status: CaptureStatus
    selected_interface: Optional[str] = None
    packets_observed: int = 0
    active_flows: int = 0
    finalized_flows: int = 0
    capture_errors: int = 0
    error_message: Optional[str] = None
    interfaces: list[NetworkInterface] = []

