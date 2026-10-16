from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

JobType = Literal["benchmark_suite", "sequence_suite", "coverage", "report", "corpus_admission", "replay_set"]
JobStatus = Literal["QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"]
DocumentStatus = Literal["AVAILABLE", "NOT_RUN", "NOT_AVAILABLE"]


class ResearchDocument(BaseModel):
    """Envelope for persisted research artefacts served verbatim from disk."""
    status: DocumentStatus
    source: Optional[str] = None
    generated_at: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    detail: Optional[str] = None


class DatasetSummary(BaseModel):
    dataset_id: str
    name: str
    state: str
    access_category: str
    license: Any = None
    composition: Any = None
    flow_count: Any = None
    research_role: Any = None
    exclusion_reasons: List[str] = []
    last_transition: Optional[Dict[str, Any]] = None


class SuiteSummary(BaseModel):
    suite_id: str
    name: str
    phase: str
    stage: str
    status: str
    created_at: Optional[str] = None
    finished_at: Optional[str] = None
    experiments: int = 0
    statuses: Dict[str, int] = {}
    evaluation_population: Optional[Dict[str, Any]] = None


class JobCreateRequest(BaseModel):
    type: JobType
    params: Dict[str, Any] = Field(default_factory=dict)


class JobRecord(BaseModel):
    job_id: str
    type: JobType
    params: Dict[str, Any]
    status: JobStatus
    created_at: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    progress: Optional[float] = None
    progress_detail: Optional[str] = None
    exit_code: Optional[int] = None
    error: Optional[str] = None
    artifacts: Dict[str, Any] = {}
    resources: Dict[str, Any] = {}


class JobLog(BaseModel):
    job_id: str
    lines: List[str]
    truncated: bool


class ActivateRequest(BaseModel):
    reason: str = Field(min_length=5, max_length=500)


class ModelVersion(BaseModel):
    model_id: str
    version: int
    track: str
    estimator: str
    status: str
    research_status: Optional[str] = None
    created_at: Optional[str] = None
    calibration: Dict[str, Any] = {}
    thresholds: Dict[str, Any] = {}
    training: Dict[str, Any] = {}
    evaluation: Dict[str, Any] = {}
    feature_schema: Dict[str, Any] = {}
    limitations: List[str] = []
    artifact: Dict[str, Any] = {}
    missing_feature_policy: Optional[str] = None


class ModelRegistryView(BaseModel):
    models: List[ModelVersion]
    activation_history: List[Dict[str, Any]]
    active_by_track: Dict[str, str]
