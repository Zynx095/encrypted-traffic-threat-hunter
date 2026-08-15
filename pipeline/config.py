"""
Configuration for the Phase 6 pipeline.
"""
import os
from pathlib import Path

PIPELINE_VERSION = "0.1.0"
SCHEMA_VERSION = "1.0.0"

PROJECT_ROOT = Path(os.environ.get("ETTH_PROJECT_ROOT", Path(__file__).resolve().parent.parent))

RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"
SAMPLES_DS004_DIR = PROJECT_ROOT / "data" / "samples" / "ds004"
VERIFICATION_PCAPS_DIR = PROJECT_ROOT / "data" / "verification" / "pcaps"

INTERIM_DIR = PROJECT_ROOT / "data" / "interim"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
MODEL_SAFE_DIR = PROJECT_ROOT / "data" / "processed" / "model_safe"
MANIFEST_DIR = PROJECT_ROOT / "data" / "manifests"

FLOW_IDLE_TIMEOUT_SECONDS = 120
FLOW_MAX_DURATION_SECONDS = 3600
FLOW_MIN_PACKETS = 1

TLS_HANDSHAKE_CONTENT_TYPE = 22
TLS_CLIENTHELLO_TYPE = 1
TLS_SERVERHELLO_TYPE = 2

MAX_PACKET_SEQUENCE_LENGTH = 1000

MIN_FLOW_DURATION_SECONDS = 0.0
MAX_FLOW_DURATION_SECONDS = 7200
