"""
Filesystem layout for Phase 8 corpus artefacts.

Small, human-reviewable metadata (registry, capture plan, manifests, reports) lives under
data/corpus/ and may be versioned. Raw captures live under data/raw/ and processed tables
under data/processed/, both of which are git-ignored by repository convention.
"""
from pathlib import Path

from pipeline import config

PROJECT_ROOT: Path = config.PROJECT_ROOT

CORPUS_DIR = PROJECT_ROOT / "data" / "corpus"
REGISTRY_PATH = CORPUS_DIR / "dataset_registry.json"
CAPTURE_PLAN_PATH = CORPUS_DIR / "capture_plan.json"
ARTIFACT_MANIFEST_PATH = CORPUS_DIR / "artifact_manifest.json"
VALIDATION_REPORT_PATH = CORPUS_DIR / "validation_report.json"
ADMISSION_REPORT_JSON = CORPUS_DIR / "admission_report.json"
ADMISSION_REPORT_MD = CORPUS_DIR / "admission_report.md"
SUFFICIENCY_REPORT_JSON = CORPUS_DIR / "sufficiency_assessment.json"

RAW_DIR = PROJECT_ROOT / "data" / "raw"
ACQUISITION_STAGING_DIR = RAW_DIR / "acquisition_staging"
ACQUISITION_LOG = ACQUISITION_STAGING_DIR / "acquisition_log.tsv"
EXTRACTED_DIR = RAW_DIR / "extracted"

PROCESSED_V3_DIR = PROJECT_ROOT / "data" / "processed" / "v3"
INTERIM_V3_DIR = PROJECT_ROOT / "data" / "interim" / "v3"
CORPUS_FEATURES_PATH = PROCESSED_V3_DIR / "corpus_flows.parquet"
CORPUS_PROVENANCE_PATH = PROCESSED_V3_DIR / "corpus_provenance.parquet"
CORPUS_MANIFEST_PATH = PROCESSED_V3_DIR / "corpus_manifest.json"


def rel(path: Path) -> str:
    """Repository-relative POSIX path, used in every persisted record."""
    try:
        return Path(path).resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError:
        return Path(path).as_posix()


def resolve(relative: str) -> Path:
    """Resolve a repository-relative path and refuse anything that escapes the repository."""
    candidate = (PROJECT_ROOT / relative).resolve()
    root = PROJECT_ROOT.resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"Path escapes repository root: {relative}")
    return candidate
