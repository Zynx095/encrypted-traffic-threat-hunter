"""
Phase 8: dataset acquisition registry, provenance manifest, validation and corpus admission.

Modules:
    registry    -- dataset records and evidence-backed lifecycle transitions
    artifacts   -- per-file provenance manifest (raw / interim / processed tiers)
    extract     -- PCAP-only extraction from password-protected source archives
    capture_plan-- declarative list of captures that make up the research corpus
    validation  -- PCAP- and flow-level integrity checks
    builder     -- deterministic corpus construction reusing the Phase 6 pipeline
    admission   -- admission report and benign-corpus sufficiency assessment
"""
from pipeline.corpus.paths import CORPUS_DIR  # noqa: F401
