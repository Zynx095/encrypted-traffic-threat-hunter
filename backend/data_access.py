"""
Cached, read-only access to research data tables for the API and the replay engine.

Preference order (first existing wins):
    replay:      data/processed/v3/replay_flows.parquet  (capture-balanced, provenance included)
                 data/processed/v2/model_safe/model_safe_dataset.parquet  (Stage 6.5)
                 data/processed/features/flows_behavioral_features.parquet (Phase 6)
    explorer:    same as replay (small enough to filter per request)
    fingerprint: column projection of the full corpus v3 (counts over all flows)

Tables are loaded once per process (thread-safe) and never modified.
"""
from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Dict, Optional, Tuple

import pandas as pd

logger = logging.getLogger(__name__)
BASE_DIR = Path(__file__).resolve().parent.parent

REPLAY_CANDIDATES = [
    BASE_DIR / "data" / "processed" / "v3" / "replay_flows.parquet",
    BASE_DIR / "data" / "processed" / "v2" / "model_safe" / "model_safe_dataset.parquet",
    BASE_DIR / "data" / "processed" / "features" / "flows_behavioral_features.parquet",
]
CORPUS_FLOWS = BASE_DIR / "data" / "processed" / "v3" / "corpus_flows.parquet"
CORPUS_PROVENANCE = BASE_DIR / "data" / "processed" / "v3" / "corpus_provenance.parquet"

_lock = threading.Lock()
_cache: Dict[str, Tuple[Optional[pd.DataFrame], Optional[str]]] = {}


def _first_existing():
    for p in REPLAY_CANDIDATES:
        if p.exists():
            return p
    return None


def _tag_historical_ja4(df: pd.DataFrame) -> pd.DataFrame:
    """Every replay candidate predates FoxIO JA4 in ETTH: its 'ja4' column is the historical ETTH
    implementation. Declare that explicitly, since inference refuses undeclared JA4 values."""
    if "ja4" in df.columns and "ja4_implementation" not in df.columns:
        from pipeline.canonical_flow import JA4_IMPLEMENTATION_ETTH, JA4_VERSION_ETTH_V1
        has = df["ja4"].notna()
        df = df.assign(ja4_implementation=has.map({True: JA4_IMPLEMENTATION_ETTH, False: None}),
                       ja4_version=has.map({True: JA4_VERSION_ETTH_V1, False: None}))
    return df


def replay_frame() -> Tuple[Optional[pd.DataFrame], Optional[str]]:
    """Returns (dataframe, source path) or (None, None) when no dataset exists."""
    with _lock:
        if "replay" not in _cache:
            path = _first_existing()
            df = None
            if path is not None:
                try:
                    df = _tag_historical_ja4(pd.read_parquet(path))
                    logger.info("Loaded %d replay rows from %s", len(df), path.name)
                except Exception as exc:
                    logger.error("Failed to read %s: %s", path, exc)
                    path = None
            _cache["replay"] = (df, str(path.relative_to(BASE_DIR).as_posix()) if path else None)
        return _cache["replay"]


def fingerprint_frame() -> Optional[pd.DataFrame]:
    with _lock:
        if "fingerprint" not in _cache:
            df = None
            if CORPUS_FLOWS.exists() and CORPUS_PROVENANCE.exists():
                f = pd.read_parquet(CORPUS_FLOWS, columns=["corpus_index", "label", "ja3_hash", "ja3s_hash", "ja4"])
                p = pd.read_parquet(CORPUS_PROVENANCE, columns=["corpus_index", "flow_id", "dataset_id"])
                df = f.merge(p, on="corpus_index")
            else:
                rdf, _ = _cache.get("replay", (None, None))
                df = rdf
            _cache["fingerprint"] = (df, None)
        return _cache["fingerprint"][0]


def clear_cache() -> None:
    with _lock:
        _cache.clear()
