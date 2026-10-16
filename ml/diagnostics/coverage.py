"""
Fingerprint availability and attrition analysis (Phase 9.6) and dataset-shift diagnostics.

Fingerprint availability is part of the research problem: a JA3/JA4 model can only score
flows that carry a parsed ClientHello. This module reports, from the actual corpus:
    total / TLS-handshake / JA3-computable / JA4-computable / both / neither flows,
    broken down by source, label, transport protocol, TLS version and capture;
    fingerprints derived from ClientHellos truncated in the first segment;
    distinct fingerprint values per class and their overlap;
    the share of each class that every track can score (coverage loss).
"""
from __future__ import annotations

import datetime as _dt
from typing import Any, Dict

import numpy as np
import pandas as pd

from ml.features.governance import CANONICAL_TRACKS, TRACKS, population_mask
from pipeline.corpus.validation import fingerprint_overlap


def _block(part: pd.DataFrame) -> Dict[str, Any]:
    n = len(part)
    ch = part["clienthello_present"].fillna(False).astype(bool)
    sh = part["serverhello_present"].fillna(False).astype(bool)
    ja3 = part["ja3_hash"].notna()
    ja4 = part["ja4"].notna()
    trunc = part["clienthello_record_truncated"].fillna(False).astype(bool) if "clienthello_record_truncated" in part else pd.Series(False, index=part.index)
    return {
        "flows": int(n),
        "tls_handshake_flows": int((ch | sh).sum()),
        "clienthello_flows": int(ch.sum()),
        "ja3_computable": int(ja3.sum()),
        "ja4_computable": int(ja4.sum()),
        "both": int((ja3 & ja4).sum()),
        "neither": int((~ja3 & ~ja4).sum()),
        "ja3_rate": round(float(ja3.mean()), 6) if n else None,
        "ja4_rate": round(float(ja4.mean()), 6) if n else None,
        "fingerprints_from_truncated_clienthello": int((trunc & ja3).sum()),
        "truncated_share_of_fingerprints": round(float((trunc & ja3).sum() / max(int(ja3.sum()), 1)), 6),
    }


def coverage_report(df: pd.DataFrame) -> Dict[str, Any]:
    df = df.copy()
    df["binary_label"] = np.where(df["y"] == 1, "MALICIOUS", "BENIGN")
    df["tls_version_str"] = df["tls_version"].map(lambda v: "MISSING" if pd.isna(v) else str(v))
    out: Dict[str, Any] = {"generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z"),
                           "overall": _block(df)}
    for key, col in (("by_source", "dataset_id"), ("by_label", "binary_label"), ("by_protocol", "protocol"),
                     ("by_tls_version", "tls_version_str"), ("by_capture", "capture_id")):
        if col in df:
            out[key] = {str(k): _block(p) for k, p in df.groupby(col)}
    out["by_source_and_label"] = {f"{s}|{l}": _block(p) for (s, l), p in df.groupby(["dataset_id", "binary_label"])}
    out["fingerprint_overlap"] = {"ja3": fingerprint_overlap(df, "ja3_hash"), "ja4": fingerprint_overlap(df, "ja4")}
    out["track_coverage"] = {}
    for t in list(CANONICAL_TRACKS) + ["A0_FLOW_STRICT"]:
        m = population_mask(df, t)
        out["track_coverage"][t] = {
            "population": TRACKS[t].population,
            "rows": int(m.sum()),
            "coverage_all": round(float(m.mean()), 6),
            "coverage_malicious": round(float(m[df["y"].to_numpy() == 1].mean()), 6) if (df["y"] == 1).any() else None,
            "coverage_benign": round(float(m[df["y"].to_numpy() == 0].mean()), 6) if (df["y"] == 0).any() else None,
            "captures_with_rows": int(df.loc[m, "capture_id"].nunique()),
        }
    mal = df[df["y"] == 1]["ja4"].notna().mean() if (df["y"] == 1).any() else np.nan
    ben = df[df["y"] == 0]["ja4"].notna().mean() if (df["y"] == 0).any() else np.nan
    out["availability_asymmetry"] = {
        "ja4_rate_malicious": None if np.isnan(mal) else round(float(mal), 6),
        "ja4_rate_benign": None if np.isnan(ben) else round(float(ben), 6),
        "note": ("When fingerprint availability differs strongly between classes, presence flags and missingness "
                 "carry label information on their own; see the P_AVAILABILITY_PROBE results."),
    }
    return out


def shift_report(df: pd.DataFrame) -> Dict[str, Any]:
    """Distribution of key observables by source and label (dataset-shift / confounding diagnostics)."""
    df = df.copy()
    years = pd.to_datetime(df["collection_date"], errors="coerce").dt.year
    df["year"] = years
    out: Dict[str, Any] = {}
    out["collection_years_by_source"] = {s: sorted(set(int(y) for y in p["year"].dropna())) for s, p in df.groupby("dataset_id")}
    out["tls_version_share_by_source"] = {s: {str(k): round(float(v), 4) for k, v in p["tls_version"].value_counts(normalize=True, dropna=False).items()}
                                          for s, p in df.groupby("dataset_id")}
    out["protocol_share_by_source"] = {s: {str(k): round(float(v), 4) for k, v in p["protocol"].value_counts(normalize=True).items()}
                                       for s, p in df.groupby("dataset_id")} if "protocol" in df else {}
    num = ["flow_duration", "total_packets", "total_bytes", "packet_length_mean", "iat_mean"]
    out["median_by_source"] = {s: {c: (None if p[c].dropna().empty else float(p[c].median())) for c in num} for s, p in df.groupby("dataset_id")}
    out["flows_per_capture_by_source"] = {s: {"median": float(p.groupby("capture_id").size().median()),
                                              "min": int(p.groupby("capture_id").size().min()),
                                              "max": int(p.groupby("capture_id").size().max())} for s, p in df.groupby("dataset_id")}
    return out
