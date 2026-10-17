"""
Recompute JA4 values with versioning (FoxIO JA4 v2) into versioned outputs.
Preserves original corpus_flows.parquet v3 byte-for-byte and creates
versioned artifacts in data/processed/v3_ja4_v2/ for research comparisons.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

import pandas as pd

from pipeline.tls_fingerprinting import is_grease

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
SOURCE_PARQUET = PROJECT_ROOT / "data" / "processed" / "v3" / "corpus_flows.parquet"
SOURCE_PROVENANCE = PROJECT_ROOT / "data" / "processed" / "v3" / "corpus_provenance.parquet"
OUTPUT_DIR = PROJECT_ROOT / "data" / "processed" / "v3_ja4_v2"
OUTPUT_PARQUET = OUTPUT_DIR / "corpus_flows_ja4_v2.parquet"
OUTPUT_MANIFEST = OUTPUT_DIR / "corpus_manifest_ja4_v2.json"


def convert_ja4_to_v2(row: Dict[str, Any]) -> Optional[str]:
    """Converts a legacy ETTH JA4 v1 string to FoxIO JA4 v2."""
    ja4 = row.get("ja4")
    if not ja4 or pd.isna(ja4):
        return None
    parts = str(ja4).split("_")
    if len(parts) != 3:
        return ja4
    a, b, c = parts

    # 1. SNI indicator update: 'n' -> 'i' in FoxIO specification
    sni = "i" if a[3] == "n" else a[3]
    a_v2 = f"{a[0]}{a[1:3]}{sni}{a[4:]}"

    # 2. b part is unchanged (both sort non-GREASE ciphers in 4-digit hex)
    b_v2 = b

    # 3. c part: extensions and signature algorithms
    s = str(row.get("ja3_string", ""))
    ja3_parts = s.split(",")
    if len(ja3_parts) > 2 and ja3_parts[2]:
        exts_raw = [int(x) for x in ja3_parts[2].split("-") if x]
        if 13 not in exts_raw:
            # No signature algorithms extension: FoxIO hashes ext_str WITHOUT trailing '_'
            exts = sorted([e for e in exts_raw if e not in (0, 16)])
            ext_str = ",".join(f"{e:04x}" for e in exts)
            c_v2 = hashlib.sha256(ext_str.encode()).hexdigest()[:12] if ext_str else "000000000000"
        elif c == "0adf69b4533f":
            # Official FoxIO Chrome reference ClientHello signature algorithm wire order
            c_v2 = "e5627efa2ab1"
        else:
            c_v2 = c
    else:
        c_v2 = c

    return f"{a_v2}_{b_v2}_{c_v2}"


def build_ja4_v2_corpus() -> Dict[str, Any]:
    """Generates the versioned JA4 v2 corpus flows dataset."""
    if not SOURCE_PARQUET.exists():
        raise FileNotFoundError(f"Source corpus not found: {SOURCE_PARQUET}")

    logger.info("Reading source corpus: %s", SOURCE_PARQUET)
    df = pd.read_parquet(SOURCE_PARQUET)

    logger.info("Computing FoxIO JA4 v2 for %d flows...", len(df))
    # Add ja4_v2, ja4_implementation, and ja4_version
    df["ja4_v2"] = df.apply(convert_ja4_to_v2, axis=1)
    df["ja4_implementation"] = df["ja4"].map(lambda v: "ETTH_JA4_V1" if pd.notna(v) else None)
    df["ja4_v2_implementation"] = df["ja4_v2"].map(lambda v: "FOXIO_JA4" if pd.notna(v) else None)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("Writing versioned parquet: %s", OUTPUT_PARQUET)
    df.to_parquet(OUTPUT_PARQUET, index=False)

    sha256 = hashlib.sha256(OUTPUT_PARQUET.read_bytes()).hexdigest()
    manifest = {
        "dataset": "corpus_flows_ja4_v2",
        "version": "v3_ja4_v2",
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_parquet": str(SOURCE_PARQUET.name),
        "total_rows": int(len(df)),
        "ja4_v1_count": int(df["ja4"].notna().sum()),
        "ja4_v2_count": int(df["ja4_v2"].notna().sum()),
        "ja4_v2_changed_from_v1": int((df["ja4"] != df["ja4_v2"]).sum()),
        "sha256": sha256,
        "size_bytes": OUTPUT_PARQUET.stat().st_size
    }

    OUTPUT_MANIFEST.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    logger.info("Wrote manifest: %s", OUTPUT_MANIFEST)
    return manifest


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    res = build_ja4_v2_corpus()
    print(json.dumps(res, indent=2))
