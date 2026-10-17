"""Recompute FoxIO JA4 for corpus v3 from the raw captures, as a new versioned side table.

    python -m pipeline.corpus.recompute_ja4_foxio [--raw-root DIR]

Why: corpus v3's ``ja4`` is the historical ETTH implementation (sorted signature algorithms and
other deviations). FoxIO's JA4 cannot be derived from the stored v1 strings or from the JA3
string, because the ClientHello's signature-algorithm wire order, its supported_versions values
and its first ALPN value are not stored. It must be recomputed from the ClientHello bytes.

How:
* Every included capture is re-read from its raw file, whose SHA-256 must equal the RAW record in
  data/corpus/artifact_manifest.json.
* Flows are reconstructed with corpus v3 semantics (``reassemble_tls=False``: 120 s idle timeout,
  FIN/RST split, first-segment ClientHello), so the n-th flow of a capture is corpus row
  ``capture_flow_index == n``.
* Alignment is *proved*, not assumed: the recomputed ETTH v1 ``ja4`` and ``ja3_hash`` must equal
  the stored corpus values for every row of the capture, or the capture is rejected.
* ``ja4_foxio`` comes from ``generate_ja4_foxio`` on the same parsed ClientHello. When v3 marked
  that ClientHello as truncated (first segment only), no FoxIO value is emitted (status
  ``INCOMPLETE_FIRST_SEGMENT``): a fingerprint of a partial ClientHello is not FoxIO JA4.

Outputs (git-ignored): data/processed/v3_ja4_foxio/ja4_foxio.parquet and manifest.json. Corpus v3
and the invalid data/processed/v3_ja4_v2/ table are left untouched.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import logging
import platform
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

from pipeline.canonical_flow import JA4_IMPLEMENTATION_FOXIO, JA4_VERSION_FOXIO
from pipeline.corpus import paths
from pipeline.corpus.builder import git_revision, reconstruct_capture
from pipeline.corpus.capture_plan import included
from pipeline.corpus.extract import sha256_file

logger = logging.getLogger(__name__)

OUTPUT_DIR = paths.PROJECT_ROOT / "data" / "processed" / "v3_ja4_foxio"
OUTPUT_TABLE = OUTPUT_DIR / "ja4_foxio.parquet"
OUTPUT_MANIFEST = OUTPUT_DIR / "manifest.json"
TABLE_VERSION = "v3_ja4_foxio-1"

STATUS_OK = "COMPUTED"
STATUS_NO_CH = "NO_CLIENTHELLO"
STATUS_TRUNCATED = "INCOMPLETE_FIRST_SEGMENT"


def _same(a: Any, b: Any) -> bool:
    na, nb = a is None or (isinstance(a, float) and a != a), b is None or (isinstance(b, float) and b != b)
    return (na and nb) or (not na and not nb and str(a) == str(b))


def _raw_hashes() -> Dict[str, str]:
    manifest = json.loads(paths.ARTIFACT_MANIFEST_PATH.read_text(encoding="utf-8"))
    return {a["capture_id"]: a["sha256"] for a in manifest["artifacts"] if a["tier"] == "RAW" and a.get("sha256")}


def recompute(raw_root: Path) -> Dict[str, Any]:
    plan = json.loads(paths.CAPTURE_PLAN_PATH.read_text(encoding="utf-8"))
    flows = pd.read_parquet(paths.CORPUS_FEATURES_PATH, columns=["corpus_index", "ja3_hash", "ja4"])
    prov = pd.read_parquet(paths.CORPUS_PROVENANCE_PATH, columns=["corpus_index", "capture_id", "capture_flow_index"])
    corpus = flows.merge(prov, on="corpus_index", validate="one_to_one")
    raw_sha = _raw_hashes()

    rows: List[Dict[str, Any]] = []
    captures: List[Dict[str, Any]] = []
    for cap in included(plan):
        cid = cap["capture_id"]
        part = corpus[corpus["capture_id"] == cid].sort_values("capture_flow_index")
        entry: Dict[str, Any] = {"capture_id": cid, "corpus_rows": int(len(part))}
        if part.empty:
            entry["status"] = "NOT_IN_CORPUS"
            captures.append(entry)
            continue
        raw = raw_root / cap["raw_path"]
        if not raw.exists():
            entry["status"] = "RAW_MISSING"
            captures.append(entry)
            continue
        digest = sha256_file(raw)
        entry["raw_sha256"] = digest
        if digest != raw_sha.get(cid):
            entry["status"] = "RAW_SHA256_MISMATCH"
            captures.append(entry)
            continue
        logger.info("Reconstructing %s (%d corpus rows)", cid, len(part))
        rec = reconstruct_capture(raw, digest, reassemble_tls=False)
        entry["reconstructed_flows"] = len(rec)
        mismatches = 0
        if len(rec) != len(part):
            entry["status"] = "FLOW_COUNT_MISMATCH"
            captures.append(entry)
            continue
        out = []
        for f, (_, row) in zip(rec, part.iterrows()):
            if not (_same(f.get("ja4"), row["ja4"]) and _same(f.get("ja3_hash"), row["ja3_hash"])):
                mismatches += 1
                continue
            if not f.get("clienthello_present"):
                status, value = STATUS_NO_CH, None
            elif f.get("clienthello_record_truncated"):
                status, value = STATUS_TRUNCATED, None
            else:
                status, value = STATUS_OK, f.get("ja4_v2")
            out.append({"corpus_index": int(row["corpus_index"]), "ja4_foxio": value, "ja4_foxio_status": status})
        entry["fingerprint_mismatches"] = mismatches
        if mismatches:
            entry["status"] = "ALIGNMENT_FAILED"
            captures.append(entry)
            continue
        entry["status"] = "ALIGNED"
        entry["ja4_foxio_values"] = sum(1 for r in out if r["ja4_foxio"] is not None)
        entry["truncated_withheld"] = sum(1 for r in out if r["ja4_foxio_status"] == STATUS_TRUNCATED)
        rows.extend(out)
        captures.append(entry)

    table = pd.DataFrame(rows, columns=["corpus_index", "ja4_foxio", "ja4_foxio_status"])
    table["ja4_implementation"] = table["ja4_foxio"].map(lambda v: JA4_IMPLEMENTATION_FOXIO if v else None)
    table["ja4_version"] = table["ja4_foxio"].map(lambda v: JA4_VERSION_FOXIO if v else None)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    table.to_parquet(OUTPUT_TABLE, index=False)

    complete = all(c["status"] == "ALIGNED" for c in captures if c["status"] != "NOT_IN_CORPUS")
    manifest = {
        "table": "ja4_foxio", "version": TABLE_VERSION, "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "complete": complete and len(table) == len(corpus),
        "ja4_implementation": JA4_IMPLEMENTATION_FOXIO, "ja4_version": JA4_VERSION_FOXIO,
        "reference_vectors": "data/reference/foxio_ja4/vectors.json",
        "semantics": "corpus v3 flows (reassemble_tls=False); FoxIO JA4 withheld for truncated first-segment ClientHellos",
        "inputs": {"corpus_flows_sha256": sha256_file(paths.CORPUS_FEATURES_PATH),
                   "corpus_provenance_sha256": sha256_file(paths.CORPUS_PROVENANCE_PATH),
                   "artifact_manifest_sha256": sha256_file(paths.ARTIFACT_MANIFEST_PATH)},
        "code": {"git_revision": git_revision(), "script": "pipeline.corpus.recompute_ja4_foxio",
                 "python": platform.python_version()},
        "rows": int(len(table)), "corpus_rows": int(len(corpus)),
        "status_counts": table["ja4_foxio_status"].value_counts().to_dict(),
        "output_sha256": hashlib.sha256(OUTPUT_TABLE.read_bytes()).hexdigest(),
        "captures": captures,
    }
    OUTPUT_MANIFEST.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def load_ja4_foxio(require_complete: bool = True) -> pd.DataFrame:
    """The recomputed table, refusing an incomplete or unverifiable build."""
    if not OUTPUT_MANIFEST.exists() or not OUTPUT_TABLE.exists():
        raise FileNotFoundError("FoxIO JA4 table not built: run python -m pipeline.corpus.recompute_ja4_foxio")
    manifest = json.loads(OUTPUT_MANIFEST.read_text(encoding="utf-8"))
    if hashlib.sha256(OUTPUT_TABLE.read_bytes()).hexdigest() != manifest["output_sha256"]:
        raise ValueError("ja4_foxio.parquet does not match its manifest checksum")
    if require_complete and not manifest["complete"]:
        raise ValueError("FoxIO JA4 table is incomplete (see manifest captures)")
    return pd.read_parquet(OUTPUT_TABLE)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--raw-root", type=Path, default=paths.PROJECT_ROOT,
                    help="directory that contains data/raw/... (default: this repository)")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    m = recompute(args.raw_root)
    print(json.dumps({k: m[k] for k in ("complete", "rows", "corpus_rows", "status_counts")}, indent=2))


if __name__ == "__main__":
    main()
