"""
Independent re-verification of persisted experiment results.

For every experiment record of the latest completed suites this module:
* checks the SHA-256 of the out-of-fold predictions file against the record;
* recomputes, from those predictions, the pooled average precision (validation-calibrated
  scores), the test FPR and recall at the validation-selected FPR<=1% threshold, and the
  population sizes, and compares them with the values stored in the record;
* re-derives every claim of the generated ledger from the same artefacts and compares statuses
  with the committed claim_ledger.json.

It never trains a model or edits an artefact. Predictions are git-ignored, so on a clean checkout
the checksum/recompute step reports MISSING rather than passing silently.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

from ml.benchmark.registry import sha256_file, suite_dir
from ml.evaluation import metrics as M
from ml.reporting.claims import build_claims
from ml.reporting.report import REPORT_DIR, ROOT, latest_suites

TOLERANCE = 1e-9
THRESHOLD_COLUMN = "pred@fpr<=0.01"


def _close(a: Optional[float], b: Optional[float]) -> bool:
    if a is None or b is None:
        return a is None and b is None
    return math.isclose(float(a), float(b), rel_tol=TOLERANCE, abs_tol=TOLERANCE)


def verify_record(record: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"experiment_id": record["experiment_id"], "status": record.get("status"),
                           "track": (record.get("config") or {}).get("track"),
                           "model": (record.get("config") or {}).get("model")}
    if record.get("status") != "COMPLETED":
        out["result"] = "NOT_COMPLETED"
        return out
    art = (record.get("artifacts") or {}).get("predictions.parquet")
    if not art:
        out["result"] = "NO_PREDICTIONS_RECORDED"
        return out
    path = ROOT / art["path"]
    if not path.exists():
        out["result"] = "MISSING"
        return out
    if sha256_file(path) != art["sha256"]:
        out["result"] = "CHECKSUM_MISMATCH"
        return out
    P = pd.read_parquet(path)
    metrics = record.get("metrics") or {}
    recorded_ap = (metrics.get("pooled_calibrated") or {}).get("average_precision")
    recomputed_ap = M.ranking_metrics(P["y"].to_numpy(), P["score_calibrated"].to_numpy()).get("average_precision")
    checks = {"average_precision": (recorded_ap, recomputed_ap)}
    thr = (metrics.get("at_validation_thresholds") or {}).get(THRESHOLD_COLUMN)
    if thr and THRESHOLD_COLUMN in P.columns:
        sub = P[P[THRESHOLD_COLUMN] >= 0]
        neg, pos = sub[sub["y"] == 0], sub[sub["y"] == 1]
        checks["test_fpr_at_val_fpr_0.01"] = (thr.get("fpr"), float((neg[THRESHOLD_COLUMN] == 1).mean()) if len(neg) else None)
        checks["recall_at_val_fpr_0.01"] = (thr.get("recall"), float((pos[THRESHOLD_COLUMN] == 1).mean()) if len(pos) else None)
        checks["n_pos"] = (thr.get("n_pos"), int(len(pos)))
        checks["n_neg"] = (thr.get("n_neg"), int(len(neg)))
    out["checks"] = {k: {"recorded": a, "recomputed": b, "match": _close(a, b)} for k, (a, b) in checks.items()}
    out["result"] = "VERIFIED" if all(c["match"] for c in out["checks"].values()) else "MISMATCH"
    return out


def verify_all() -> Dict[str, Any]:
    latest = latest_suites()
    suites: Dict[str, Any] = {}
    counts: Dict[str, int] = {}
    for name, entry in sorted(latest.items()):
        sid = entry["suite"]["suite_id"]
        rows: List[Dict[str, Any]] = []
        for rec_path in sorted(suite_dir(sid).glob("*/record.json")):
            res = verify_record(json.loads(rec_path.read_text(encoding="utf-8")))
            counts[res["result"]] = counts.get(res["result"], 0) + 1
            rows.append(res)
        suites[name] = {"suite_id": sid, "experiments": rows}

    committed = REPORT_DIR / "claim_ledger.json"
    claims_check: Dict[str, Any] = {"committed_ledger": str(committed.relative_to(ROOT).as_posix())}
    if committed.exists():
        old = {c["claim_id"]: c["status"] for c in json.loads(committed.read_text(encoding="utf-8")).get("claims", [])}
        new = {c["claim_id"]: c["status"] for c in build_claims(latest)}
        claims_check["status_differences"] = {k: {"committed": old.get(k), "rederived": new.get(k)}
                                              for k in sorted(set(old) | set(new)) if old.get(k) != new.get(k)}
        claims_check["rederived_ids"] = sorted(new)
    return {"result_counts": counts, "suites": suites, "claims": claims_check}
