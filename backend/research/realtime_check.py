"""
Measured end-to-end check of the real-time detection path on the replay set.

Runs every replay row through the production DetectionPipeline (target attribution ->
registry-backed inference -> canonical ETTHStreamEvent validation) for each track and records
status counts, skip reasons, OOD flags, in-sample flags, and per-flow processing / inference
latency. Optionally streams a few events over the real WebSocket endpoint to confirm the
canonical contract end to end.

    python -m backend.research.realtime_check [--limit 2000] [--websocket-events 20]

Output: data/experiments/phase9/diagnostics/realtime_check.json
The scores of replayed flows from training captures are IN-SAMPLE and are not evaluation results.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import statistics
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict

BASE_DIR = Path(__file__).resolve().parent.parent.parent
OUT = BASE_DIR / "data" / "experiments" / "phase9" / "diagnostics" / "realtime_check.json"


def _q(vals, p):
    vals = sorted(vals)
    return round(vals[min(len(vals) - 1, int(p * len(vals)))], 4) if vals else None


def run(limit: int = 2000, websocket_events: int = 20) -> Dict[str, Any]:
    from backend.data_access import replay_frame
    from backend.detection_pipeline import detection_pipeline
    from backend.inference_engine import SUPPORTED_TRACKS, inference_engine
    from backend.schemas import ETTHStreamEvent

    df, source = replay_frame()
    if df is None:
        raise SystemExit("No replay dataset; run python -m pipeline.corpus replay-set")
    rows = df.head(limit).to_dict(orient="records")
    out: Dict[str, Any] = {"generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z"),
                           "replay_source": source, "rows": len(rows), "model_status": inference_engine.reload(), "tracks": {}}
    for track in SUPPORTED_TRACKS:
        statuses, skips, ood, preds = Counter(), Counter(), Counter(), Counter()
        proc, inf = [], []
        in_sample = 0
        t0 = time.perf_counter()
        for i, row in enumerate(rows):
            ev = detection_pipeline.process_flow(row, track=track, stream_id="realtime_check", sequence=i + 1)
            ETTHStreamEvent.model_validate(ev.model_dump())
            d = ev.detection
            statuses[d.status] += 1
            if d.status == "SKIPPED" and d.skip_reason:
                skips[d.skip_reason.split(":")[0]] += 1
            if d.status == "COMPLETED":
                preds[f"{row.get('label')}->{d.prediction}"] += 1
                inf.append(getattr(ev, "_inf_duration_ms", 0.0))
            proc.append(getattr(ev, "_proc_duration_ms", 0.0))
            for f in d.ood_flags:
                ood[f.split(":")[0]] += 1
                in_sample += f.startswith("IN_SAMPLE_REPLAY")
        wall = time.perf_counter() - t0
        out["tracks"][track] = {
            "status_counts": dict(statuses), "skip_reasons": dict(skips), "ood_flag_counts": dict(ood),
            "in_sample_flows": in_sample,
            "label_to_prediction_counts_IN_SAMPLE": dict(preds),
            "inference_ms": {"n": len(inf), "p50": _q(inf, 0.5), "p95": _q(inf, 0.95), "p99": _q(inf, 0.99),
                             "mean": round(statistics.fmean(inf), 4) if inf else None},
            "pipeline_ms": {"p50": _q(proc, 0.5), "p95": _q(proc, 0.95)},
            "throughput_flows_per_s": round(len(rows) / wall, 1) if wall > 0 else None,
        }
    if websocket_events:
        from fastapi.testclient import TestClient
        from backend.main import app
        from backend.replay_engine import replay_engine
        client = TestClient(app)
        received = []
        with client.websocket_connect("/ws/live-stream") as ws:
            ws.receive_json()
            ws.send_json({"action": "START_REPLAY", "speed": 100.0, "track": "E_JA4_FLOW"})
            while len([e for e in received if e["event_type"] == "flow.detected"]) < websocket_events:
                msg = ws.receive_json()
                ETTHStreamEvent.model_validate(msg)
                received.append(msg)
            ws.send_json({"action": "STOP_REPLAY"})
        flows = [e for e in received if e["event_type"] == "flow.detected"]
        out["websocket"] = {"events_received": len(received), "flow_events": len(flows),
                            "detection_statuses": dict(Counter(e["detection"]["status"] for e in flows)),
                            "all_valid_canonical_events": True}
    out["note"] = ("Replayed flows come from captures used to train the active models, so predictions are IN-SAMPLE "
                   "(flagged IN_SAMPLE_REPLAY) and must not be read as detection performance.")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=2000)
    ap.add_argument("--websocket-events", type=int, default=20)
    a = ap.parse_args()
    res = run(a.limit, a.websocket_events)
    print(json.dumps({t: {"status": v["status_counts"], "inference_ms": v["inference_ms"]} for t, v in res["tracks"].items()}, indent=2))
