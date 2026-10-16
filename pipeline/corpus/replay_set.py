"""
Replay set: a small, capture-balanced slice of corpus v3 for the real-time replay stream.

At most PER_CAPTURE flows per capture (uniform, deterministic), all model-candidate features
plus the provenance needed by stream events (flow_id, capture_id, dataset_id, endpoints,
ground-truth label). Packet sequences are dropped to keep the backend lightweight.
Replaying flows from captures that were used for training yields IN-SAMPLE scores; the
inference engine flags such events (IN_SAMPLE_REPLAY) so they are never read as evaluation.
"""
from __future__ import annotations

import json

import pandas as pd

from pipeline.corpus import paths
from pipeline.corpus.builder import SEQUENCE_COLUMNS, load_corpus

REPLAY_PATH = paths.PROCESSED_V3_DIR / "replay_flows.parquet"
PER_CAPTURE = 300


def build_replay_set(per_capture: int = PER_CAPTURE, seed: int = 42) -> dict:
    flows, prov = load_corpus()
    df = flows.drop(columns=[c for c in SEQUENCE_COLUMNS if c in flows.columns]).merge(
        prov.drop(columns=["label"]), on="corpus_index", how="left")
    parts = []
    for i, (cid, g) in enumerate(df.groupby("capture_id", sort=True)):
        parts.append(g.sample(n=min(per_capture, len(g)), random_state=seed + i).sort_values("capture_flow_index"))
    # Interleave captures so a replay shows both classes early instead of one capture at a time.
    out = pd.concat(parts)
    out["_rank"] = out.groupby("capture_id").cumcount()
    out = out.sort_values(["_rank", "capture_id"]).drop(columns=["_rank"]).reset_index(drop=True)
    out.to_parquet(REPLAY_PATH, index=False)
    meta = {"rows": int(len(out)), "per_capture": per_capture, "seed": seed,
            "captures": int(out["capture_id"].nunique()),
            "labels": {k: int(v) for k, v in out["label"].value_counts().items()}}
    REPLAY_PATH.with_suffix(".json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta
