"""
Sequence-model interpretation on a held-out test fold.

Methods (all evaluated as the change in average precision on held-out data):
  channel ablation     a channel is set to its post-normalisation neutral value (0) on real steps;
  temporal occlusion   all channels of the real steps inside a window are set to the neutral value 0
                       while mask and lengths stay unchanged (identical semantics for CNN and GRU);
  IAT scaling          SIMULATED_PERTURBATION: inter-arrival times multiplied by k = 0.5 or 2.0 (a
                       plausible change of path speed). For IAT >> 1 ms, log1p(k*t) ~ log1p(t) + log(k),
                       so the standardised channel is shifted by log(k) / std_train. It is a
                       sensitivity probe on held-out data, not new ground truth.
Saliency or occlusion importance is descriptive, not causal.
"""
from __future__ import annotations

from typing import Any, Dict

import numpy as np

from ml.evaluation import metrics as M
from ml.sequence.dataset import CHANNELS
from ml.sequence.train import predict

WINDOW = 8


def _ap(model, d) -> float:
    return M.ranking_metrics(d["y"], predict(model, d["x"], d["mask"], d["lengths"]))["average_precision"]


def interpret_sequence_model(model, test: Dict[str, np.ndarray], fold: str, iat_std: float = 1.0,
                             max_rows: int = 6000, seed: int = 0) -> Dict[str, Any]:
    n = len(test["y"])
    if n > max_rows:
        rng = np.random.default_rng(seed)
        idx = np.sort(rng.choice(n, size=max_rows, replace=False))
        test = {k: v[idx] for k, v in test.items()}
    if len(np.unique(test["y"])) < 2:
        return {"status": "NOT_RUN", "reason": "single-class sample"}
    base = _ap(model, test)
    out: Dict[str, Any] = {"status": "COMPLETED", "fold": fold, "rows": int(len(test["y"])), "baseline_ap": base,
                           "channel_ablation": {}, "temporal_occlusion": {}, "simulated_iat_scaling": {}}
    for c, name in enumerate(CHANNELS):
        x = test["x"].copy()
        x[:, :, c] = np.where(test["mask"], 0.0, x[:, :, c])
        out["channel_ablation"][name] = {"ap": _ap(model, {**test, "x": x}), "delta_ap": None}
        out["channel_ablation"][name]["delta_ap"] = out["channel_ablation"][name]["ap"] - base
    L = test["x"].shape[1]
    for start in range(0, L, WINDOW):
        x = test["x"].copy()
        window = test["mask"][:, start:start + WINDOW]
        x[:, start:start + WINDOW, :] = np.where(window[:, :, None], 0.0, x[:, start:start + WINDOW, :])
        ap = _ap(model, {**test, "x": x})
        out["temporal_occlusion"][f"steps_{start}-{start + WINDOW - 1}"] = {"ap": ap, "delta_ap": ap - base,
                                                                           "flows_with_steps_in_window": int(window.any(1).sum())}
    iat_c = CHANNELS.index("log_iat_ms")
    for k in (0.5, 2.0):
        x = test["x"].copy()
        x[:, :, iat_c] = np.where(test["mask"], x[:, :, iat_c] + np.log(k) / iat_std, x[:, :, iat_c])
        ap = _ap(model, {**test, "x": x})
        out["simulated_iat_scaling"][f"x{k}"] = {"ap": ap, "delta_ap": ap - base,
                                                 "label": "SIMULATED_PERTURBATION (log-IAT shift approximation)"}
    return out
