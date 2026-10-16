"""
Disciplined training loop for sequence models.

* deterministic seeding (python, numpy, torch; deterministic algorithms in warn-only mode);
* class weighting via pos_weight = negatives / positives of the TRAINING split;
* AdamW, gradient clipping (1.0), ReduceLROnPlateau on validation AP;
* early stopping on validation AP only (patience), best checkpoint restored at the end and
  written as safetensors (no pickle);
* per-epoch history (loss, validation AP, learning rate, seconds);
* CPU path by default; the installed PyTorch is a CPU build.
"""
from __future__ import annotations

import os
import random
import time
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np
import torch
from torch import nn

from ml.evaluation import metrics as M
from ml.sequence.models import ARCHITECTURES, parameter_count


def seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(True, warn_only=True)


def _batches(n: int, batch_size: int, rng: Optional[np.random.Generator]):
    order = rng.permutation(n) if rng is not None else np.arange(n)
    for s in range(0, n, batch_size):
        yield order[s:s + batch_size]


def predict(model: nn.Module, x: np.ndarray, mask: np.ndarray, lengths: np.ndarray, batch_size: int = 2048) -> np.ndarray:
    model.eval()
    out = []
    with torch.no_grad():
        for b in _batches(len(x), batch_size, None):
            logits = model(torch.from_numpy(x[b]), torch.from_numpy(mask[b]), torch.from_numpy(lengths[b]))
            out.append(torch.sigmoid(logits).numpy())
    return np.concatenate(out) if out else np.zeros(0)


def train_model(arch: str, train: Dict[str, np.ndarray], val: Dict[str, np.ndarray], seed: int = 42,
                epochs: int = 30, patience: int = 5, lr: float = 2e-3, batch_size: int = 512,
                checkpoint_path: Optional[Path] = None) -> Dict[str, Any]:
    seed_everything(seed)
    torch.set_num_threads(max(1, (os.cpu_count() or 2) - 1))
    in_ch = train["x"].shape[2]
    model = ARCHITECTURES[arch](in_ch)
    y_tr = train["y"].astype(np.float32)
    pos, neg = float(y_tr.sum()), float(len(y_tr) - y_tr.sum())
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor(neg / max(pos, 1.0)))
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    sched = torch.optim.lr_scheduler.ReduceLROnPlateau(opt, mode="max", factor=0.5, patience=2)
    rng = np.random.default_rng(seed)
    history, best_ap, best_state, best_epoch, wait = [], -1.0, None, -1, 0
    t_start = time.perf_counter()
    try:
        for epoch in range(epochs):
            model.train()
            t0, total, nb = time.perf_counter(), 0.0, 0
            for b in _batches(len(y_tr), batch_size, rng):
                opt.zero_grad()
                logits = model(torch.from_numpy(train["x"][b]), torch.from_numpy(train["mask"][b]),
                               torch.from_numpy(train["lengths"][b]))
                loss = loss_fn(logits, torch.from_numpy(y_tr[b]))
                loss.backward()
                nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                opt.step()
                total += float(loss.item()); nb += 1
            val_s = predict(model, val["x"], val["mask"], val["lengths"])
            val_ap = M.ranking_metrics(val["y"], val_s)["average_precision"]
            val_ap = -1.0 if val_ap is None else val_ap
            sched.step(val_ap)
            history.append({"epoch": epoch, "train_loss": total / max(nb, 1), "val_ap": val_ap,
                            "lr": opt.param_groups[0]["lr"], "seconds": round(time.perf_counter() - t0, 3)})
            if val_ap > best_ap + 1e-6:
                best_ap, best_epoch, wait = val_ap, epoch, 0
                best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
            else:
                wait += 1
                if wait >= patience:
                    break
    finally:
        if best_state is not None:
            model.load_state_dict(best_state)
    train_seconds = time.perf_counter() - t_start
    if checkpoint_path is not None and best_state is not None:
        from safetensors.torch import save_file
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        save_file({k: v.contiguous() for k, v in best_state.items()}, str(checkpoint_path))
    return {"model": model, "history": history, "best_epoch": best_epoch, "best_val_ap": best_ap,
            "epochs_run": len(history), "train_seconds": round(train_seconds, 2),
            "parameters": parameter_count(model), "pos_weight": neg / max(pos, 1.0),
            "device": "cpu", "torch_version": torch.__version__}


def load_checkpoint(arch: str, in_channels: int, path: Path) -> nn.Module:
    from safetensors.torch import load_file
    model = ARCHITECTURES[arch](in_channels)
    model.load_state_dict(load_file(str(path)))
    model.eval()
    return model
