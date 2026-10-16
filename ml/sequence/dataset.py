"""
Sequence construction for Phase 10.

Source columns (per flow, produced by the Phase 6 reconstruction, capped at 1000 packets):
    sequence_packet_lengths   IP packet length per packet
    sequence_relative_times   seconds since the first packet of the flow
    sequence_directions       +1 forward (initiator) / -1 reverse
    sequence_tcp_flags        TCP flag byte, -1 for UDP

Construction rules:
  * ONE sequence per flow: the first `max_len` packets. No sliding windows, so no two samples
    overlap and a sample can never straddle a capture, session or behavioural-group boundary.
  * Channels per step (no payload content is used):
        0 direction (+1/-1)
        1 log1p(packet length)           -> standardised with TRAINING mean/std
        2 log1p(inter-arrival time in ms) -> standardised with TRAINING mean/std (first step 0)
        3..7 TCP flag bits SYN, FIN, RST, PSH, ACK (0 for UDP)
        8 is_udp
  * Padding: zeros after the last real step; a boolean mask marks real steps. Models must use
    the mask (CNN masked pooling, GRU packed sequences).
  * Malformed rows (list lengths disagree, non-finite or negative values, decreasing relative
    times) are rejected and counted, never repaired.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

SEQ_COLUMNS = ["sequence_packet_lengths", "sequence_relative_times", "sequence_directions", "sequence_tcp_flags"]
CHANNELS = ["direction", "log_len", "log_iat_ms", "syn", "fin", "rst", "psh", "ack", "is_udp"]
FLAG_BITS = {"syn": 0x02, "fin": 0x01, "rst": 0x04, "psh": 0x08, "ack": 0x10}
NORMALISED = (1, 2)


@dataclass
class SequenceBatch:
    x: np.ndarray           # (n, max_len, C) float32, NOT yet normalised
    mask: np.ndarray        # (n, max_len) bool
    lengths: np.ndarray     # (n,) int
    valid: np.ndarray       # (n,) bool  (False = malformed row, excluded)
    reasons: Dict[str, int]


def _as_list(v) -> List:
    if v is None:
        return []
    return list(v.tolist() if hasattr(v, "tolist") else v)


def build_sequences(df: pd.DataFrame, max_len: int = 64) -> SequenceBatch:
    n = len(df)
    C = len(CHANNELS)
    x = np.zeros((n, max_len, C), dtype=np.float32)
    mask = np.zeros((n, max_len), dtype=bool)
    lengths = np.zeros(n, dtype=np.int64)
    valid = np.ones(n, dtype=bool)
    reasons = {"length_mismatch": 0, "empty": 0, "non_finite": 0, "negative_length": 0, "time_decreasing": 0}
    cols = [df[c].to_numpy() for c in SEQ_COLUMNS]
    for i in range(n):
        L, T, D, F = (_as_list(c[i]) for c in cols)
        if not (len(L) == len(T) == len(D) == len(F)):
            valid[i] = False; reasons["length_mismatch"] += 1; continue
        if len(L) == 0:
            valid[i] = False; reasons["empty"] += 1; continue
        k = min(len(L), max_len)
        Ln = np.asarray(L[:k], dtype=float); Tn = np.asarray(T[:k], dtype=float)
        Dn = np.asarray(D[:k], dtype=float); Fn = np.asarray(F[:k], dtype=float)
        if not (np.isfinite(Ln).all() and np.isfinite(Tn).all() and np.isfinite(Dn).all() and np.isfinite(Fn).all()):
            valid[i] = False; reasons["non_finite"] += 1; continue
        if (Ln < 0).any():
            valid[i] = False; reasons["negative_length"] += 1; continue
        iat = np.diff(Tn, prepend=Tn[0])
        if (iat < -1e-9).any():
            valid[i] = False; reasons["time_decreasing"] += 1; continue
        x[i, :k, 0] = Dn
        x[i, :k, 1] = np.log1p(Ln)
        x[i, :k, 2] = np.log1p(np.clip(iat, 0, None) * 1000.0)
        udp = Fn < 0
        flags = np.where(udp, 0, Fn).astype(np.int64)
        for j, name in enumerate(("syn", "fin", "rst", "psh", "ack")):
            x[i, :k, 3 + j] = ((flags & FLAG_BITS[name]) > 0).astype(np.float32)
        x[i, :k, 8] = udp.astype(np.float32)
        mask[i, :k] = True
        lengths[i] = k
    return SequenceBatch(x, mask, lengths, valid, reasons)


class SequenceNormaliser:
    """Fitted on training sequences only (real steps only)."""

    def fit(self, batch: SequenceBatch, idx: np.ndarray) -> "SequenceNormaliser":
        self.stats = {}
        for c in NORMALISED:
            vals = batch.x[idx][:, :, c][batch.mask[idx]]
            mu = float(vals.mean()) if vals.size else 0.0
            sd = float(vals.std()) if vals.size else 1.0
            self.stats[c] = (mu, sd if sd > 0 else 1.0)
        return self

    def transform(self, batch: SequenceBatch, idx: np.ndarray) -> np.ndarray:
        out = batch.x[idx].copy()
        m = batch.mask[idx]
        for c, (mu, sd) in self.stats.items():
            out[:, :, c] = np.where(m, (out[:, :, c] - mu) / sd, 0.0)
        return out

    def to_dict(self):
        return {CHANNELS[c]: {"mean": mu, "std": sd} for c, (mu, sd) in self.stats.items()}


def aggregate_features(batch: SequenceBatch) -> pd.DataFrame:
    """Stage A: summary statistics of the SAME first-max_len steps (information-matched baseline)."""
    x, m = batch.x, batch.mask
    feats: Dict[str, np.ndarray] = {"seq_len": batch.lengths.astype(float)}
    cnt = np.clip(m.sum(1), 1, None)
    for c, name in ((0, "direction"), (1, "log_len"), (2, "log_iat_ms")):
        v = np.where(m, x[:, :, c], np.nan)
        with np.errstate(all="ignore"):
            feats[f"{name}_mean"] = np.nanmean(v, axis=1)
            feats[f"{name}_std"] = np.nanstd(v, axis=1)
            feats[f"{name}_min"] = np.nanmin(np.where(m, x[:, :, c], np.inf), axis=1)
            feats[f"{name}_max"] = np.nanmax(np.where(m, x[:, :, c], -np.inf), axis=1)
    signed = np.where(m, x[:, :, 0] * np.expm1(x[:, :, 1]), 0.0)
    feats["fwd_bytes_first_k"] = np.where(signed > 0, signed, 0).sum(1)
    feats["rev_bytes_first_k"] = np.where(signed < 0, -signed, 0).sum(1)
    for j, name in enumerate(("syn", "fin", "rst", "psh", "ack", "is_udp")):
        feats[f"{name}_frac"] = (x[:, :, 3 + j] * m).sum(1) / cnt
    out = pd.DataFrame(feats)
    for c in out.columns:
        out[c] = out[c].replace([np.inf, -np.inf], np.nan)
    return out
