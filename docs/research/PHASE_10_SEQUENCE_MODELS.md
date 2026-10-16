# Phase 10: Sequence Models for Encrypted-Flow Behaviour

**Status:** IMPLEMENTED · TESTED · EXECUTED (exploratory, CPU). Not scientifically validated: the data is source-confounded and there is one seed.
**Code:** `ml/sequence/` (`dataset.py`, `models.py`, `train.py`, `experiment.py`, `interpret.py`) · **Tests:** `tests/test_sequence_models.py` (8 tests)
**Research question:** Do sequence representations of observable encrypted-flow behaviour add measurable, reproducible detection value over well-tuned tabular baselines under group-isolated, source-aware evaluation?

## 1. Feasibility (verified from corpus v3)

The Phase 6 reconstruction stores, for every flow, per-packet IP length, relative time, direction and TCP flags. These are header metadata only; no payload is stored. They are capped at the first 1,000 packets, and the true packet count is kept in `sequence_original_length`. Timestamps are capture timestamps. Valid sequences can therefore be built for every flow, with no reconstruction of information the data lacks.

## 2. Sequence construction (`ml/sequence/dataset.py`)

* **One sequence per flow:** its first `max_len = 64` packets.
  * There are no sliding windows, so samples never overlap.
  * A sample can never straddle a capture, session or behavioural-group boundary.
  * Outer folds are whole captures with duplicate-group purging (Phase 9 §3), so no near-identical window can sit on both sides of a split.
* **Channels** (9 per step):
  * direction (±1)
  * `log1p(IP length)`
  * `log1p(IAT in ms)` (first step 0)
  * TCP SYN/FIN/RST/PSH/ACK bits
  * `is_udp`
* **Normalisation:** `log1p(length)` and `log1p(IAT)` are standardised with mean and SD computed on **real steps of the training rows only** (`SequenceNormaliser`, tested).
* **Padding:** zeros plus a boolean mask.
  * The CNN zeroes padded steps before every convolution and pools only over real steps. A bug found by `test_models_ignore_padding` was fixed: padding activations leaked into the last real steps.
  * The GRU consumes packed sequences.
* **Malformed rows** (list-length mismatch, empty, non-finite, negative length, decreasing time) are **rejected and counted, never repaired**.

## 3. Models

| Stage | Model | Notes |
|---|---|---|
| A | `seqagg_logreg`, `seqagg_hist_gb` | summary statistics of the **same** first 64 packets (information-matched) |
| A′ | `tab_trackA_hist_gb`, `tab_trackA_random_forest` | Track A full-flow features, a strong tabular baseline. It sees the **whole** flow, so strictly more information than the sequence models. |
| B | `cnn`: 2 × Conv1d (k = 5) + masked mean/max pooling + MLP | 15,937 parameters |
| C | `gru`: 1-layer GRU (48 units) over packed sequences | 8,545 parameters |
| D | Transformer encoder | **not implemented.** It is justified only if B or C beats the information-matched baseline reproducibly; attention weights would not be an explanation by themselves. |

## 4. Training discipline (`ml/sequence/train.py`, `ml/sequence/experiment.py`)

* **Splits.** Outer: capture-grouped 5-fold, the same assignment as the Phase 9 suites for the same datasets and seed. Inner: one held-out group of **validation captures** taken from the outer training fold, chosen to contain both classes. Training rows sharing a `behavioral_hash` with validation rows are purged.
* **Shared evaluation conditions.** Every model, tabular and sequence, uses the same training rows, validation captures and test folds. Training rows are capped at 60,000 per fold by deterministic, capture-proportional sub-sampling; the evaluation set is complete.
* **Optimisation.** Deterministic seeding; `pos_weight = negatives / positives` of the training split; AdamW (lr 2e-3, weight decay 1e-4); gradient clipping at 1.0; ReduceLROnPlateau on validation AP.
* **Checkpointing.** Early stopping on validation AP only (patience 5, at most 30 epochs). The best checkpoint is restored and written as safetensors (no pickle).
* **Calibration and thresholds** are fitted on validation captures (Platt; FPR ≤ 1 % and ≤ 5 %). The test fold is scored once.
* **Hardware.** CPU path: the installed PyTorch is `2.13.0+cpu`. It was not upgraded even though an RTX 5050 is present.
* **Recorded per fold:** epoch history (loss, validation AP, LR, seconds), best epoch, training seconds, parameter count, latency per flow and RSS delta.

## 5. Interpretation (`ml/sequence/interpret.py`)

All probes run on a held-out test fold (≤ 6,000 rows), measured as ΔAP:

* **Channel ablation:** a channel is set to its neutral value.
* **Temporal occlusion:** 8-step windows are zeroed while mask and lengths stay unchanged.
* **SIMULATED IAT scaling (×0.5, ×2):** a shift of log(k) / std in the standardised log-IAT channel. This is a sensitivity probe, not ground truth.

The outputs are descriptive, not causal.

## 6. Comparisons

There are four pre-declared paired contrasts (capture bootstrap of ΔAP, Holm-adjusted):

* CNN vs information-matched tabular
* GRU vs information-matched tabular
* CNN vs full-flow tabular
* GRU vs full-flow tabular

## 7. Commands

```bash
python -m ml sequence --epochs 30                              # all admitted datasets
python -m ml sequence --epochs 30 --datasets DS-009,DS-011     # same-laboratory subset
```

## 8. Results

See §9 below (filled from `data/experiments/phase10/<suite>/summary.json`) and `data/experiments/reports/latest_report.md`.
