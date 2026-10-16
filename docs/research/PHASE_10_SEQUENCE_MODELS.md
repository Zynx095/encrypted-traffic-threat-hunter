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

## 8. Results (exploratory, executed 2026-10-16, CPU)

### 8.1 All admitted datasets: `sequence_capture_cv-20261016T185120Z`

62,543 flows, all valid (0 rejected; 913 flows longer than 64 packets were truncated). Five outer capture folds.

| Model | AP [95% CI] (FEW_GROUPS) | Recall / FPR @val-FPR≤1 % | Mean fit s / fold | Latency ms / flow (batch) | Parameters |
|---|---|---|---|---|---|
| seqagg_hist_gb (information-matched) | **0.909 [0.759, 0.973]** | 41.9 % / 4.8 % | 1.2 | 0.002 | — |
| tab_trackA_random_forest (full flow) | 0.904 [0.730, 0.984] | 36.2 % / 6.3 % | 0.8 | 0.006 | — |
| tab_trackA_hist_gb (full flow) | 0.886 [0.692, 0.983] | 31.7 % / 8.4 % | 7.4 | 0.009 | — |
| cnn | 0.871 [0.662, 0.979] | 38.9 % / 6.9 % | 7.0 | 0.016 | 15,937 |
| seqagg_logreg | 0.841 [0.629, 0.954] | 38.3 % / 11.4 % | 0.1 | 0.0004 | — |
| gru | 0.828 [0.603, 0.972] | 40.9 % / 12.0 % | 24.1 | 0.006 | 8,545 |

Pre-declared contrasts (ΔAP = sequence − tabular; Holm over 4):

| Contrast | ΔAP [95% CI] | Holm p |
|---|---|---|
| CNN vs information-matched | −0.039 [−0.118, 0.030] | 1.00 |
| GRU vs information-matched | −0.082 [−0.171, 0.011] | 0.59 |
| CNN vs full-flow | −0.015 [−0.060, 0.029] | 1.00 |
| GRU vs full-flow | **−0.058 [−0.105, −0.006]** | **0.024** |

The GRU is worse than the full-flow tabular baseline. No sequence model beats a tabular baseline.

### 8.2 Same-laboratory subset: `sequence_capture_cv_DS009_DS011-20261016T190417Z`

AP for each model:

* tab_trackA_random_forest 0.942
* tab_trackA_hist_gb 0.926
* seqagg_hist_gb 0.896
* cnn 0.893
* gru 0.871
* seqagg_logreg 0.857

No contrast is significant: every Holm p ≥ 0.90, every ΔAP ≤ 0.

### 8.3 Interpretation probes (held-out fold, 6,000 rows; descriptive only)

* **Channel ablation:** the SYN-flag channel matters most (ΔAP −0.14 GRU, −0.08 CNN). Whether a flow starts with a TCP handshake is partly a capture artefact: flows that began before a long malware capture started lack a SYN. This channel therefore carries collection-process signal as well as behaviour.
* **Temporal occlusion:** nearly all signal sits in the first 8 packets (ΔAP −0.16 GRU, −0.12 CNN). Later windows contribute ≈ 0.
* **SIMULATED IAT scaling:** ×2 changes AP by −0.062 (GRU) and +0.033 (CNN); ×0.5 by −0.028 and −0.031. The models are sensitive to plausible path-speed changes.

### 8.4 Conclusion

**Phase 10 exit criterion met.** Sequence models were trained and evaluated end to end with group-isolated, capture-held-out folds and compared fairly against tabular baselines on identical rows.

**Scientific outcome:** on this corpus there is **no evidence that sequence models add detection value**. The GRU is significantly worse than the full-flow tabular baseline. This is an acceptable negative result, and it is source-confounded like every other result here. A Transformer (Stage D) was not justified and was not implemented.
