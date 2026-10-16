# Phase 9: Generalised Multi-Track Benchmark Protocol

**Status:** IMPLEMENTED · TESTED · EXECUTED (exploratory). **Not** scientifically validated: every suite is exploratory on source-confounded data, and confirmatory evaluation is BLOCKED.
**Code:** `ml/features`, `ml/estimators`, `ml/evaluation`, `ml/benchmark`, `ml/diagnostics`, `ml/model_registry.py`
**Tests:** `tests/test_feature_governance_and_splits.py`, `tests/test_benchmark_metrics.py`, `tests/test_model_registry_inference.py`, `tests/test_reporting_claims.py`

## 1. Feature governance (`ml/features/governance.py`)

The five canonical tracks keep the meaning they had in `pipeline/experimental_dataset_constructor.py`:

| Track | Inputs | Population |
|---|---|---|
| A_FLOW | 74 flow statistics (counts, rates, ratios, packet-length / IAT stats per direction, bursts) + TLS structural (`clienthello_present`, `serverhello_present`, `sni_present`, `tls_version`, `alpn_value`) | all flows |
| B_JA3 | `ja3_hash` | flows with a JA3 |
| C_JA4 | `ja4` | flows with a JA4 |
| D_JA3_FLOW | B + A inputs | flows with a JA3 |
| E_JA4_FLOW | C + A inputs | flows with a JA4 |

Non-canonical feature sets, never reported as A-E: `A_FLOW@JA3POP` and `A_FLOW@JA4POP` (track A inputs on the D/E population, for paired contrasts), `A0_FLOW_STRICT` (flow statistics without TLS structural fields), and `P_AVAILABILITY_PROBE` (handshake presence flags only, a shortcut probe).

* **Allow-list.** A column reaches a model matrix only if it is registered with a model-eligible family. Unknown columns are rejected (`assert_model_safe`), as are 38 explicitly forbidden provenance columns ( IP, port, MAC, endpoints, timestamps, dataset/capture/file IDs, family annotations, `behavioral_hash`, label) and the sequence/JA3S/raw-string families.
* **Registry metadata.** Each feature records type, family, extraction, availability, leakage risk, justification, preprocessing and track membership (`GET /api/research/features/governance`).
* **Missing fingerprints.** A fingerprint track scores only flows that carry its fingerprint; every other flow counts as coverage loss and is reported, never imputed. Inside fusion tracks, `tls_version` and `alpn_value` carry an explicit `__MISSING__` level.
* **Fingerprint encodings** (`ml/estimators/preprocessing.py`), all fitted on the training fold:
  * one-hot with min-frequency 2, plus explicit `__UNKNOWN__` and `__MISSING__` columns;
  * training-frequency encoding, plus unknown and missing indicators;
  * MD5 hashing into 64 buckets (collisions possible and documented).
  Raw fingerprint strings are never mapped to ordinal numbers.
* **Numeric missing values** (e.g. IAT of a single-packet flow): training-fold median plus a missing-indicator column.

## 2. Evaluation population

Captures range from 9 to 123,497 flows. Each suite therefore evaluates a **capture-balanced sample**: at most 4,000 flows per capture, drawn uniformly and deterministically within each capture, independent of label. Captures smaller than 4,000 flows are kept whole. Pooled suites get 62,543 rows (DS-008 2,543, DS-009 36,000, DS-011 24,000). The exact population of every suite is stored in `suite.json → evaluation_population`. Full-corpus coverage statistics are reported separately (`python -m ml coverage`).

## 3. Split protocols (`ml/evaluation/splits.py`)

| Protocol | Use | Notes |
|---|---|---|
| CAPTURE_GROUP_KFOLD | **primary** | `StratifiedGroupKFold` over whole captures (5 folds; each fold holds out at least one benign and one malicious capture). One assignment per suite is shared by all tracks and models, so paired contrasts use identical folds. Training rows whose `behavioral_hash` also occurs in the test fold are **purged from training**; the test population is never altered. Purge counts are recorded. |
| BEHAVIORAL_HOLDOUT | legacy continuity | Phase 7 protocol (`GroupShuffleSplit`, 20 %, seed 42, groups = `behavioral_hash`). Captures leak across the split, so it is expected to be optimistic. |
| BEHAVIORAL_GROUP_KFOLD | inner folds of behavioural protocols | `StratifiedGroupKFold` on `behavioral_hash` |
| LEAVE_ONE_SOURCE_OUT | cross-source probe | Each dataset is held out in turn. Holding out the only benign source leaves a single-class training set, recorded as INFEASIBLE. Malicious hold-outs report detection rate only. |
| LEAVE_ONE_FAMILY_OUT | family generalisation | Each malware family group is held out (groups merge families that share captures, e.g. AsyncRAT/XWorm), together with one rotating benign capture. |
| TEMPORAL_HOLDOUT | implemented | **Infeasible for detection here:** all benign data is from 2017, so any later test period has no benign flows. |
| Environment holdout | not implemented | The admitted corpus has a single benign environment class. |

Invariant `validate_fold`: no row and no `behavioral_hash` appears on both sides of any fold. It runs for every fold and is tested.

## 4. Training, selection, calibration, thresholds (`ml/benchmark/runner.py`)

For each outer fold:

1. Nested selection over the model's pre-declared grid. Inner 3-fold grouped CV runs on the outer training fold, with the inner grouping unit matching the outer protocol. The criterion is average precision.
2. The inner out-of-fold scores of the selected configuration fit a **Platt calibrator** and set **decision thresholds** for target FPRs of 1 % and 5 % (`threshold_for_fpr`).
3. Refit on the full outer training fold. Score the outer test fold **once**.

The outer test fold never influences selection, calibration or thresholds. This is enforced by `test_runner_never_uses_test_labels_for_selection_or_thresholds`, which permutes test labels and asserts that selected parameters, calibrators and thresholds are unchanged.

There is no resampling (class weights only) and no feature selection.

**Models** (`ml/estimators/zoo.py`):

* `dummy_prior` (prevalence floor)
* L2 `logreg` (C ∈ {0.1, 1, 10}; standardised inputs)
* `random_forest` (150 trees; min_samples_leaf ∈ {1, 5})
* `hist_gb` (100 iterations; two learning-rate / leaf-count settings)
* `extra_trees` (available, not used in the recorded suites)

The **primary model for confirmatory-style contrasts, `random_forest`, was declared before any Phase 9 result existed** (`ml/benchmark/suites.py::PRIMARY_MODEL`).

## 5. Metrics (`ml/evaluation/metrics.py`)

The positive class is MALICIOUS.

* **Ranking:** average precision (sklearn step-wise; primary), trapezoidal PR-AUC (reported separately for continuity with the Phase 7 pilot and **not** interchangeable with AP), ROC-AUC, Brier score, ECE (15 equal-width bins), and TPR at FPR ∈ {0.1 %, 1 %, 5 %} as a descriptive curve property.
* **Operating points:** recall, precision, F1, balanced accuracy, specificity, FPR, FNR, MCC and the confusion matrix, at the **validation-selected** thresholds and, separately, at an uncalibrated 0.5.
* **Population counts:** every block reports n, n_pos and n_neg.
* **Undefined metrics** (e.g. AP on a single-class fold) are `None` with a reason, never 0 or 1.
* **Pooled results** concatenate out-of-fold predictions using validation-calibrated scores. Per-fold mean ± SD is reported alongside.
* **Breakdowns:** per capture, per source and per family. Costs: fit seconds, prediction latency per flow, throughput and RSS delta.

## 6. Uncertainty and comparisons (`ml/evaluation/uncertainty.py`, `ml/benchmark/comparisons.py`)

* **Bootstrap unit = capture.** Captures are resampled with replacement within each class, 1,000 replicates, 95 % percentile intervals.
* **Group-count rules.** With fewer than 5 groups in any class the interval is withheld (`INSUFFICIENT_GROUPS`). With 5-9 groups it is flagged `FEW_GROUPS`. The pooled suites have 6 benign captures, so **all intervals are FEW_GROUPS and likely too narrow**.
* **Pre-declared paired contrasts** (same rows, same folds, paired capture bootstrap of ΔAP, recall and test FPR at the validation threshold):
  * A@JA3POP→D
  * A@JA4POP→E
  * B→D
  * C→E
* **Multiple comparisons:** Holm across the four contrasts, separately per suite and model.
* **Interpretation:** a non-significant difference reads "no evidence of a difference". No equivalence margin was pre-registered, so no equivalence claim is made.

## 7. Diagnostics

* `python -m ml coverage` writes the fingerprint availability and attrition by source, label, protocol, TLS version and capture, and the dataset-shift report.
* `P_AVAILABILITY_PROBE` measures how much label information handshake-presence flags carry on their own.
* `source_identifiability` suite: a diagnostic, not detection. It asks whether features distinguish DS-008 from DS-009 (both malicious).
* `python -m ml unseen` measures how fingerprint models treat client stacks absent from the training fold.
* `python -m ml explain` produces permutation importance on outer test folds only, plus labelled impurity importance or coefficients. Explanations are never used for feature selection.

## 8. Experiment registry (`ml/benchmark/registry.py`)

* Immutable experiment directories with an append-only `index.jsonl`.
* Each record holds config hash, source revision, dataset fingerprint (corpus manifest and input SHA-256), feature-schema fingerprint, seeds, coverage, metrics, costs, warnings, artefact checksums and status (COMPLETED / FAILED / INFEASIBLE). Failures keep their error message and traceback; the API never shows tracebacks.
* Suites can be resumed. EXPLORATORY and CONFIRMATORY stages are separate. Confirmatory runs are BLOCKED by policy until an independent source exists (`CONFIRMATORY_POLICY`).

## 9. Real-time integration (`ml/model_registry.py`, `backend/inference_engine.py`)

* `python -m ml train-deployable` fits a model on the full track population with the hyper-parameters selected most often in the referenced benchmark experiment. Calibration and the FPR ≤ 1 % threshold come from inner capture-grouped out-of-fold scores.
* The model is exported in the **pickle-free** `etth-tabular-model/1` format: JSON plus `npz` loaded with `allow_pickle=False`. Supported estimators are logistic regression, random forest and extra trees, verified bit-equivalent to sklearn.
* Each artefact is SHA-256 pinned and registered as CANDIDATE. Activation is explicit (one ACTIVE version per track), the history is kept, and rollback is supported.
* The inference engine loads only ACTIVE, checksum-verified artefacts from the controlled artefact root and trains nothing at import.
* Records lacking a required column, or with a missing value for a feature never missing in training, return **SKIPPED / INCOMPATIBLE_FEATURE_SCHEMA**. A track without an active model returns **SKIPPED / NO_VALIDATED_MODEL**.
* OOD flags cover values outside the 0.5-99.5 % training range, unseen categories, and in-sample replay. Latency, skip reasons and OOD counts are exposed at `GET /api/research/inference/status`.

## 10. Contract changes (documented)

| Change | Reason | Callers / tests updated |
|---|---|---|
| Inference no longer trains RandomForests at import, zero-fills missing features, or falls back to `ETTH-GroundTruthRule` (which echoed the ground-truth label as the prediction) | research integrity: no fabricated scores | `tests/test_detection_pipeline.py`: tests 1, 4 and 5 now pass complete flow records (assertions unchanged); new test 1b asserts sparse records are SKIPPED |
| Live capture no longer assigns a constant hard-coded JA3/JA4/JA3S to every ClientHello, no longer sets `tls_version=771`, `packet_length_std=0` and `iat_std=0`, and uses IP length instead of frame length | fabricated fingerprints and features | `tests/test_live_capture.py`: test 11 uses a well-formed ClientHello (assertions unchanged); new tests 11b and 11c |
| `DetectionDetails` gains optional `model_id`, `model_version`, `research_status`, `calibration_status`, `decision_threshold`, `ood_flags` | registry provenance | additive; `frontend/src/types/api.ts` updated; old events still validate (tested) |
| Detection events report `UNKNOWN` endpoints and `False` handshake flags when not observed (previously `192.168.1.100:443`, `10.0.0.5:52314`, `True`) | no invented values | — |
| Replay with no dataset transitions to `ERROR` with a `stream.error` event instead of idling in `PLAYING` | honest state | new behaviour; `test_13` passes with the replay set present |
| `/api/flows/*` and `/api/fingerprints/*` read corpus v3 (replay set / fingerprint projection); benign counts include every non-MALICIOUS label | endpoints returned 404 after the move | — |

## 11. Exploratory results (executed 2026-10-16)

Every number below comes from the suite summaries named in each heading; full tables are in `data/experiments/reports/latest_report.md`. AP is pooled out-of-fold average precision with a capture-bootstrap 95 % CI. Every interval is FEW_GROUPS (6 benign captures) and is likely too narrow. "Recall / FPR @val" are measured on the test fold at the threshold that gave FPR ≤ 1 % on validation captures.

### 11.1 Pooled capture-grouped CV: `pooled_capture_cv-20261016T164118Z`

Population: 62,543 flows (38,543 malicious, 24,000 benign, 25 captures). The TLS population used by B–E has 11,220 flows (8,591 / 2,629).

| Track | Prevalence AP | LR | RF (primary) | HGB | RF recall / FPR @val |
|---|---|---|---|---|---|
| A_FLOW (all flows) | 0.600 | 0.875 [0.762, 0.954] | **0.931 [0.797, 0.986]** | 0.898 [0.686, 0.987] | 49.5 % / 5.8 % |
| A0_FLOW_STRICT | 0.600 | 0.861 | 0.929 | 0.876 | 42.5 % / 6.1 % |
| P_AVAILABILITY_PROBE | 0.600 | 0.765 | 0.765 [0.628, 0.898] | 0.765 | 24.2 % / 0.1 % |
| B_JA3 | 0.767 | 0.970 | 0.971 [0.868, 1.000] | 0.999 | 99.8 % / **18.6 %** |
| C_JA4 | 0.767 | 0.999 | 0.994 [0.953, 1.000] | 0.999 | 99.4 % / **18.4 %** |
| D_JA3_FLOW | 0.767 | 0.9998 (FPR 1.9 %) | 0.988 [0.931, 1.000] | 0.995 | 99.5 % / 17.4 % |
| E_JA4_FLOW | 0.767 | 0.9999 (FPR 1.2 %) | 0.991 [0.944, 1.000] | 0.995 | 99.6 % / 12.1 % |
| A_FLOW on the TLS population | 0.767 | 0.9994 (FPR 1.5 %) | 0.990 [0.946, 1.000] | 0.983 | 99.6 % / 12.3 % |

**Paired contrasts, primary model RF (Holm over 4):**

* A@JA3POP→D ΔAP −0.002 [−0.015, 0.000]
* A@JA4POP→E +0.0001 [−0.003, 0.001]
* B→D +0.017 [0.000, 0.072]
* C→E −0.003 [−0.033, 0.014]

All Holm p ≥ 0.52: **no evidence of a difference**. For LR, adding JA3 or JA4 to flow gives ΔAP +0.0004 / +0.0005 (Holm p 0.032 / 0.042). That is statistically detectable under FEW_GROUPS but practically negligible, and HGB and RF do not reproduce it.

**Unseen fingerprints explain the fingerprint-only false positives** (`unseen_*.json`):

* 18.8 % of held-out benign TLS flows carry a fingerprint absent from the training fold.
* Fingerprint-only LR flags **98.8 % (JA3) / 98.2 % (JA4)** of those flows, against 0 % of benign flows whose fingerprint was seen.
* The fusion track E flags 6.3 % of unseen-fingerprint benign flows.

Fingerprint models therefore treat novel client stacks as malicious.

**Per-capture view (A_FLOW, RF):** benign CTU-Normal-21 is flagged at **34.4 %**, while the other five benign captures are at ≤ 0.2 %. It is the only benign capture recorded on a different LAN (192.168.1.191 instead of a 10.0.2.15 VM), which suggests capture-environment sensitivity. DS-008 (2024–2026) flows are detected at 6.7 %, DS-009 (2017) flows at 52.5 %.

**Explanations** (permutation importance on held-out folds): every AP drop is ≤ 0.005 for A_FLOW and ≤ 0.04 for E_JA4_FLOW. `alpn_value` ranks first in both. Most flow statistics are redundant: permuting any single one costs almost nothing.

### 11.2 Same-laboratory subset: `matched_lab_capture_cv-20261016T172459Z`

DS-009 (malicious, 9 captures) against DS-011 (benign, 6 captures); 60,000 flows; TLS population 11,026.

* **A_FLOW:** RF AP 0.934 [0.846, 0.984] (prevalence 0.535); LR 0.780; HGB 0.885.
* **B_JA3 and C_JA4:** AP **1.000** with FPR 0 % (LR, RF). JA3/JA4 separate the classes perfectly inside the same laboratory and period. The READMEs describe benign captures as Kali/iceweasel and malware hosts as Windows VMs, so the fingerprints identify operating system and client stack.
* **D, E and A on TLS:** AP 0.999–1.000. Every paired contrast is at the ceiling (ΔAP ≈ 0, **no evidence of a difference**).
* **Operating-point transfer is unstable even with perfect ranking.** Thresholds chosen on validation captures give a test FPR of 13–15 % (RF) and 30 % (HGB) on the TLS population.

### 11.3 Leave-one-source-out: `leave_one_source_out-20261016T180916Z`

Holding out the only benign source is INFEASIBLE, so only detection rates on a held-out malicious source are measurable.

| Held-out source | A_FLOW (LR / RF / HGB) | B_JA3, C_JA4 (all models) | D_JA3_FLOW (LR / RF / HGB) | E_JA4_FLOW (LR / RF / HGB) |
|---|---|---|---|---|
| DS-008 (trained on DS-009 + DS-011) | 0.0 / 3.8 / 2.4 % | **0 %** | 61.9 / 28.9 / 23.7 % | 61.9 / 35.1 / 23.7 % |
| DS-009 (trained on DS-008 + DS-011) | 0.3 / 15.3 / 0.0 % | **100 %** | 99.9 / 3.4 / 22.9 % | 99.9 / 26.2 / 22.9 % |

Fingerprint-only detection of a held-out source is all-or-nothing: 0 % or 100 %. The outcome depends on how the model scores never-seen fingerprints relative to the validation threshold, not on learned malicious behaviour. Flow-only models barely transfer across sources. This is the central exploratory evidence that **neither family has been shown to generalise**.

### 11.4 Source identifiability (diagnostic): `source_identifiability-*`

Task: distinguish DS-008 from DS-009 (both malicious); chance AP = 0.066 for flows and 0.023 for TLS flows.

| Track | RF AP |
|---|---|
| A_FLOW | 0.141 [0.090, 0.298] (weak) |
| C_JA4 | **1.000** |
| E_JA4_FLOW | 0.828 [0.581, 1.000] |

JA4 encodes the collection era and client stack completely.

### 11.5 Encoding ablation: `encoding_ablation-20261016T163936Z`

LR, pooled folds.

| Track | One-hot | Train-frequency | Hashing |
|---|---|---|---|
| B_JA3 | AP 0.970, FPR @val 18.6 % | AP 0.995, FPR 0.0 % | AP 0.995, FPR 18.4 % |
| C_JA4 | AP 0.999, FPR 18.4 % | AP 0.995, FPR 0.0 % | AP 0.996, FPR 18.4 % |

Under frequency encoding an unseen fingerprint receives frequency 0, which this LR maps to benign. That removes the false positives at a recall cost (97.7 %). The behaviour is a property of the encoding's novelty handling, not of maliciousness.

### 11.6 Leave-one-family-out: `leave_one_family_out-20261016T181651Z`

Each of 10 family groups is held out, together with one rotating benign capture.

| Track | RF AP (pooled) | RF recall / FPR @val | Per-family RF detection @val (selection) |
|---|---|---|---|
| A_FLOW | **0.710 [0.456, 0.962]** | 37.1 % / 8.0 % | AsyncRAT_XWorm 0 %, Lumma 5 %, NetSupport_StealC 0 %, Pikabot 0 %, Trickbot 0 %, XLoader 1 %, Remcos 38 %, DarkGate 43 %, Dridex 60 % |
| D_JA3_FLOW | 0.992 [0.937, 1.000] | 98.5 % / 20.0 % | NetSupport_StealC 0 %, Pikabot 0 %, XLoader 11 %, AsyncRAT_XWorm 37 %, Lumma 65 %, Dridex/Trickbot/Remcos/DarkGate 100 % |
| E_JA4_FLOW | 0.982 [0.918, 1.000] | 99.0 % / 17.8 % | NetSupport_StealC 0 %, XLoader 20 %, AsyncRAT_XWorm 53 %, Pikabot 65 %, Lumma 79 %, others 100 % |

* The flow-only AP falls from 0.931 (capture-grouped) to 0.710 when whole families are unseen.
* The fusion tracks keep a high AP, but their validation-selected thresholds produce 18–20 % test FPR.
* The fold that pairs a family with benign capture CTU-Normal-21 shows about 40 % FPR (A_FLOW), consistent with §11.1.
* HGB results (AP 0.630 for A; 0.982 for D and E) are in the suite summary.

### 11.7 Legacy behavioural-hash holdout: `legacy_behavioral_holdout-20261016T184825Z`

This is the Phase 7 protocol: one 80/20 `GroupShuffleSplit` on `behavioral_hash`, so captures appear on both sides.

| Track (RF) | Legacy AP | Recall / FPR @val (legacy) | Capture-grouped AP (§11.1) | Recall / FPR @val (capture-grouped) |
|---|---|---|---|---|
| A_FLOW | 0.992 [0.976, 0.999] | 95.0 % / 1.1 % | 0.931 | 49.5 % / 5.8 % |
| B_JA3 / C_JA4 | 1.000 | 100 % / 0.4 % | 0.971 / 0.994 | 99.8 % / 18.6 % |
| D_JA3_FLOW / E_JA4_FLOW | 1.000 | 100 % / 0.6 % | 0.988 / 0.991 | 99.5 % / 17.4 %, 99.6 % / 12.1 % |

The legacy protocol overstates both ranking quality and, above all, the achievable operating point. It hides the unseen-fingerprint false positives entirely. Capture-level evaluation is required.

