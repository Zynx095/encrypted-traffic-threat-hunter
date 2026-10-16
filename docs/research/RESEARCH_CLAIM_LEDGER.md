# Research Claim Ledger

The ledger is **generated**, not hand-written. Each claim is evaluated by a fixed rule in `ml/reporting/claims.py` against persisted artefacts: corpus reports, suite summaries, experiment records and tests.

* Live version: `data/experiments/reports/claim_ledger.json` (also served at `GET /api/research/claims` and shown in the Research Workbench, Claims tab).
* Regenerate: `python -m ml report`

## Status vocabulary and rules

| Status | Meaning in this project |
|---|---|
| SUPPORTED | Directly verified (deterministic rebuild, descriptive corpus facts, engineering properties under test). |
| PRELIMINARY | Exploratory evidence in the claimed direction. **This is the ceiling for any detection-performance claim on the current corpus**, because each dataset contributes a single class. |
| CONTRADICTED | Exploratory evidence against the claim (e.g. a paired CI entirely on the wrong side, Holm-significant). |
| INSUFFICIENT_EVIDENCE | No defensible conclusion. A non-significant or unstable difference falls here; it is never read as "no effect". |
| UNTESTED | The producing experiment has not completed. |
| BLOCKED | A prerequisite (independent data, confirmatory source) is unavailable. |

Every claim record carries: claim text, supporting experiment IDs, datasets, protocol, metrics, uncertainty, assumptions, known confounders and limitations.

## Snapshot

The table below is copied verbatim from the last generated `claim_ledger.json` (see the generation timestamp in the final report).

Generated 2026-10-16T19:20:06.803974Z.

| ID | Claim | Status |
|---|---|---|
| C01 | Corpus v3 reproduces the Stage 6.5 DS-008 flow, JA3 and JA4 counts from checksum-verified inputs. | **SUPPORTED** |
| C02 | The admitted benign corpus is sufficient to investigate generalisation (sufficiency level C). | **BLOCKED** |
| C03 | JA3 and JA4 values observed in the corpus never occur in both classes. | **SUPPORTED** |
| C04 | Adding JA3 to flow features increases average precision on the shared JA3 population (A@JA3POP -> D). | **INSUFFICIENT_EVIDENCE** |
| C05 | Adding JA4 to flow features increases average precision on the shared JA4 population (A@JA4POP -> E). | **INSUFFICIENT_EVIDENCE** |
| C06 | Adding flow features to JA3 increases average precision (B -> D). | **INSUFFICIENT_EVIDENCE** |
| C07 | Adding flow features to JA4 increases average precision (C -> E). | **INSUFFICIENT_EVIDENCE** |
| C08A | Flow-only detectors (A_FLOW) transfer to a held-out malicious source at the validation-selected FPR<=1% threshold. | **CONTRADICTED** |
| C08B | Fingerprint-only detectors (B_JA3, C_JA4) transfer to a held-out malicious source at the validation-selected FPR<=1% threshold. | **INSUFFICIENT_EVIDENCE** |
| C08C | Fusion detectors (D_JA3_FLOW, E_JA4_FLOW) transfer to a held-out malicious source at the validation-selected FPR<=1% threshold. | **CONTRADICTED** |
| C09 | ETTH detection generalises to independent, unseen benign and malicious environments. | **BLOCKED** |
| C10 | Handshake-availability flags alone (no flow statistics, no fingerprints) carry label information beyond prevalence. | **PRELIMINARY** |
| C11 | Flow features identify which malicious source (DS-008 vs DS-009) a flow came from. | **INSUFFICIENT_EVIDENCE** |
| C11B | JA4 alone identifies which malicious source (DS-008 vs DS-009) a TLS flow came from. | **PRELIMINARY** |
| C16 | Fingerprint-only models flag most benign flows whose fingerprint was absent from the training fold. | **PRELIMINARY** |
| C17 | Flow-only (A_FLOW) ranking quality drops when whole malware families are held out. | **PRELIMINARY** |
| C12 | The legacy behavioural-hash holdout gives a higher A_FLOW estimate than capture-grouped CV. | **PRELIMINARY** |
| C13 | Sequence models (CNN/GRU on the first 64 packets) add detection value over information-matched tabular baselines. | **INSUFFICIENT_EVIDENCE** |
| C14 | Real-time inference only uses registered, checksum-verified models and never derives a score from ground-truth labels. | **SUPPORTED** |
| C15 | The system does not decrypt TLS application payloads. | **SUPPORTED** |

Each claim's evidence, metrics, uncertainty, confounders and limitations are in `data/experiments/reports/claim_ledger.json` and in `latest_report.md`.

### Reading the snapshot

* **Supported** claims are engineering, reproducibility and descriptive facts: C01, C03, C14, C15.
* **No detection-performance claim is SUPPORTED.**
* The incremental-value claims C04–C07, which are the central research question, are **INSUFFICIENT_EVIDENCE**. On the shared TLS population both flow-only and fusion models are near the ceiling on source-confounded data.
* Cross-source transfer is **CONTRADICTED** for flow-only and fusion models (C08A, C08C). It is **INSUFFICIENT_EVIDENCE** for fingerprint-only models, whose held-out-source detection is all-or-nothing (C08B).
* The preliminary diagnostics C10, C11B, C16, C17 and C12 describe shortcut and novelty effects.
* Generalisation (C09) and benign sufficiency (C02) are **BLOCKED** on independent data.
