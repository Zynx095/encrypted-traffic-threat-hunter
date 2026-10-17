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

Generated 2026-10-17T03:57:52.178674Z (integration branch `integration/phase-8-12-validation`).

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
| C18 | The Zeek, Suricata and eBPF adapters normalise records into the canonical flow contract without fabricating fingerprints, endpoints, protocols, durations or rates, and without silently dropping, duplicating or relabelling records. | **SUPPORTED** |
| C19 | Models trained on ETTH packet features and ETTH JA4 refuse sensor-aggregate statistics and FoxIO JA4 instead of scoring them. | **SUPPORTED** |
| C20 | Live capture produces the same flows (boundaries, initiator direction) and the same flow and TLS feature values as the offline PCAP pipeline for the same packets. | **SUPPORTED** |
| C21 | ETTH detection models can score flows observed by Zeek, Suricata or eBPF sensors. | **BLOCKED** |

Each claim's evidence, metrics, uncertainty, confounders and limitations are in `data/experiments/reports/claim_ledger.json` and in `latest_report.md`.

### Reading the snapshot

* **Supported** claims are engineering, reproducibility and descriptive facts: C01, C03, C14, C15, and the integration properties C18–C20. C18–C20 are verified with synthetic fixtures and packets only.
* **No detection-performance claim is SUPPORTED.**
* The incremental-value claims C04–C07, which are the central research question, are **INSUFFICIENT_EVIDENCE**. On the shared TLS population both flow-only and fusion models are near the ceiling on source-confounded data.
  * The status rule uses the pre-declared primary model (random forest).
  * The evidence also reports the secondary models. Logistic regression gains ΔAP +0.0004 (JA3) and +0.0005 (JA4) on AP ≈ 0.9994. That is Holm-significant within the model's four contrasts (p 0.032 / 0.042), but not after Holm across all 12 model × contrast tests (p 0.096 / 0.154). Gradient boosting and random forest show no difference.
* Cross-source transfer is **CONTRADICTED** for flow-only and fusion models (C08A, C08C). It is **INSUFFICIENT_EVIDENCE** for fingerprint-only models, whose held-out-source detection is all-or-nothing (C08B).
* The preliminary diagnostics C10, C11B, C16, C17 and C12 describe shortcut and novelty effects.
* Generalisation (C09) and benign sufficiency (C02) are **BLOCKED** on independent data. Detection on sensor telemetry (C21) is **BLOCKED** on sensor-aware models and labelled sensor data.
* Every number behind these statuses was re-checked with `python -m ml verify`:
  * 124/124 experiment records reproduce from their out-of-fold predictions (checksums, AP, FPR/recall at the validation threshold, class counts);
  * re-deriving the ledger from the artefacts gives the same statuses.

## Reconciliation with the Phase 12 draft ledger

The Phase 12 branch (`research/phase-12-paper-manuscript`, `7c609af`) contained a hand-written ledger, *ETTH Research Claim Ledger*. It was based on the Phase 7 pilot and written before any Phase 8–10 result existed.

During the cross-phase merge the generated ledger above was kept as the authoritative version, for two reasons:
* it is computed from persisted artefacts by `ml/reporting/claims.py`;
* the hand-written version contradicts those artefacts.

What happened to each Phase 12 claim. The original text is preserved in Git history on the Phase 12 branch.

| Phase 12 claim | Phase 12 status | Disposition after reconciliation |
|---|---|---|
| 1. Zero-decryption metadata sufficiency | VERIFIED | Same claim as **C15** (SUPPORTED, an engineering property under test). Phase 12's ECH and mid-stream-capture limitations are kept: if the ClientHello is missed or encrypted (full ECH), no fingerprint exists and only flow features remain. |
| 2. Five "mutually exclusive" tracks under leakage-free `GroupShuffleSplit` | VERIFIED | **Corrected.** <ul><li>The tracks are not mutually exclusive: D and E contain all of A's inputs, and B–E are restricted to the fingerprint-available population.</li><li>The behavioural-hash `GroupShuffleSplit` keeps duplicate vectors apart but not captures. It gives higher estimates than capture-grouped CV (**C12**, PRELIMINARY), and Phase 9 replaced it.</li><li>Leakage controls are now an engineering claim covered by tests (see C14 and `PHASE_9_BENCHMARK_PROTOCOL.md`).</li></ul> |
| 3. Pilot PR-AUC ≈ 1.0 / F1 ≈ 0.99 | engineering demonstration; contradicted as generalised performance | **Not a claim.** The Phase 7 pilot (2,543 malicious vs 6 benign flows) treats the 99.7 %-prevalent class as positive, so its PR-AUC carries no information. It is historical only. |
| 4. JA4 discriminates better than JA3 | NOT YET TESTED | **Untested.** No pre-declared B vs C contrast exists. ETTH's JA4 is not FoxIO-conformant (signature algorithms are sorted; see `docs/integration/CROSS_PHASE_CONTRACTS.md`), so no statement about FoxIO JA4 can be tested with the current corpus. |
| 5. Sequence models beat tabular statistics | NOT YET TESTED | **Executed in Phase 10; see C13 (INSUFFICIENT_EVIDENCE).** The CNN and GRU did not exceed the information-matched tabular baseline, and the GRU was worse than the full-flow baseline in one exploratory contrast. |
| 6. Cross-sensor identity resolution across Zeek, Suricata and eBPF | PROVISIONALLY SUPPORTED | **Withdrawn: unsupported.** No cross-sensor correlation is implemented. Each adapter correlates records only within its own sensor (Zeek `uid`, Suricata `flow_id`), and only synthetic fixtures were tested. The engineering claims about the sensor adapters are tracked separately in the generated ledger. |
