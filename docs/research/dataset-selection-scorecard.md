# Dataset Selection Scorecard for ETTH

**Date:** 2026-08-14
**Purpose:** Provide a transparent, evidence-based scoring framework for comparing candidate datasets against ETTH's experimental requirements
**Scope:** This scorecard evaluates the datasets currently registered in `dataset-registry.csv`. It does NOT make a final dataset selection.
**Companion file:** `dataset-verification-queue.md` — prioritized list of unresolved verification items

---

## 1. Research Question the Scorecard Must Serve

The scorecard weights criteria according to the ETTH primary research question:

> Does combining TLS fingerprint features (JA4/JA3S) with encrypted-flow behavioral features provide statistically significant improvement in detection performance compared to using either feature family in isolation?

Consequences for scoring:
- **JA4/JA3S/JA3 computability and ClientHello/ServerHello availability are mandatory prerequisites** for experiments B–E.
- **Raw PCAP availability** is mandatory because fingerprints cannot be computed from aggregated CSV features.
- **Flow statistics, packet lengths, and IATs** are mandatory for experiments A, D, and E.
- **Malware and benign labels** are mandatory for the binary malicious/benign classification task.
- **TLS 1.3 representation** is highly important because the ETTH claim concerns modern traffic.
- **Dataset size alone must not dominate the ranking**; it is capped as a criterion.

---

## 2. Scoring Framework

### 2.1 Scoring Scale

Every criterion is scored on a 0–3 scale, consistent with `dataset-acceptance-criteria.md`:

| Score | Meaning |
|-------|---------|
| 0 | Property absent or dataset unusable for the required purpose. |
| 1 | Property exists but is weak, incomplete, or poorly documented. |
| 2 | Property exists and is acceptable, with minor reservations. |
| 3 | Property exists, is well documented, and is strongly supported by direct evidence. |

**Important rule:** A criterion must NEVER be scored 2 or 3 based on inference. If evidence is missing, the criterion receives score 1 at most, and the dataset's `verification_status` must remain `PENDING` or `PARTIALLY_VERIFIED`. In the tables below, `NV` (NOT_VERIFIED) is scored as 1 (or 0 where a hard requirement exists) and is explicitly flagged.

### 2.2 Criteria Definitions

| ID | Criterion | What Is Being Scored | Scoring Rule |
|----|-----------|----------------------|--------------|
| A | Raw PCAP availability | Raw packet capture files available in the distribution | 3 = official download with PCAPs; 2 = PCAPs via mirror; 1 = PCAPs mentioned but unverified; 0 = no PCAPs |
| B | Bidirectional traffic | Both client→server and server→client directions present | 3 = verified bidirectional capture; 2 = implied; 1 = unverified; 0 = single-direction |
| C | ClientHello availability | TLS ClientHello records present with fingerprint fields | 3 = verified on sample PCAP; 2 = documented by authors; 1 = unverified; 0 = absent |
| D | ServerHello availability | TLS ServerHello records present | 3 = verified on sample PCAP; 2 = documented; 1 = unverified; 0 = absent |
| E | JA3 computability | JA3 fingerprints computable from raw data | 3 = extraction verified; 2 = extraction attempted with partial success; 1 = unverified; 0 = impossible |
| F | JA3S computability | JA3S fingerprints computable | Same rule as E |
| G | JA4 computability | JA4 fingerprints computable | Same rule as E |
| H | TLS 1.3 representation | Meaningful proportion of TLS 1.3 flows with AEAD ciphers | 3 = verified significant TLS 1.3; 2 = some TLS 1.3 documented; 1 = unverified; 0 = confirmed absent |
| I | Modern encrypted traffic relevance | Collection recency and protocol relevance | 3 = collected ≤5 years ago with modern protocols; 2 = partially modern; 1 = legacy; 0 = obsolete |
| J | Malware traffic | Malware-labeled flows present | 3 = documented families; 2 = malware present, poorly documented; 1 = unverified; 0 = absent |
| K | C2 relevance | C2 framework or beaconing traffic present | 3 = explicit C2 tools documented; 2 = likely C2, undocumented; 1 = unverified; 0 = absent |
| L | Benign traffic | Benign-labeled flows present | 3 = documented real/simulated benign; 2 = benign present, weakly documented; 1 = unverified; 0 = absent |
| M | Label quality | Labeling process documented and validated | 3 = documented with validation; 2 = documented without validation; 1 = undocumented; 0 = known-wrong labels |
| N | Class balance | Class distribution documented and not extreme | 3 = balanced and documented; 2 = imbalanced but documented; 1 = undocumented; 0 = extreme imbalance |
| O | Flow statistics availability | Flow features extractable | 3 = verified extraction; 2 = documented; 1 = unverified; 0 = impossible |
| P | Packet length availability | Per-packet size information available | 3 = verified; 2 = documented; 1 = unverified; 0 = absent |
| Q | IAT availability | Packet timestamps for inter-arrival times | 3 = verified microsecond precision; 2 = documented; 1 = unverified; 0 = absent |
| R | Capture-environment quality | Environment documented (hardware, OS, topology) | 3 = fully documented; 2 = partially documented; 1 = undocumented; 0 = n/a |
| S | Temporal information | Time metadata present with sufficient precision | 3 = verified; 2 = documented; 1 = unverified; 0 = absent |
| T | Dataset size | Sufficient samples for stratified evaluation | 3 = ≥10⁵ flows; 2 = 10⁴–10⁵; 1 = 10³–10⁴; 0 = <10³ (capped: cannot exceed 3) |
| U | Cross-dataset/generalization value | Value for testing model generalization | 3 = distinct environment/collection from other candidates; 2 = partially distinct; 1 = similar to others; 0 = n/a |
| V | Reproducibility/accessibility | Public access with clear license | 3 = open download, clear license; 2 = registration required; 1 = unverified access; 0 = restricted/paywalled |

---

## 3. Weighting Methodology

### 3.1 Weight Assignment Logic

Weights reflect the ETTH research question directly. The three feature families being compared (flow-only, TLS-fingerprint-only, combined) impose the following importance tiers:

**MANDATORY (highest weight, 3.0):**
- A (Raw PCAP) — prerequisite for any fingerprint experiment.
- C (ClientHello) — prerequisite for JA3/JA4.
- D (ServerHello) — prerequisite for JA3S/JA4S.
- E (JA3 computability) — experiment B/D.
- F (JA3S computability) — experiment B/D.
- G (JA4 computability) — experiments C/E (central research question).
- O (Flow statistics) — experiments A/D/E.
- P (Packet lengths) — core flow feature.
- Q (IAT) — core flow feature.
- J (Malware traffic) — required for the threat-hunting classification task.
- L (Benign traffic) — required for binary classification.

**HIGHLY IMPORTANT (weight 2.0):**
- H (TLS 1.3 representation) — modern relevance of conclusions.
- I (Modern traffic relevance) — generalizability.
- M (Label quality) — validity of supervised learning.
- N (Class balance) — validity of per-class metrics.
- V (Reproducibility) — scientific reproducibility.

**SUPPORTING (weight 1.0):**
- B (Bidirectional traffic) — needed but often implied by PCAP presence.
- K (C2 relevance) — desirable but not strictly mandatory.
- R (Capture-environment quality) — context for bias interpretation.
- S (Temporal information) — needed for IAT, partially redundant with Q.
- T (Dataset size) — **deliberately capped at weight 1.0 so size never dominates.**
- U (Cross-dataset/generalization value) — context for validation planning.

### 3.2 Weight Table

| ID | Criterion | Weight |
|----|-----------|--------|
| A | Raw PCAP availability | 3.0 |
| B | Bidirectional traffic | 1.0 |
| C | ClientHello availability | 3.0 |
| D | ServerHello availability | 3.0 |
| E | JA3 computability | 3.0 |
| F | JA3S computability | 3.0 |
| G | JA4 computability | 3.0 |
| H | TLS 1.3 representation | 2.0 |
| I | Modern traffic relevance | 2.0 |
| J | Malware traffic | 3.0 |
| K | C2 relevance | 1.0 |
| L | Benign traffic | 3.0 |
| M | Label quality | 2.0 |
| N | Class balance | 2.0 |
| O | Flow statistics | 3.0 |
| P | Packet lengths | 3.0 |
| Q | IAT availability | 3.0 |
| R | Capture-environment quality | 1.0 |
| S | Temporal information | 1.0 |
| T | Dataset size | 1.0 |
| U | Generalization value | 1.0 |
| V | Reproducibility/accessibility | 2.0 |

### 3.3 Score Computation

- **Maximum possible score:** Σ(weight × 3) = 3(3+3+3+3+3+3+3+3+3+3+3) + 2(2+2+2+2+2) + 1(1+1+1+1+1+1) = 3×11 + 2×5 + 1×6 = 33 + 10 + 6 = **49**.
- **Dataset score:** Σ(weight × criterion_score). Reported as a raw score and as a percentage of the maximum.
- **Percentages are informative, not decisive.** A dataset can score highly only on criteria that matter to the ETTH question; the score is a decision-support tool, not a substitute for the acceptance criteria or verification.

### 3.4 Explicit Anti-Dominance Rule

> **Dataset size (T) is capped at weight 1.0 and score 3.** A dataset with 10⁸ flows cannot outrank a dataset with 10⁵ flows on size alone; size contributes at most 3 of 49 points (6.1%). Raw PCAP, ClientHello/ServerHello, JA3/JA4 computability, flow features, and malware/benign labels together contribute 33 of 49 points (67.3%) and dominate the ranking.

---

## 4. Candidate Scoring (Current Registry)

Scores are derived ONLY from the evidence recorded in `dataset-registry.csv`, `dataset-evaluation.md`, and `dataset-acceptance-criteria.md`. Where the registry records `NOT_VERIFIED`, the criterion is scored **1** (weak/unverified) and the dataset is flagged as requiring verification. `VERIFIED_NO` is scored **0**.

### 4.1 DS-001 — ISCXVPN2016 (2016)

| ID | Criterion | Score | Justification |
|----|-----------|-------|---------------|
| A | Raw PCAP | 3 | Official CIC page; ~28 GB PCAPs |
| B | Bidirectional | 1 | NOT_VERIFIED |
| C | ClientHello | 1 | NOT_VERIFIED; PCAPs exist but presence not confirmed |
| D | ServerHello | 1 | NOT_VERIFIED |
| E | JA3 computable | 1 | NOT_VERIFIED (likely but untested) |
| F | JA3S computable | 1 | NOT_VERIFIED |
| G | JA4 computable | 1 | NOT_VERIFIED |
| H | TLS 1.3 | 0 | VERIFIED_NO (TLS 1.2 dominant) |
| I | Modern relevance | 1 | Pre-2018 collection; deprecated ciphers |
| J | Malware | 0 | VERIFIED_NO |
| K | C2 | 0 | NOT_APPLICABLE |
| L | Benign | 3 | Documented benign VPN/non-VPN app traffic |
| M | Label quality | 2 | PARTIALLY_VERIFIED |
| N | Class balance | 2 | PARTIALLY_VERIFIED (imbalance known) |
| O | Flow stats | 3 | CICFlowMeter CSVs + extractable from PCAP |
| P | Packet lengths | 3 | Raw PCAPs |
| Q | IAT | 3 | Raw PCAP timestamps |
| R | Capture env | 2 | PARTIALLY_VERIFIED |
| S | Temporal | 3 | Timestamps present |
| T | Size | 3 | ~158K flows |
| U | Generalization | 2 | Distinct benign app set |
| V | Reproducibility | 3 | Open download |

**Weighted score:** Σ(w×s) = 3(A=3,C=1,D=1,E=1,F=1,G=1,J=0,L=3,O=3,P=3,Q=3) + 2(H=0,I=1,M=2,N=2,V=3) + 1(B=1,K=0,R=2,S=3,T=3,U=2)
= 3×20 + 2×8 + 1×11 = 60 + 16 + 11 = **87 of 147** → **59.2%**

### 4.2 DS-002 — CIC-Darknet2020 (2020)

| ID | Criterion | Score | Justification |
|----|-----------|-------|---------------|
| A | Raw PCAP | 0 | VERIFIED_NO (CSV-only distribution) |
| B | Bidirectional | 0 | NOT_APPLICABLE (no raw data) |
| C | ClientHello | 0 | VERIFIED_NO |
| D | ServerHello | 0 | VERIFIED_NO |
| E | JA3 computable | 0 | VERIFIED_NO |
| F | JA3S computable | 0 | VERIFIED_NO |
| G | JA4 computable | 0 | VERIFIED_NO |
| H | TLS 1.3 | 0 | NOT_APPLICABLE (not in distribution) |
| I | Modern relevance | 2 | 2020 collection |
| J | Malware | 0 | VERIFIED_NO (Tor/VPN, not malware) |
| K | C2 | 0 | NOT_APPLICABLE |
| L | Benign | 3 | Non-Tor non-VPN benign samples |
| M | Label quality | 2 | PARTIALLY_VERIFIED |
| N | Class balance | 0 | VERIFIED_NO (extreme 67:1 imbalance) |
| O | Flow stats | 3 | Precomputed CICFlowMeter CSVs |
| P | Packet lengths | 2 | Flow-level length features only |
| Q | IAT | 2 | Flow-level IAT features only |
| R | Capture env | 2 | PARTIALLY_VERIFIED |
| S | Temporal | 2 | Flow timestamps |
| T | Size | 3 | ~158K samples |
| U | Generalization | 1 | Derived from ISCXVPN2016/ISCXTor2016 |
| V | Reproducibility | 3 | Open download |

**Weighted score:** 3(A=0,C=0,D=0,E=0,F=0,G=0,J=0,L=3,O=3,P=2,Q=2) + 2(H=0,I=2,M=2,N=0,V=3) + 1(B=0,K=0,R=2,S=2,T=3,U=1)
= 3×10 + 2×7 + 1×8 = 30 + 14 + 8 = **52 of 147** → **35.4%**

### 4.3 DS-003 — USTC-TFC2016 (2016)

| ID | Criterion | Score | Justification |
|----|-----------|-------|---------------|
| A | Raw PCAP | 3 | GitHub distribution, 3.71 GB, 20 PCAPs |
| B | Bidirectional | 1 | NOT_VERIFIED |
| C | ClientHello | 1 | NOT_VERIFIED |
| D | ServerHello | 1 | NOT_VERIFIED |
| E | JA3 computable | 1 | NOT_VERIFIED |
| F | JA3S computable | 1 | NOT_VERIFIED |
| G | JA4 computable | 1 | NOT_VERIFIED |
| H | TLS 1.3 | 0 | VERIFIED_NO |
| I | Modern relevance | 1 | 2011–2016 collection; deprecated ciphers |
| J | Malware | 3 | 10 malware families from CTU |
| K | C2 | 2 | Malware captures likely include C2, undocumented |
| L | Benign | 3 | 10 benign app classes |
| M | Label quality | 2 | PARTIALLY_VERIFIED (sandbox bias known) |
| N | Class balance | 1 | NOT_VERIFIED |
| O | Flow stats | 3 | Extractable from PCAPs |
| P | Packet lengths | 3 | Raw PCAPs |
| Q | IAT | 3 | Raw PCAP timestamps |
| R | Capture env | 2 | PARTIALLY_VERIFIED |
| S | Temporal | 3 | Timestamps present |
| T | Size | 2 | 3.71 GB, 20 classes |
| U | Generalization | 2 | Distinct from ISCX/CIC collections |
| V | Reproducibility | 3 | Open GitHub download |

**Weighted score:** 3(A=3,C=1,D=1,E=1,F=1,G=1,J=3,L=3,O=3,P=3,Q=3) + 2(H=0,I=1,M=2,N=1,V=3) + 1(B=1,K=2,R=2,S=3,T=2,U=2)
= 3×23 + 2×7 + 1×12 = 69 + 14 + 12 = **95 of 147** → **64.6%**

### 4.4 DS-004 — CipherSpectrum (2025)

| ID | Criterion | Score | Justification |
|----|-----------|-------|---------------|
| A | Raw PCAP | 1 | NOT_VERIFIED (access conditions unknown) |
| B | Bidirectional | 1 | NOT_VERIFIED |
| C | ClientHello | 1 | NOT_VERIFIED |
| D | ServerHello | 1 | NOT_VERIFIED |
| E | JA3 computable | 1 | NOT_VERIFIED |
| F | JA3S computable | 1 | NOT_VERIFIED |
| G | JA4 computable | 1 | NOT_VERIFIED |
| H | TLS 1.3 | 3 | VERIFIED_YES (TLS 1.3 AEAD focus) |
| I | Modern relevance | 3 | IEEE S&P 2025 |
| J | Malware | 1 | NOT_VERIFIED |
| K | C2 | 1 | NOT_VERIFIED |
| L | Benign | 1 | NOT_VERIFIED |
| M | Label quality | 1 | NOT_VERIFIED |
| N | Class balance | 1 | NOT_VERIFIED |
| O | Flow stats | 1 | NOT_VERIFIED |
| P | Packet lengths | 1 | NOT_VERIFIED |
| Q | IAT | 1 | NOT_VERIFIED |
| R | Capture env | 1 | NOT_VERIFIED |
| S | Temporal | 1 | NOT_VERIFIED |
| T | Size | 2 | 120K sessions (reported, unverified) |
| U | Generalization | 2 | Independent of legacy ISCX/CIC collections |
| V | Reproducibility | 1 | Access conditions unverified |

**Weighted score:** 3(A=1,C=1,D=1,E=1,F=1,G=1,J=1,L=1,O=1,P=1,Q=1) + 2(H=3,I=3,M=1,N=1,V=1) + 1(B=1,K=1,R=1,S=1,T=2,U=2)
= 3×11 + 2×9 + 1×8 = 33 + 18 + 8 = **59 of 147** → **40.1%**

**Critical caveat:** This score is dominated by NOT_VERIFIED entries scored at 1. The dataset is the ONLY current candidate with verified TLS 1.3, but nothing else is verified. It is a PENDING candidate, not a ranked leader.

### 4.5 DS-005 — CSTNET-TLS1.3

| ID | Criterion | Score | Justification |
|----|-----------|-------|---------------|
| A | Raw PCAP | 1 | NOT_VERIFIED |
| B | Bidirectional | 1 | NOT_VERIFIED |
| C | ClientHello | 1 | NOT_VERIFIED |
| D | ServerHello | 1 | NOT_VERIFIED |
| E | JA3 computable | 1 | NOT_VERIFIED |
| F | JA3S computable | 1 | NOT_VERIFIED |
| G | JA4 computable | 1 | NOT_VERIFIED |
| H | TLS 1.3 | 3 | VERIFIED_YES (exclusive TLS 1.3 per secondary source) |
| I | Modern relevance | 2 | Modern protocol, but collection date unverified |
| J | Malware | 1 | NOT_VERIFIED |
| K | C2 | 1 | NOT_VERIFIED |
| L | Benign | 1 | NOT_VERIFIED |
| M | Label quality | 1 | NOT_VERIFIED |
| N | Class balance | 1 | NOT_VERIFIED |
| O | Flow stats | 1 | NOT_VERIFIED |
| P | Packet lengths | 1 | NOT_VERIFIED |
| Q | IAT | 1 | NOT_VERIFIED |
| R | Capture env | 1 | NOT_VERIFIED |
| S | Temporal | 1 | NOT_VERIFIED |
| T | Size | 1 | NOT_VERIFIED |
| U | Generalization | 2 | Independent origin |
| V | Reproducibility | 1 | Access unverified |

**Weighted score:** 3(A=1,C=1,D=1,E=1,F=1,G=1,J=1,L=1,O=1,P=1,Q=1) + 2(H=3,I=2,M=1,N=1,V=1) + 1(B=1,K=1,R=1,S=1,T=1,U=2)
= 3×11 + 2×8 + 1×7 = 33 + 16 + 7 = **56 of 147** → **38.1%**

**Critical caveat:** Like DS-004, this score reflects unverified status, not confirmed weakness. Both TLS 1.3 candidates remain PENDING.

---

## 5. Provisional Dataset Roles

Roles are provisional research assignments, NOT final decisions. They are informed by the scorecard but constrained by the acceptance criteria and verification status.

| Dataset | Provisional Role | Rationale |
|---------|------------------|-----------|
| DS-001 ISCXVPN2016 | LEGACY_COMPARISON; FLOW_ONLY | Benign-only; PCAPs exist; no malware; legacy TLS |
| DS-002 CIC-Darknet2020 | FLOW_ONLY | No raw PCAPs; cannot support fingerprint experiments |
| DS-003 USTC-TFC2016 | PRIMARY_CANDIDATE (provisional); LEGACY_COMPARISON | Only current candidate with raw PCAPs + malware + benign; needs JA4 verification |
| DS-004 CipherSpectrum | MODERN_TLS_VALIDATION | Verified TLS 1.3; everything else PENDING |
| DS-005 CSTNET-TLS1.3 | MODERN_TLS_VALIDATION; REJECT_PENDING_VERIFICATION | Exclusive TLS 1.3 claim; access unverified |

---

## 6. Experiment Mapping

Mapping rules:
- Experiment A (Flow-only) requires: flow features, packet lengths, IATs, benign + malware labels.
- Experiment B (JA3-only) requires: ClientHello + ServerHello, JA3/JA3S computability, benign + malware labels.
- Experiment C (JA4-only) requires: ClientHello + ServerHello, JA4 computability, benign + malware labels.
- Experiment D (JA3 + Flow) requires: everything in A and B.
- Experiment E (JA4 + Flow) requires: everything in A and C.

| Dataset | A (Flow-only) | B (JA3-only) | C (JA4-only) | D (JA3+Flow) | E (JA4+Flow) |
|---------|---------------|--------------|--------------|--------------|--------------|
| DS-001 ISCXVPN2016 | SUPPORTED (no malware; benign-classification only) | PENDING_VERIFICATION | PENDING_VERIFICATION | PENDING_VERIFICATION | PENDING_VERIFICATION |
| DS-002 CIC-Darknet2020 | SUPPORTED (flow-only; no fingerprint exps.) | NOT_SUPPORTED | NOT_SUPPORTED | NOT_SUPPORTED | NOT_SUPPORTED |
| DS-003 USTC-TFC2016 | SUPPORTED | PENDING_VERIFICATION | PENDING_VERIFICATION | PENDING_VERIFICATION | PENDING_VERIFICATION |
| DS-004 CipherSpectrum | PENDING_VERIFICATION | PENDING_VERIFICATION | PENDING_VERIFICATION | PENDING_VERIFICATION | PENDING_VERIFICATION |
| DS-005 CSTNET-TLS1.3 | PENDING_VERIFICATION | PENDING_VERIFICATION | PENDING_VERIFICATION | PENDING_VERIFICATION | PENDING_VERIFICATION |

**Summary:**
- **SUPPORTED now:** Experiment A on DS-001, DS-002, DS-003 (flow features verified).
- **NOT_SUPPORTED now:** Experiments B–E on all datasets until ClientHello/ServerHello and JA3/JA4 computability are verified on sample PCAPs. DS-002 is permanently NOT_SUPPORTED for B–E (no raw PCAPs).
- **PENDING_VERIFICATION:** everything else.

---

## 7. Experimentally Dangerous Datasets

The following risks are flagged per dataset. Each risk matters because it can produce inflated, non-generalizable results.

### 7.1 SNI Leakage
- **Affects:** DS-001, DS-003 (raw PCAPs; SNI visible in ClientHello).
- **Why it matters:** A classifier can learn to predict the class from the SNI string rather than from traffic behavior, inflating accuracy and destroying generalization (documented by wickramasinghe2025sok, zhao2025sugar).
- **Mitigation:** Mask/remove SNI in flow features; treat SNI-derived labels separately from SNI-based features.

### 7.2 IP/Port Leakage
- **Affects:** DS-001, DS-002, DS-003.
- **Why it matters:** IP addresses, ports, and protocol fields can act as shortcuts (e.g., CIC-Darknet2020's Tor-IP list).
- **Mitigation:** Remove source/dest IP and port columns from feature vectors; verify model does not rely on them (SHAP inspection).

### 7.3 Timestamp Leakage
- **Affects:** DS-001, DS-003.
- **Why it matters:** Flow IDs and timestamps can encode session identity, enabling per-packet split shortcuts.
- **Mitigation:** Per-flow splits only; do not use flow ID as a feature.

### 7.4 Capture-Environment Leakage
- **Affects:** DS-003 (synthetic benign from network instruments), DS-001 (lab capture).
- **Why it matters:** Classifiers may learn capture artifacts (e.g., TCP offload behavior, timing precision) instead of real traffic patterns.
- **Mitigation:** Cross-dataset validation; report environment artifacts.

### 7.5 Malware-Family Memorization
- **Affects:** DS-003 (10 specific malware families from CTU).
- **Why it matters:** A model may memorize family-specific TLS parameter sets rather than general malware behavior (anderson2016deciphering).
- **Mitigation:** Report per-family results; do not claim general malware detection beyond the families present.

### 7.6 Duplicate Flows Across Splits
- **Affects:** DS-001, DS-002 (ISCXVPN2016 is a constituent of CIC-Darknet2020).
- **Why it matters:** Using both datasets in the same train/test split can leak data through duplicated flows.
- **Mitigation:** Never mix DS-001 and DS-002 in the same split; document lineage.

### 7.7 Dataset-Source Classification
- **Affects:** DS-001 vs DS-003 vs DS-004 (distinct capture environments).
- **Why it matters:** A model can learn "this dataset" rather than "this behavior," inflating cross-dataset claims.
- **Mitigation:** Use cross-dataset evaluation as the test of generalization, not the same-environment re-split.

### 7.8 Unrealistic TLS Distributions
- **Affects:** DS-001, DS-003 (TLS 1.2 dominant, deprecated ciphers), DS-005 (exclusive TLS 1.3 claim).
- **Why it matters:** Results on legacy cipher distributions do not transfer to modern networks.
- **Mitigation:** Report TLS version/cipher distributions; treat TLS 1.3 results as a separate validation scope.

### 7.9 Insufficient ClientHello / ServerHello Information
- **Affects:** All datasets (unverified); DS-002 confirmed absent.
- **Why it matters:** JA3/JA4/JA3S cannot be computed without these records; experiments B–E are impossible.
- **Mitigation:** P0 verification: run JA3/JA4 extraction on sample PCAPs.

### 7.10 Severe Class Imbalance
- **Affects:** DS-002 (67:1 Tor:non-Tor).
- **Why it matters:** Inflates accuracy, hides poor minority-class performance.
- **Mitigation:** Per-class metrics, stratified splits, or balanced sampling.

---

## 8. "Big Data" vs. "Good Research Data"

A very large dataset is NOT automatically better. The following considerations apply to all candidates:

1. **Raw PCAP availability:** A 10⁸-flow CSV with no PCAPs (e.g., DS-002) cannot support fingerprint experiments regardless of size. Size cannot substitute for raw data.
2. **Cryptographic relevance:** A large legacy dataset (DS-001, DS-003) with deprecated cipher suites and no TLS 1.3 cannot support claims about modern TLS, no matter how many flows it has.
3. **Label quality:** A huge dataset with undocumented or sandbox-biased labels (DS-003) produces confident but misleading metrics. Size amplifies label noise.
4. **Malware realism:** A large benign-only dataset (DS-001) cannot train a malicious/benign classifier at all.
5. **Feature computability:** Large datasets with only precomputed features (DS-002) prevent the extraction of JA3/JA4 or recomputation of features.
6. **Capture diversity:** A single-environment capture, however large, encodes one environment's artifacts. Cross-dataset generalization (criterion U) is undervalued if size is overvalued.
7. **Reproducibility:** A dataset that is large but restricted/unavailable (DS-004, DS-005) cannot be reproduced by others.
8. **Leakage risk:** Large datasets with leakage features (DS-002 IP/port) scale up the leakage, not the science.

**Conclusion:** Size contributes at most 3 of 49 scorecard points (6.1%). Scientific value comes from the combination of raw data, cryptographic relevance, valid labels, and verified fingerprint computability.

---

## 9. Final Dataset Decision Status

> **No final primary dataset has been selected.**

None of the five registered datasets currently satisfies all ETTH requirements:
- DS-001: PCAPs + benign, but no malware and no TLS 1.3.
- DS-002: No raw PCAPs at all.
- DS-003: PCAPs + benign + malware, but legacy TLS, no verified JA4, synthetic benign traffic.
- DS-004: Verified TLS 1.3 but everything else unverified and access uncertain.
- DS-005: Exclusive TLS 1.3 claim but entirely unverified.

The selection will be made only after the P0 verification items in `dataset-verification-queue.md` are resolved, and after any additional candidate datasets discovered during Phase 6 are evaluated with this same scorecard.

---

## 10. Decision Table

| Dataset | Overall Score (%) | ETTH Role | JA4 | Flow | Malware | TLS 1.3 | Main Strength | Main Limitation | Verification Needed |
| DS-003 USTC-TFC2016 | 64.6% | PRIMARY_CANDIDATE (provisional) | NOT_VERIFIED | VERIFIED_YES | VERIFIED_YES | VERIFIED_NO | Only candidate with raw PCAPs + malware + benign | Legacy TLS; 94.7% unencrypted; synthetic benign; JA4 unverified | JA3/JA4 on sample PCAPs; encrypted-flow class counts; leakage mask |
| DS-001 ISCXVPN2016 | 59.2% | LEGACY_COMPARISON; FLOW_ONLY | NOT_VERIFIED | VERIFIED_YES | VERIFIED_NO | VERIFIED_NO | Large benign app corpus with PCAPs | No malware; 98.9% unencrypted; no TLS 1.3 | JA3/JA4 on sample PCAPs; benign-only role confirmation |
| DS-004 CipherSpectrum | 40.1% | MODERN_TLS_VALIDATION | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | VERIFIED_YES | Verified modern TLS 1.3 (only candidate) | Access unverified; no other property verified | Access request; PCAP/ClientHello inspection; label documentation |
| DS-005 CSTNET-TLS1.3 | 38.1% | MODERN_TLS_VALIDATION; REJECT_PENDING_VERIFICATION | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | VERIFIED_YES (secondary source) | Exclusive TLS 1.3 claim | Entirely unverified; access unknown | Existence/access verification; technical specification review |
| DS-002 CIC-Darknet2020 | 35.4% | FLOW_ONLY | NOT_SUPPORTED | VERIFIED_YES | VERIFIED_NO | NOT_APPLICABLE | Precomputed flow features; 2020 collection | No raw PCAPs; extreme class imbalance; IP/port leakage | None for fingerprint exps; masking + imbalance handling for flow-only |

---
---

## 11. Research Integrity Statement

This scorecard:
- Assigns **no arbitrary scores**; every score maps to the documented scoring rule in Section 2.1 and the evidence in the registry.
- **Never converts NOT_VERIFIED into VERIFIED_YES.** Unverified criteria are scored 1 and flagged.
- **Does not select a final dataset.** Section 9 states this explicitly.
- **Does not let dataset size dominate.** Criterion T is capped at weight 1.0 (Section 3.4).
- **Marks unsupported experiments explicitly.** Section 6 uses NOT_SUPPORTED and PENDING_VERIFICATION.
- **Preserves uncertainty.** DS-004 and DS-005 scores reflect unverified status, and both are labeled PENDING.
- **Documents all leakage risks** with mitigations (Section 7).
- **Introduces no application or ML implementation.** This document is research methodology only.

---

## 12. Validation Checklist

| Check | Status |
|-------|--------|
| All 5 registry datasets represented in scorecard | PASS (DS-001–DS-005) |
| Every score has an understandable justification | PASS (Section 4 tables) |
| Experiment mappings match ETTH experimental design (A–E) | PASS (Section 6) |
| Unsupported experiments clearly marked | PASS (NOT_SUPPORTED / PENDING_VERIFICATION) |
| Unresolved claims remain unresolved | PASS (NOT_VERIFIED → score 1, flagged) |
| No application/ML implementation introduced | PASS (research document only) |
