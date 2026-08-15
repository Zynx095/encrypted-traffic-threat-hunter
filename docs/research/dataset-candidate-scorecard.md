# Dataset Candidate Scorecard for ETTH

**Date:** 2026-08-15
**Purpose:** Provide a transparent, evidence-based scoring framework for comparing all 10 candidate datasets against ETTH's experimental requirements.
**Scope:** This scorecard evaluates DS-001 through DS-010. It dictates which candidates proceed to empirical verification. It does NOT make a final dataset selection.

---

## 1. Purpose

To objectively rank dataset candidates based on their ability to support the core ETTH research question:
> Does combining TLS fingerprint features (JA4/JA3S) with encrypted-flow behavioral features provide statistically significant improvement in detection performance compared to using either feature family in isolation?

---

## 2. Scoring Methodology

The scorecard uses a 49-point system. Every criterion is scored on a 0–3 scale, weighted by importance to the research question.
- **Score 3:** Property exists, is well documented, and is strongly supported by direct evidence.
- **Score 2:** Property exists and is acceptable, with minor reservations.
- **Score 1:** Property is weak, incomplete, or **NOT_VERIFIED**.
- **Score 0:** Property is explicitly absent (`VERIFIED_NO`) or impossible.

**Crucial Constraint:** A criterion must NEVER be scored 2 or 3 based on inference. `NOT_VERIFIED` properties receive a score of 1. Dataset size (Criterion T) is capped at a weight of 1.0 (max 3 points) so that "big data" does not dominate the ranking.

---

## 3. Evidence-Strength Methodology

Evidence supporting claims is categorized into four tiers:
- **STRONG:** Official dataset documentation, original paper, official repository, directly downloadable raw PCAP.
- **MODERATE:** Peer-reviewed paper using the dataset, reproducible extraction repository.
- **WEAK:** Secondary articles, informal descriptions, dataset aggregators.
- **UNKNOWN:** No reliable evidence found.

Claims supported only by WEAK or UNKNOWN evidence receive a score of 1 (`NOT_VERIFIED`).

---

## 4. Full DS-001–DS-010 Comparison

*Note: Scores for DS-001–DS-005 remain unchanged from the previous scorecard. Their low scores primarily reflect unverified properties or obsolete TLS versions.*

| Dataset | Raw Score | Percentage | Provisional Role |
|---------|-----------|------------|------------------|
| **DS-003** (USTC-TFC2016) | 95 / 147 | 64.6% | LEGACY_COMPARISON |
| **DS-001** (ISCXVPN2016) | 87 / 147 | 59.2% | FLOW_ONLY_SUPPLEMENT |
| **DS-006** (Beyond JA4+) | 76 / 147 | 51.7% | PRIMARY_CANDIDATE (Pending PCAP access) |
| **DS-007** (Annotated Encrypted Traffic) | 76 / 147 | 51.7% | PRIMARY_CANDIDATE (Pending PCAP access) |
| **DS-010** (IoT-23) | 75 / 147 | 51.0% | SUPPLEMENTARY (IoT specific) |
| **DS-008** (Malware-Traffic-Analysis) | 75 / 147 | 51.0% | SECONDARY_MALWARE |
| **DS-009** (Stratosphere MCFP) | 70 / 147 | 47.6% | SECONDARY_MALWARE |
| **DS-004** (CipherSpectrum) | 59 / 147 | 40.1% | MODERN_TLS_VALIDATION |
| **DS-005** (CSTNET-TLS1.3) | 56 / 147 | 38.1% | REJECT_PENDING_VERIFICATION |
| **DS-002** (CIC-Darknet2020) | 52 / 147 | 35.4% | FLOW_ONLY (No PCAPs) |

> [!WARNING]
> Scores for DS-006, DS-007, DS-008, and DS-009 are severely depressed by `NOT_VERIFIED` properties (scored 1) regarding JA4 extraction success on their specific PCAPs. If empirical verification succeeds, their scores will rapidly exceed DS-003.

---

## 5. Technical Capability Matrix (Feature Extraction Capability)

This matrix evaluates whether the dataset technically provides the raw materials to extract ETTH features.

| Dataset | Raw PCAPs | ClientHello / ServerHello | JA4 Computable | Flow Features |
|---------|-----------|---------------------------|----------------|---------------|
| DS-003 | YES | PENDING (Benign lacks CH) | FAILED (SSL 3.0) | YES |
| DS-004 | YES | YES | YES | YES |
| DS-006 | YES (Req) | PENDING | PENDING | PENDING |
| DS-007 | YES (Req) | PENDING | PENDING | YES (CSV) |
| DS-008 | YES | PENDING | PENDING | PENDING |
| DS-009 | YES | PENDING | PENDING | PENDING |

---

## 6. Threat-Classification Capability Matrix

This matrix evaluates whether the dataset provides the labeled data required for the binary malware vs. benign classification task under modern conditions.

| Dataset | Malware Traffic | Benign Traffic | TLS 1.3 | Suitable for Primary Classification? |
|---------|-----------------|----------------|---------|--------------------------------------|
| DS-003 | YES (Legacy) | YES (Synthetic)| NO | NO (Legacy TLS, Sandbox bias) |
| DS-004 | NO | NO | YES | NO (No classification labels) |
| DS-006 | YES | YES | YES | **POTENTIALLY YES** |
| DS-007 | YES | YES | PENDING | **POTENTIALLY YES** |
| DS-008 | YES | NO | YES | NO (Requires external benign dataset) |
| DS-009 | YES | NO | PENDING | NO (Requires external benign dataset) |

**Conclusion:** Only DS-006 and DS-007 contain the necessary paired (malware + benign) traffic from a consistent environment. DS-008 and DS-009 can only be used if blended with another dataset.

---

## 7. Leakage-Risk Comparison

When using DS-008 or DS-009 as malware combined with an external benign dataset, the following leakage risks apply:

| Risk Type | Risk Level | Mitigability | Description |
|-----------|------------|--------------|-------------|
| **IP/Port Leakage** | HIGH | MITIGABLE | Classifiers will learn the sandbox IP subnets. Must drop IP/Port features. |
| **MAC Leakage** | HIGH | MITIGABLE | Link-layer artifacts must not be extracted or must be masked. |
| **SNI Leakage** | HIGH | PARTIALLY_MITIGABLE | Malware C2 domains easily distinguish from benign domains, overpowering behavioral features. |
| **Timestamp Leakage** | MEDIUM | MITIGABLE | Capture windows will differ between datasets; absolute time must be dropped. |
| **Capture-Env Leakage** | HIGH | NOT_CLEARLY_MITIGABLE | RTT, IAT, and TCP window behaviors will encode the sandbox environment vs the benign network. |
| **Dataset-Source Leakage**| HIGH | NOT_CLEARLY_MITIGABLE | The model may simply learn to separate "Dataset A" from "Dataset B" instead of "Malware" from "Benign". |

---

## 8. Access Comparison

| Dataset | Access Classification | Description |
|---------|-----------------------|-------------|
| DS-001, DS-002, DS-003, DS-004, DS-010 | `PUBLICLY_DOWNLOADABLE` | Available via direct download or GitHub. |
| DS-008, DS-009 | `PUBLICLY_DOWNLOADABLE` | Available via direct download (MTA/Stratosphere). |
| DS-006, DS-007 | `ACADEMIC_REQUEST_REQUIRED` | Subset/CSVs are public; full raw PCAPs require contacting the authors with a justified academic request. |
| DS-005 | `UNAVAILABLE` | Only anonymized TSVs provided; PCAPs unavailable. |

---

## 9. Provisional Score & Ranking

1. **DS-006 (Beyond JA4+)** - Highest potential for primary dataset.
2. **DS-007 (Annotated Encrypted Traffic)** - Tied highest potential for primary dataset.
3. **DS-003 (USTC-TFC2016)** - Legacy fallback for flow-only experiments.
4. **DS-008 (MTA)** - Strongest supplementary malware source.
5. **DS-010 (IoT-23)** - Supplementary IoT validation.
6. **DS-009 (Stratosphere MCFP)** - Supplementary malware source.
7. **DS-004 (CipherSpectrum)** - Modern TLS validation standard.

---

## 10. P0 Candidates
**Potentially capable of supporting the core JA4 + Flow malware experiment.**
- **DS-006 (Beyond JA4+)** - Reason: Contains both malware and benign, explicitly targets JA4.
- **DS-007 (Annotated Encrypted Traffic)** - Reason: Contains modern SOHO benign + malware.

## 11. P1 Candidates
**Useful supplementary malware/C2 or generalization candidate.**
- **DS-008 (MTA)** - Reason: Highest quality real-world TLS 1.3 C2 PCAPs, but requires cross-dataset blending (high leakage risk).
- **DS-009 (Stratosphere MCFP)** - Reason: Authentic malware captures, but TLS versions vary and requires blending.

## 12. P2 Candidates
**Useful only for legacy comparison, benign validation, or protocol validation.**
- **DS-003 (USTC-TFC2016)** - Reason: Legacy TLS, no JA4.
- **DS-004 (CipherSpectrum)** - Reason: No malware.
- **DS-001 (ISCXVPN2016)** - Reason: No malware.
- **DS-010 (IoT-23)** - Reason: Traffic is IoT, not enterprise endpoint.

## 13. Rejected Candidates
- **TQH-C2**: Not found / Unavailable.
- **Encrypted VPN Dataset (Zenodo 7301756)**: Lacks malware focus.
- **DS-002 (CIC-Darknet2020)**: No raw PCAPs.
- **DS-005 (CSTNET-TLS1.3)**: No raw PCAPs.

---

## 14. Unknowns Requiring Empirical Verification

For DS-006, DS-007, DS-008, DS-009:
- Are the raw PCAPs readable by standard tools (Zeek/TShark)?
- Do the ClientHello packets contain the necessary extensions for JA4?
- Are the flow lengths sufficient for meaningful statistical calculation (or do malware payloads abort instantly)?

## 15. Recommended Verification Order

1. **Initiate Access Requests:** Immediately draft requests for **DS-006** and **DS-007**.
2. **Empirical Check (DS-008):** While waiting for academic access, download a small sample of 2024-2026 TLS 1.3 PCAPs from **DS-008 (MTA)** and run the `verify_ds004.py` JA4 extraction pipeline. This will prove whether modern malware C2 is JA4-computable in practice.
3. **Empirical Check (DS-006/007):** Upon receipt of PCAPs, run the same JA4 extraction pipeline on them.
