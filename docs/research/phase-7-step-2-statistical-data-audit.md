# Phase 7 Step 2 — Statistical / Data Audit

## 1. Audit Methodology
The audit evaluated the exact Parquet files stored in `data/processed/v2/model_safe/model_safe_dataset.parquet` and `data/processed/v2/experiments/`. Calculations were performed deterministically using Pandas (v.2.2.3 or compatible) without any randomness, scaling, imputation, or data mutation.

## 2. A — Dataset Inventory
- **Model-Safe Dataset Rows:** 2,549
- **Model-Safe Dataset Columns:** 87
- **Target Feature:** `label`
- **Target Classes:** `MALICIOUS`, `BENIGN_VALIDATION`
- **Duplicate Behavioral Groups:** 75
- **Exact Duplicate Rows:** 1,005

**Experimental Datasets:**
| Experiment | Rows | Features | Malicious | Benign |
| :--- | :--- | :--- | :--- | :--- |
| **A (Flow-only)** | 2,118 (train split) | 87 | 2,114 | 4 |
| **B (JA3-only)** | 160 (train split) | 3 | 156 | 4 |
| **C (JA4-only)** | 160 (train split) | 3 | 156 | 4 |
| **D (JA3+Flow)** | 160 (train split) | 88 | 156 | 4 |
| **E (JA4+Flow)** | 160 (train split) | 88 | 156 | 4 |

> [!WARNING]
> **Important Note on Experiment Rows:**
> `A_flow_only.parquet` (and B-E equivalent files) only contains the **Training Set** (approx 80%), whereas `A_flow_only_meta.parquet` contains the **Test Set** (approx 20%). The exact counts differ from total available fingerprint flows due to the strict `GroupShuffleSplit`.

## 3. B — Class Distribution
* **Total Model-Safe Rows:** 2,549
* **MALICIOUS Count:** 2,543 (99.76%)
* **BENIGN_VALIDATION Count:** 6 (0.24%)
* **Imbalance Ratio:** ~424:1

## 4. C & D — Missingness and Cardinality
Missingness primarily originates from the absence of TLS handshakes or the brevity of flows (preventing statistical variability).

**TLS / Fingerprint Missingness (2,549 Rows):**
- `tls_version`: 2,349 missing (92.15%)
- `alpn_value`: 2,349 missing (92.15%)
- **Valid Fingerprints:** JA3/JA4 are available for exactly 200 rows.

**Flow Missingness:**
- `maximum_idle_gap`: 84.8% missing
- `rev_iat_` series (min, max, mean, std, median, percentiles): 67.19% missing
- `rev_packet_length_` series: 58.26% missing
- `fwd_iat_` series: 43.53% missing
- `iat_` series: 34.8% missing
- `burst_size` metrics: 34.8% missing

This suggests a very high volume of unidirectional or heavily skewed traffic where reverse packets or IAT gaps are completely absent.

**Categorical Features:**
- `tls_version`: 1.2 or 1.3
- `clienthello_present`: `True` / `False`
- `serverhello_present`: `True` / `False`

**Constant Features:**
In Experiments D and E (which mandate JA3/JA4 presence), `clienthello_present` and `serverhello_present` are practically constant (value = `True`), as fingerprints implicitly require the handshake.

## 5. F & G — Numeric & Categorical Distributions
- `BENIGN_VALIDATION` flows correctly exhibit TLS version diversity (2x TLS 1.2, 4x TLS 1.3).
- `MALICIOUS` flows heavily cluster in missing TLS information (2,349 rows), with only 111x TLS 1.2 and 83x TLS 1.3.
- `SNI` is present in 5/6 (83%) of Benign flows, but only 148/2543 (5.8%) of Malicious flows.

## 6. H — Duplicate / Behavioral Structure Audit
* **Total duplicate behavioral rows:** 1,005
* **Duplicate behavioral groups:** 75
* **Cross-PCAP duplicate groups:** 0
* **Cross-label duplicate groups:** 0

As expected for malware sandbox captures, a massive amount of exact-duplicate beaconing exists (e.g. 1,005 duplicates map into just 75 unique behaviors). Strict duplicate-grouping cross-validation remains critical to avoid data leakage.

## 7. I — Correlation Audit
Spearman rank correlation (>0.95) reveals highly clustered metrics:
- Packet lengths and their percentiles (`packet_length_std`, `packet_length_p95`, `packet_length_max`).
- Forward and total flow packet/byte correlations (`forward_packets`, `total_packets`, `forward_byte_ratio`).
- IAT percentiles (`iat_mean`, `iat_max`, `iat_p95`).
- Burst sizes (`maximum_burst_size`).

This heavy multicollinearity is expected for flow data and suggests non-linear, tree-based models or dimensionality reduction (e.g., PCA) may perform well later.

## 8. J — Leakage Audit
A scan of all predictive features confirmed:
* **No `IP` addresses.**
* **No `Ports`.**
* **No `MAC` addresses.**
* **No `Timestamps`.**
* **No `Filenames`.**
* **No `Dataset/Provenance` identifiers.**
* **No `SNI` raw domains.**

The pipeline's model-safe barrier correctly stripped all explicit leakage points.

## 9. K — Dataset-Source Confounding Audit
The analysis identified severe potential dataset-source confounders:
- **Missingness Separation:** 0% of `BENIGN_VALIDATION` flows have missing TLS versions, whereas 92.15% of `MALICIOUS` flows lack TLS. A model could simply learn: "If TLS is absent, it is malicious."
- **SNI Absence:** 83% of benign flows have SNI vs 5.8% for malicious.
- **Sequence Characteristics:** `MALICIOUS` sequence lengths range heavily up to 29,213 packets, reflecting long-running sandbox executions.

These are likely environmental artifacts of the `Malware-Traffic-Analysis.net` sandbox source compared to the `CipherSpectrum` benign source, rather than universal malicious traits.

## 10. L — Fingerprint Coverage
- **DS-008 (MALICIOUS):** 200 out of 2543 flows (7.86%) contain valid JA3/JA4 fingerprints.
- **DS-004 (BENIGN_VALIDATION):** 6 out of 6 flows (100%) contain valid JA3/JA4 fingerprints.

## 11. M — Sequence / Array Audit
* **Minimum length:** 1
* **Maximum length:** 29,213
* **Median length:** 2.0
* **Mean length:** 87.06
Extremely heavy-tailed distributions. Over 50% of flows have 2 or fewer packets, representing minimal TCP handshakes or failed connections.

## 12. N — Experiment Comparison
Moving from **Experiment A** to **B/C/D/E** reduces the training population from 2,118 rows to 160 rows. This >90% data loss severely limits statistical significance for the fingerprint experiments.

## 13. O — Scientific Risk Classification

| Risk | Classification | Description | Next Steps |
| :--- | :--- | :--- | :--- |
| **Severe Class Imbalance** | **CRITICAL** | 424:1 imbalance. Will cause total classification collapse if trained directly. | Evaluate SMOTE/Downsampling strictly inside training folds in Step 3/4. |
| **Fingerprint Attrition** | **CRITICAL** | B-E experiments contain only 160 training rows. Extremely volatile for cross-validation. | Document high variance constraints during training. |
| **Source Confounding** | **HIGH** | Extreme divergence in TLS missingness (0% vs 92%) based purely on dataset source. | Track feature importances specifically against missingness indicators. |
| **Missing Flow Data** | **HIGH** | IAT and Reverse metrics exceed 50% missingness. | Require robust imputation strategy in Step 3. |
| **Multicollinearity** | **MEDIUM** | Extremely dense feature correlation among size/timing percentiles. | Tree-based model baseline recommended. |

---
**Status:** COMPLETE
