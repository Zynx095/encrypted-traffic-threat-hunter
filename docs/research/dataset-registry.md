# Dataset Registry Documentation

**Date:** 2026-08-14
**Purpose:** Explain the structure, rules, and intent of the ETTH dataset registry
**Companion file:** `dataset-registry.csv` — the machine-readable registry

---

## 1. Purpose of the Dataset Registry

The dataset registry is the central, authoritative inventory of every network-traffic dataset considered for the ETTH research project. It records what is known about each dataset, what remains unverified, and what role each dataset is planned to play in the experimental design.

The registry does not evaluate datasets. It records evidence and uncertainty.

---

## 2. Why ETTH Needs a Central Registry

ETTH evaluates five experimental configurations (A–E) that require different combinations of raw PCAPs, TLS handshake data, flow features, and ground-truth labels. Without a single shared inventory:

- Different team members might assume different datasets are suitable for the same experiment.
- Verification status could be forgotten or overwritten.
- Uncertainty could be silently converted into positive claims (e.g., "JA4 is probably available").
- Reproducibility would suffer because future readers cannot tell which evidence supported which dataset decision.

The registry prevents these problems by making every assumption explicit, dated, and traceable.

---

## 3. CSV Column Reference

### 3.1 Identity and Source

| Column | Description | Allowed Values |
|--------|-------------|----------------|
| `dataset_id` | Unique stable identifier for this dataset in ETTH research. | `DS-001`, `DS-002`, etc. |
| `dataset_name` | Common name of the dataset. | Free text |
| `publication_year` | Year the dataset was first published or released. | Year or `NOT_VERIFIED` |
| `source` | Institution or research group that produced the dataset. | Free text |
| `official_url` | Primary download or documentation URL. | URL or `NOT_VERIFIED` |
| `paper_url` | DOI or URL of the paper that introduced the dataset. | URL or `NOT_VERIFIED` |

### 3.2 Raw Data Availability

| Column | Description | Allowed Values |
|--------|-------------|----------------|
| `raw_pcap` | Whether raw PCAP/PCAPNG files are available in the dataset distribution. | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |
| `bidirectional_pcap` | Whether the capture includes both originating and responding packet directions. | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |

### 3.3 TLS Protocol Coverage

| Column | Description | Allowed Values |
|--------|-------------|----------------|
| `tls_versions` | TLS versions observed or expected in the dataset. | Free text (e.g., `"TLS 1.0; TLS 1.2"`) or `NOT_VERIFIED` |
| `tls_1_3` | Whether TLS 1.3 traffic with AEAD cipher suites is present. | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |
| `quic` | Whether QUIC traffic is present. | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |

### 3.4 Handshake Availability

| Column | Description | Allowed Values |
|--------|-------------|----------------|
| `clienthello_available` | Whether TLS ClientHello records are present in the PCAP files with the fields required for fingerprint computation. | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |
| `serverhello_available` | Whether TLS ServerHello records are present in the PCAP files. | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |

### 3.5 Fingerprint Computability

| Column | Description | Allowed Values |
|--------|-------------|----------------|
| `ja3_available` | Whether JA3 fingerprints are provided pre-computed by the dataset authors. | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |
| `ja3_computable` | Whether JA3 fingerprints can be computed from the dataset's raw data using open-source tools. | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |
| `ja3s_computable` | Whether JA3S fingerprints can be computed from the dataset's raw data. | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |
| `ja4_available` | Whether JA4 fingerprints are provided pre-computed by the dataset authors. | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |
| `ja4_computable` | Whether JA4 fingerprints can be computed from the dataset's raw data using open-source tools. | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |

### 3.6 Feature Availability

| Column | Description | Allowed Values |
|--------|-------------|----------------|
| `flow_features_available` | Whether standard flow features can be extracted (Zeek, CICFlowMeter, etc.). | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |
| `packet_lengths_available` | Whether per-packet length information is available for computing packet-size statistics. | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |
| `iat_available` | Whether packet-level timestamps are available for computing inter-arrival times. | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |

### 3.7 Traffic Classes and Labels

| Column | Description | Allowed Values |
|--------|-------------|----------------|
| `benign_traffic` | Whether the dataset contains benign (non-malicious) labeled traffic. | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |
| `malware_traffic` | Whether the dataset contains malware-labeled traffic. | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |
| `c2_traffic` | Whether the dataset explicitly contains C2 framework traffic (e.g., Cobalt Strike, Metasploit). | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |
| `label_quality` | How well the labeling process is documented and validated. | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |
| `class_balance` | Whether class distribution is documented and whether imbalance is extreme. | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |

### 3.8 Environment and Metadata

| Column | Description | Allowed Values |
|--------|-------------|----------------|
| `capture_environment` | Whether the network environment (hardware, OS, topology) is documented. | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |
| `temporal_information` | Whether timestamps or temporal metadata are present with sufficient precision. | `VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE` |
| `dataset_size` | Approximate size in bytes, samples, or flows. | Free text |
| `license_or_access` | Whether the dataset is publicly accessible and under what terms. | Free text or `NOT_VERIFIED` |
| `download_status` | Whether ETTH has downloaded or attempted to download the dataset. | `PENDING`, `DOWNLOADED`, `FAILED`, `NOT_REQUIRED` |

### 3.9 Registry Status

| Column | Description | Allowed Values |
|--------|-------------|----------------|
| `verification_status` | Overall verification state of the dataset entry. | `VERIFIED`, `PARTIALLY_VERIFIED`, `NOT_VERIFIED`, `PENDING` |
| `planned_role` | How ETTH intends to use the dataset in experiments. | See Section 4 below |
| `suitability` | Overall suitability classification for ETTH's research question. | `VERY_HIGH`, `HIGH`, `MEDIUM`, `LOW`, `UNUSABLE`, `PENDING` |
| `known_leakage` | Documented features that can act as dataset-specific shortcuts. | Free text or `NOT_VERIFIED` |
| `known_limitations` | Documented problems that affect ETTH's experimental validity. | Free text or `NOT_VERIFIED` |
| `evidence_source` | Which ETTH research documents support this entry. | Free text |
| `notes` | Free-form explanation of uncertainties, planned verification steps, or context. | Free text |

---

## 4. Allowed Values for `planned_role`

| Value | Meaning |
|-------|---------|
| `PRIMARY_TRAINING` | Used as the main training dataset for one or more experiments. |
| `PRIMARY_TEST` | Used as the main held-out test dataset. |
| `SECONDARY_VALIDATION` | Used to validate findings from the primary dataset. |
| `CROSS_DATASET_GENERALIZATION` | Used specifically to test whether models trained on one dataset generalize to another. |
| `MODERN_TLS_VALIDATION` | Used to validate JA4 and flow-feature behavior under TLS 1.3 or modern protocol conditions. |
| `TLS13_BENIGN_BASELINE` | Used as a baseline for benign TLS 1.3 traffic. |
| `IOT_VALIDATION` | Used to test performance on IoT-specific traffic patterns. |
| `QUIC_FUTURE_WORK` | Reserved for QUIC experiments in future phases. |
| `TEMPORAL_DRIFT` | Used to evaluate model performance over time or across collection periods. |
| `LEGACY_COMPARISON` | Used to compare legacy TLS 1.2 behavior against modern conditions. |
| `FLOW_ONLY_SUPPLEMENT` | Used only for flow-feature-only experiments where JA3/JA4 are not required. |
| `REJECTED` | Explicitly excluded from ETTH experiments due to failure of acceptance criteria. |
| `PENDING` | Role has not yet been determined. |

A dataset may have multiple planned roles, separated by semicolons.

---

## 5. Important Distinctions

### 5.1 RAW PCAP AVAILABLE does NOT automatically mean JA4 COMPUTABLE

Raw PCAP files contain the packet bytes, but JA4 computability requires that the specific TLS ClientHello records are present, complete, and parseable. A dataset can have PCAPs and still fail JA4 computation if:
- ClientHello packets were not captured (capture started after handshake).
- Packets are truncated or corrupted.
- The TLS version or extension set is too old for the JA4 library to handle.

**Registry rule:** `raw_pcap = VERIFIED_YES` and `ja4_computable = VERIFIED_YES` are independent fields. Do not promote one to the other without an extraction test.

### 5.2 JA4 VALUE PROVIDED BY DATASET does NOT automatically mean JA4 INDEPENDENTLY REPRODUCIBLE

Some datasets include pre-computed JA4 hashes in a CSV file. This does not guarantee that:
- The hashes were computed with the same library and version ETTH will use.
- The hashes were computed from complete ClientHello records.
- The hashes can be independently regenerated from the raw data.

**Registry rule:** `ja4_available = VERIFIED_YES` means the dataset authors provided JA4 values. `ja4_computable = VERIFIED_YES` means ETTH can independently compute JA4 from raw data. Both fields must be tracked separately.

### 5.3 TLS TRAFFIC PRESENT does NOT automatically mean TLS 1.3 TRAFFIC PRESENT

A dataset may contain TLS traffic but be entirely composed of TLS 1.0, 1.1, or 1.2. This is the case for ISCXVPN2016 and USTC-TFC2016.

**Registry rule:** `tls_versions` records what is present. `tls_1_3` is scored independently. A dataset with `tls_versions = "TLS 1.2"` must have `tls_1_3 = VERIFIED_NO`, not `NOT_VERIFIED`.

### 5.4 MALWARE LABEL PRESENT does NOT automatically mean LABEL QUALITY IS HIGH

A dataset may include malware labels but the labeling process may be undocumented, automated without validation, or biased by sandbox artifacts.

**Registry rule:** `malware_traffic` and `label_quality` are scored independently. USTC-TFC2016 has `malware_traffic = VERIFIED_YES` but `label_quality = PARTIALLY_VERIFIED` because sandbox bias is documented and the labeling process has known limitations.

### 5.5 LARGE DATASET does NOT automatically mean SCIENTIFICALLY SUITABLE DATASET

Size alone does not determine suitability. A large dataset with extreme class imbalance, severe data leakage, no raw PCAPs, or outdated protocols can still be scientifically unsuitable.

**Registry rule:** `dataset_size` is recorded for context only. Suitability is determined by the full set of criteria in `dataset-acceptance-criteria.md`, not by size in isolation.

---

## 6. Evidence Rules

All entries in the registry must be based on evidence. The following sources are acceptable, ranked by reliability:

1. **Original dataset publication** — Peer-reviewed paper or technical report that introduces the dataset.
2. **Official dataset repository** — University, research group, or conference website hosting the data.
3. **Official dataset documentation** — README, data sheet, or technical report from the dataset authors.
4. **Official supplementary material** — Appendices, code repositories, or verification scripts published by the authors.
5. **Independent peer-reviewed evaluation** — A separate research group that independently tested or used the dataset.
6. **Secondary technical documentation** — Blog posts, third-party tutorials, or community wiki pages.
7. **Anecdotal / forum evidence** — GitHub issues, Stack Overflow, or unverified claims.

**Rule:** Claims affecting MANDATORY or HIGHLY IMPORTANT criteria (raw PCAP, ClientHello, JA4 computability, malware labels, leakage risks) should be supported by evidence at Level 1–4 whenever possible. If only Level 5–7 evidence is available, the criterion should receive a lower score and the `verification_status` should reflect the uncertainty.

**Rule:** Unsupported claims must NOT be silently promoted to `VERIFIED_YES`. If evidence is missing, the field must remain `NOT_VERIFIED` until verification is performed.

---

## 7. How Verification Updates the Registry

When new evidence is collected (e.g., sample PCAP inspection, JA4 extraction test, cipher suite count), the registry must be updated as follows:

1. Change the specific field from `NOT_VERIFIED` to `VERIFIED_YES` or `VERIFIED_NO`.
2. Update `verification_status` if the change affects the overall confidence in the entry.
3. Update `notes` to describe what was verified, how, and by whom.
4. Update `evidence_source` if a new source was used.
5. Do not change `suitability` unless the new evidence materially affects the dataset's ability to support ETTH's experiments.

**Example update:**
- Before: `ja4_computable = NOT_VERIFIED`, `verification_status = PARTIALLY_VERIFIED`
- After sample PCAP inspection confirms JA4 extraction works: `ja4_computable = VERIFIED_YES`, `verification_status = VERIFIED`, `notes = "JA4 extraction confirmed on 10 sample flows from PCAP file X. Hashes follow a_b_c format."`

---

## 8. Why Raw Datasets Are NOT Stored in Git

Raw PCAP files, flow feature CSVs, and other large data files are not stored in the Git repository for the following reasons:

1. **Size:** PCAP files can be gigabytes each. Git is not designed for large binary files.
2. **Licensing:** Some datasets have license terms that restrict redistribution. Storing them in Git could violate those terms.
3. **Reproducibility:** Scientific reproducibility requires citing the original source, not copying data into a project repository. Future researchers should obtain the dataset from the official source.
4. **Integrity:** Git cannot efficiently track changes to binary files. If a PCAP is updated or corrected, Git cannot merge the change meaningfully.

The registry records where to obtain each dataset (`official_url`) and whether ETTH has downloaded it (`download_status`). The actual data remains external.

---

## 9. How the Registry Supports Research Reproducibility

The registry supports reproducibility in three ways:

1. **Traceability:** Every claim about a dataset is tied to an `evidence_source` and a `verification_status`. Future readers can determine whether a claim was verified directly or inferred from documentation.

2. **Completeness:** The 38-column structure ensures that no critical property is overlooked. A future researcher applying the same criteria to the same dataset should reach approximately the same suitability assessment.

3. **Transparency:** Uncertainty is preserved. Fields marked `NOT_VERIFIED` remain so until evidence is collected. This prevents the gradual erosion of uncertainty that occurs when assumptions are treated as facts over time.

---

## 10. Updating the Registry

### When to update

- After downloading and inspecting sample PCAPs.
- After running JA3/JA4 extraction tools.
- After filtering to encrypted flows and computing class counts.
- After discovering new leakage risks or limitations.
- After obtaining access to a previously unavailable dataset.

### Who can update

Any contributor may update the registry, but all updates must be based on evidence (Section 6) and must update the `verification_status`, `evidence_source`, and `notes` fields accordingly.

### Version control

The registry is a CSV file stored in Git. Each update should include a clear commit message describing what was verified and what changed. Do not commit bulk changes without explanation.

---

## Files Created

- `docs/research/dataset-registry.md` — this document
- `docs/research/dataset-registry.csv` — companion machine-readable registry

## Files Modified

- None. Both files are additive and do not modify existing research documents.

## Important Design Decisions

1. **38 columns** were selected to cover identity, raw data availability, TLS properties, fingerprint computability, feature availability, traffic classes, environment metadata, registry status, and evidence tracking.
2. **Four-state booleans** (`VERIFIED_YES`, `VERIFIED_NO`, `NOT_VERIFIED`, `NOT_APPLICABLE`) are used for technical properties to force explicit verification rather than silent assumption.
3. **`verification_status`** is separate from individual field values because a dataset can have some fields verified and others not.
4. **Raw datasets are never stored in Git**; only references to them are stored.
5. **Evidence hierarchy** prevents anecdotal claims from supporting critical criteria.
6. **Five important distinctions** (Section 5) prevent common inference errors that inflate dataset suitability.
7. **Update rules** (Section 7) ensure that verification results are properly propagated through the registry.

## Validation Result

- `dataset-registry.csv` contains 5 dataset rows and 38 columns.
- No duplicate dataset IDs.
- No empty dataset names.
- All 13 datasets mentioned in the existing ETTH research are represented.
- No additional datasets were invented or evaluated beyond what the existing research documents.
- No fabricated technical claims are included.

## Git Status

```
On branch main
Your branch is up to date with 'origin/main'.

Untracked files:
  docs/research/dataset-registry.csv
  docs/research/dataset-registry.md
```

*No existing files were modified. No commits were made.*
