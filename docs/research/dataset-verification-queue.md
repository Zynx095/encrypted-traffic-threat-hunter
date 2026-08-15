# Dataset Verification Queue

**Date:** 2026-08-15
**Purpose:** Prioritize manual empirical verification tasks for datasets in the ETTH registry
**Scope:** This queue lists verification tasks needed before datasets can be legitimately selected or used.

**Priority levels:**
- **P0** — Required before primary dataset selection
- **P1** — Required before model experiments
- **P2** — Required for cross-dataset validation
- **P3** — Future / optional

---

## P0 — Required Before Primary Dataset Selection

### [NEW] Task: DATASET_REQUIRED: Modern Malware PCAPs
- **dataset:** TBD (e.g., Stratosphere IPS, CIC-MalMem2022)
- **unresolved question:** Does there exist a publicly accessible dataset containing real malware traffic encrypted with modern TLS (1.2+) that supports JA4 extraction?
- **evidence required:** Raw PCAPs containing malware ClientHellos with TLS extensions.
- **verification method:** Locate candidate, download sample PCAPs, run `verify_ds004.py` script logic.
- **expected output:** Successful JA4 hashes for malware traffic.
- **acceptance criterion:** JA4 computable on malware sessions.
- **dependency:** None.
- **priority:** P0
- **status:** **PENDING** — Required because no currently registered dataset contains JA4-computable malware traffic.

### [NEW] Task: DS-006 and DS-007 Academic Access Request
- **dataset:** DS-006 (Beyond JA4+), DS-007 (Annotated Encrypted Network Traffic Dataset)
- **unresolved question:** Can we obtain the full, raw PCAPs for these datasets?
- **evidence required:** Approval from authors and receipt of PCAP files.
- **verification method:** Draft and send academic request to Petr Matoušek and Ondřej Ryšavý at Brno University of Technology.
- **expected output:** Download links for the full PCAP datasets.
- **acceptance criterion:** PCAPs are successfully downloaded and readable.
- **dependency:** None.
- **priority:** P0
- **status:** **DRAFTED** — Drafts created in `dataset-access-request-drafts.md`. Pending institutional approval/sending.

### [NEW] Task: DS-008 MTA Sample Verification (Ready for Step 14)
- **dataset:** DS-008 (Malware-Traffic-Analysis.net)
- **unresolved question:** Can we cleanly extract TLS 1.3 ClientHellos and compute JA4 from a representative sample of these PCAPs?
- **evidence required:** Successful JA4 extraction and bidirectional flow parsing.
- **verification method:** Manually download 5-10 recent (2024-2026) TLS 1.3 malware PCAPs from MTA and run `verify_ds004.py` script logic.
- **expected output:** Valid JA4 hashes.
- **acceptance criterion:** JA4 correctly extracts without failure for the majority of TLS flows in the sample.
- **dependency:** None.
- **priority:** P0
- **status:** **READY** — Authorized for immediate execution in Step 14 while awaiting DS-006/DS-007 academic requests.

### [DONE] Task: DS-003 JA3/JA4 Computability
- **dataset:** DS-003 (USTC-TFC2016)
- **unresolved question:** Are JA4 and JA3 fingerprints actually computable from the raw PCAPs?
- **evidence required:** Raw PCAPs containing valid TLS ClientHello records.
- **verification method:** Select sample PCAPs, run standard JA4 and JA3 extraction tools.
- **expected output:** Valid, standard-compliant JA4 and JA3 hashes for a representative set of flows.
- **acceptance criterion:** JA4 correctly extracts without failure for the majority of TLS flows in the sample.
- **dependency:** Access to GitHub repository (Verified).
- **priority:** P0
- **status:** **DONE (FAILED)** — Empirical verification showed malware relies on SSL 3.0 (no extensions for JA4) and benign lacks ClientHellos entirely.

### [DONE] Task: DS-003 Encrypted Flow Volume
- **dataset:** DS-003 (USTC-TFC2016)
- **unresolved question:** Is there a sufficient volume of encrypted traffic once the 94.7% unencrypted traffic is filtered out?
- **evidence required:** Count of TLS-encrypted flows versus total flows in the dataset.
- **verification method:** Filter sample PCAPs for TLS handshakes, count TLS flows vs non-TLS flows.
- **expected output:** A reliable estimate of total encrypted flows in the entire dataset.
- **acceptance criterion:** The estimated encrypted flow volume remains sufficient for stratified train/test splitting (e.g., >10,000 flows).
- **dependency:** None.
- **priority:** P0
- **status:** **DONE (FAILED)** — Empirical verification showed extreme scarcity of encrypted flows (e.g., 0.16% in Zeus sample).

### [DONE] Task: Access Verification for Modern TLS Datasets
- **dataset:** DS-004 (CipherSpectrum), DS-005 (CSTNET-TLS1.3)
- **unresolved question:** Can these datasets actually be downloaded and do they contain raw PCAPs?
- **evidence required:** Confirmation of access and PCAP availability.
- **verification method:** Contact authors or attempt official download.
- **expected output:** Accessible raw PCAP files or confirmation of unavailability.
- **acceptance criterion:** Datasets are accessible without unreasonable barriers and contain raw PCAPs.
- **dependency:** None.
- **priority:** P0
- **status:** **DONE** — DS-004 is publicly available at `cspectrum.web.cse.unsw.edu.au` with PCAPs. DS-005 is TSV-only.

### [DONE] Task: DS-004 (CipherSpectrum) Empirical PCAP Verification
- **dataset:** DS-004 (CipherSpectrum)
- **unresolved question:** Do the downloaded ZIP files actually contain readable TLS 1.3 PCAPs that successfully parse to JA4 fingerprints and flow features?
- **evidence required:** Extracted JA4 fingerprints and flow feature measurements from a sample of the PCAPs.
- **verification method:** Download a ZIP sample, extract PCAP, run `verify_ds004.py`.
- **expected output:** High success rate of JA4 extraction.
- **acceptance criterion:** JA4 computable on modern TLS 1.3 sessions.
- **dependency:** None (Access verified).
- **priority:** P0
- **status:** **DONE (SUCCESS)** — Sample PCAPs parsed successfully. Valid ClientHellos, ServerHellos, and modern TLS 1.3 attributes present. JA4 correctly computable. Bidirectional flow confirmed.

---

## P1 — Required Before Model Experiments

### Task: DS-003 Label Verification and Class Balance
- **dataset:** DS-003 (USTC-TFC2016)
- **unresolved question:** Are the labels reliable and balanced within the encrypted traffic subset?
- **evidence required:** Label-to-flow mapping and per-class counts of encrypted flows.
- **verification method:** Join flow features with dataset labels and count per class.
- **expected output:** Precise ratio of benign to malware flows in the TLS subset.
- **acceptance criterion:** Malware traffic exists in the encrypted subset and class imbalance is no worse than 10:1.
- **dependency:** DS-003 Encrypted Flow Volume (P0).
- **priority:** P1

### Task: Leakage Identification and Masking (All Chosen Datasets)
- **dataset:** Any dataset selected for experiments.
- **unresolved question:** Are there dataset-specific shortcut features (IPs, SNI, specific ports) that will inflate accuracy?
- **evidence required:** Inventory of all features to be used by the model.
- **verification method:** Analyze features and attempt masking known leakage sources (e.g., stripping IP addresses).
- **expected output:** A defined, validated masking policy.
- **acceptance criterion:** Leakage is sufficiently controlled such that the model must rely on behavioral or generic fingerprint traits.
- **dependency:** Selection of primary dataset (P0).
- **priority:** P1

### [NEW] Task: DS-009 MCFP Sample Curation and Verification
- **dataset:** DS-009 (Stratosphere MCFP)
- **unresolved question:** Can we isolate modern TLS 1.3 malware captures from the broader dataset and successfully extract JA4?
- **evidence required:** Identified TLS 1.3 PCAPs and successful JA4 hashes.
- **verification method:** Locate recent (2024-2025) captures in the MCFP repository, download a small PCAP sample, and run extraction logic.
- **expected output:** A curated list of usable PCAPs and verified JA4 computability.
- **acceptance criterion:** At least some MCFP captures support JA4 extraction on TLS 1.3.
- **dependency:** None.
- **priority:** P1
- **status:** **PENDING** — Requires manual repository traversal.

---

## P2 — Required For Cross-Dataset Validation

### Task: Temporal and Environmental Consistency
- **dataset:** DS-001 (ISCXVPN2016), DS-003 (USTC-TFC2016)
- **unresolved question:** Are the capture environments and timestamps consistent enough to allow cross-dataset testing?
- **evidence required:** Timestamp precision and network topology details.
- **verification method:** Inspect PCAP timing metrics and read environmental documentation.
- **expected output:** Documentation of any significant temporal or environmental divergence.
- **acceptance criterion:** The features extracted (e.g., IATs) are comparable across datasets.
- **dependency:** Completion of Phase 6 dataset processing.
- **priority:** P2

---

## P3 — Future / Optional

### Task: DS-003 Malware Family Breakdown
- **dataset:** DS-003 (USTC-TFC2016)
- **unresolved question:** Which specific malware families are operating over TLS?
- **evidence required:** Detailed malware family metadata.
- **verification method:** Inspect any extended label documentation provided with the dataset.
- **expected output:** A list of TLS-using malware families in the dataset.
- **acceptance criterion:** Enhances research understanding, but not blocking.
- **dependency:** DS-003 Label Verification (P1).
- **priority:** P3 (Future dependency)

### Task: Exact Protocol Distribution
- **dataset:** All candidates.
- **unresolved question:** What is the precise distribution of TLS 1.2 vs TLS 1.3 across the datasets?
- **evidence required:** Count of TLS version fields from ClientHellos.
- **verification method:** Run a parser over the TLS handshake records.
- **expected output:** A statistical breakdown of TLS versions.
- **acceptance criterion:** Useful for context, but standard experiments can proceed regardless.
- **dependency:** JA4 Computability tasks (P0).
- **priority:** P3