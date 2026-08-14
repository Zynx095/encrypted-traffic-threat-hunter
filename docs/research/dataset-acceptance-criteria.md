# Dataset Acceptance Criteria for ETTH

**Date:** 2026-08-14
**Purpose:** Define objective, reproducible criteria for including or excluding network-traffic datasets in the ETTH experimental phase
**Scope:** This document defines rules only. No individual dataset is evaluated or selected here.

---

## 1. How to Use This Document

For each candidate dataset, collect evidence for every criterion below. Assign a score:

- **0** — unavailable / unusable
- **1** — weak
- **2** — acceptable
- **3** — strong

Record the evidence source for every score. Do not infer scores from assumptions.

After scoring all criteria, apply the overall suitability classification and rejection rules in Sections 4 and 5.

---

## 2. Scoring Definitions

| Score | Meaning |
|-------|---------|
| 0 | The property is absent or the dataset is unusable for the required purpose. |
| 1 | The property exists but is weak, incomplete, or poorly documented. |
| 2 | The property exists and is acceptable for ETTH's needs, with minor reservations. |
| 3 | The property exists, is well documented, and is strongly supported by direct evidence. |

---

## 3. Criteria

### 3.1 Raw PCAP Availability

**What it means:** The dataset includes raw packet capture files in PCAP or PCAPNG format, containing layer-2 through layer-7 packet headers and payloads.

**Why ETTH needs it:** JA3 and JA4 fingerprints are computed from the raw bytes of TLS ClientHello and ServerHello packets. No CSV, JSON, or database export can substitute for raw packet data, because the ordered cipher suite list, ordered extension list, GREASE values, and TLS record structure are lost during feature extraction.

**Evidence to collect:**
- Official dataset download page listing PCAP files.
- File headers or documentation confirming PCAP/PCAPNG format.
- Sample file inspection confirming readable packet data.

**Strong evidence:** Official download page with PCAP files, confirmed by sample inspection and cited in the original dataset publication.

**Weak evidence:** Documentation mentions PCAPs but no download link is available, or PCAPs are only available from a third-party mirror.

---

### 3.2 Bidirectional Traffic Availability

**What it means:** The dataset contains both originating (client-to-server) and responding (server-to-client) packet directions for each flow.

**Why ETTH needs it:** Byte counts, packet counts, and direction sequences are core flow features. One-sided captures (e.g., client-side only) cannot compute bidirectional ratios or response-packet statistics, which are needed for Experiments A, D, and E.

**Evidence to collect:**
- Capture methodology description.
- Sample flow inspection showing bidirectional packets.
- Flow feature files with originating and responding columns.

**Strong evidence:** Dataset paper describes bidirectional capture hardware or software, and sample inspection confirms packets in both directions.

**Weak evidence:** Bidirectionality is implied but not explicitly documented.

---

### 3.3 TLS ClientHello Availability

**What it means:** The PCAP files contain actual TLS ClientHello records with the fields required for fingerprint computation (TLS version or supported_versions extension, cipher suite list, extension list, SNI extension, ALPN extension, signature algorithms where applicable).

**Why ETTH needs it:** Without ClientHello packets, JA3, JA3S, JA4, and JA4S cannot be computed. Experiments B, C, D, and E all depend on this criterion.

**Evidence to collect:**
- Filter PCAPs for TLS handshake packets (port 443 or other TLS ports).
- Inspect ClientHello records to confirm presence of required fields.
- Attempt JA3/JA4 extraction on a sample and verify output.

**Strong evidence:** Sample PCAP inspection shows ClientHello packets with complete field sets, and JA3/JA4 extraction produces valid, non-empty hashes.

**Weak evidence:** Documentation states TLS traffic is present, but no extraction test has been performed.

---

### 3.4 TLS ServerHello Availability

**What it means:** The PCAP files contain TLS ServerHello records with the fields required for JA3S and JA4S computation (TLS version, selected cipher, extension list).

**Why ETTH needs it:** JA3S and JA4S provide server-side fingerprints. Combined client-server fingerprinting reduces false positives compared to client-only fingerprinting. ETTH's experimental design includes JA3S and JA4S as part of the JA3-only and JA4-only configurations.

**Evidence to collect:**
- Filter PCAPs for ServerHello packets following ClientHello packets in the same flow.
- Inspect ServerHello records for required fields.
- Attempt JA3S/JA4S extraction on a sample and verify output.

**Strong evidence:** Sample extraction produces valid JA3S/JA4S hashes for a representative subset of flows.

**Weak evidence:** ServerHello presence is assumed because the dataset contains TLS traffic, but no extraction test has been performed.

---

### 3.5 TLS 1.2 Representation

**What it means:** The dataset contains a meaningful proportion of TLS 1.2 traffic (sufficient samples for stratified splitting and statistical comparison).

**Why ETTH needs it:** TLS 1.2 is still widely deployed. JA4 was designed to be compatible with TLS 1.2, and many existing datasets are TLS 1.2 only. ETTH must document JA4 performance under TLS 1.2 to establish a baseline before evaluating TLS 1.3.

**Evidence to collect:**
- Extract TLS version from ClientHello records across the dataset.
- Count flows per TLS version.

**Strong evidence:** Version counts are reported in dataset documentation or can be extracted and show a substantial TLS 1.2 population.

**Weak evidence:** Collection date and known application versions imply TLS 1.2 dominance, but no explicit version extraction has been performed.

---

### 3.6 TLS 1.3 Representation

**What it means:** The dataset contains a meaningful proportion of TLS 1.3 traffic with modern AEAD cipher suites (TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256).

**Why ETTH needs it:** TLS 1.3 is the current standard. Its cipher suite list, extension set, and handshake structure differ from TLS 1.2. JA4 behavior under TLS 1.3 (including handling of supported_versions, key_share, and encrypted SNI) must be measured. Without TLS 1.3 data, ETTH cannot claim its results generalize to modern networks.

**Evidence to collect:**
- Extract TLS version from ClientHello records.
- Count flows with TLS 1.3.
- Verify presence of AEAD cipher suites.

**Strong evidence:** Dataset documentation or extraction confirms significant TLS 1.3 sample count with AEAD ciphers.

**Weak evidence:** Some TLS 1.3 flows are present but in small numbers, or presence is assumed from collection date.

---

### 3.7 QUIC Representation (Where Applicable)

**What it means:** The dataset contains QUIC traffic (UDP-based, often on port 443 or 8443) that can be identified and separated from TCP/TLS traffic.

**Why ETTH needs it:** QUIC is increasingly used for HTTPS and encrypted C2. JA4 has a QUIC variant (JA4Q). If the dataset contains QUIC, ETTH should document whether QUIC flows are present and whether they can be processed separately.

**Evidence to collect:**
- Identify UDP flows on typical QUIC ports.
- Inspect initial packets for QUIC header structure.
- Attempt JA4Q extraction if applicable.

**Strong evidence:** QUIC flows are explicitly identified and documented in the dataset.

**Weak evidence:** QUIC may be present but has not been quantified.

**Note:** QUIC is OPTIONAL for current ETTH experiments. If absent, document that the dataset covers TCP/TLS only.

---

### 3.8 JA3 Computability

**What it means:** JA3 fingerprints can be reliably computed from the dataset's PCAP files using an open-source library, producing valid MD5 hashes for a non-trivial subset of TLS flows.

**Why ETTH needs it:** JA3 is the legacy baseline for Experiments B and D. Even if JA4 is the primary fingerprinting method, JA3 provides a controlled comparison point. JA3 computability also serves as a sanity check for PCAP quality and TLS handshake integrity.

**Evidence to collect:**
- Run an open-source JA3 extractor (e.g., ja3er/ja3, Zeek with JA3 plugin) on sample PCAPs.
- Verify that hashes are produced and are non-empty.
- Compare a subset of hashes against any published reference values.

**Strong evidence:** JA3 extraction succeeds on sample PCAPs, produces valid hashes, and matches reference values where available.

**Weak evidence:** JA3 extraction produces hashes but no reference values exist for comparison, or extraction succeeds on only a small subset of flows.

---

### 3.9 JA3S Computability

**What it means:** JA3S fingerprints can be reliably computed from the dataset's PCAP files, producing valid MD5 hashes for server-side handshakes.

**Why ETTH needs it:** JA3S is required for the JA3-only configuration (Experiment B). Combined JA3+JA3S reduces false positives compared to JA3 alone.

**Evidence to collect:**
- Run a JA3S extractor on sample PCAPs after JA3 extraction.
- Verify that hashes are produced for flows where ServerHello is present.

**Strong evidence:** JA3S extraction succeeds on a representative subset of flows.

**Weak evidence:** JA3S extraction is possible but only on a small fraction of flows, or ServerHello presence is uncertain.

---

### 3.10 JA4 Computability

**What it means:** JA4 fingerprints can be reliably computed from the dataset's PCAP files using an open-source JA4 library, producing valid human-readable fingerprints (format: `a_b_c`) for a non-trivial subset of TLS flows.

**Why ETTH needs it:** JA4 is the primary fingerprinting method for Experiments C and E. Without JA4 computability, the central research question cannot be tested. JA4 requires specific field handling (sorted cipher/extension lists, GREASE stripping, SHA-256 truncation) that must be verified on the actual dataset.

**Evidence to collect:**
- Run an open-source JA4 extractor (e.g., FoxIO/ja4, ja3er/ja4) on sample PCAPs.
- Verify output format matches the JA4 specification.
- Verify that hashes are non-empty and follow the `a_b_c` structure.

**Strong evidence:** JA4 extraction succeeds on sample PCAPs, output matches the specification, and a non-trivial number of flows yield valid fingerprints.

**Weak evidence:** JA4 extraction produces output but only for a small subset of flows, or the output format has deviations from the specification.

---

### 3.11 Flow Feature Computability

**What it means:** Standard flow features can be extracted from the dataset using established tools (Zeek, CICFlowMeter, or equivalent), producing complete per-flow records with the fields required for ETTH experiments.

**Why ETTH needs it:** Flow features are the foundation of Experiment A and are combined with TLS fingerprints in Experiments D and E. Without reliable flow feature extraction, no experiment can proceed.

**Evidence to collect:**
- Run Zeek or CICFlowMeter on sample PCAPs.
- Verify output contains required fields: packet sizes, IATs, byte counts, packet counts, flow duration, protocol, timestamps.
- Check for missing or malformed records.

**Strong evidence:** Flow extraction succeeds, output format is documented, and required fields are present for all or most flows.

**Weak evidence:** Flow extraction succeeds but many fields are missing, or the extraction tool produces warnings/errors for a significant fraction of flows.

---

### 3.12 Packet-Size Sequence Availability

**What it means:** Per-packet size information is available in the PCAP files or can be extracted, enabling computation of packet-size statistics (mean, std, min, max, quantiles, distributions).

**Why ETTH needs it:** Packet-size statistics are the most widely validated flow feature family for encrypted traffic classification [garcia2018efficient, akem2024realtime, akbari2022traffic]. They are unaffected by encryption and form the core of Experiment A.

**Evidence to collect:**
- Inspect PCAP files for packet length fields.
- Extract packet-size sequences for a sample of flows.
- Verify that size values span a meaningful range (not all identical).

**Strong evidence:** Packet sizes are present, vary across flows, and can be aggregated into per-flow statistics without error.

**Weak evidence:** Packet sizes are present but truncated, or many flows have only one packet (no meaningful distribution).

---

### 3.13 Inter-Arrival-Time Availability

**What it means:** Packet-level timestamps are present in the PCAP files with sufficient precision to compute inter-arrival times (IATs) and flow durations.

**Why ETTH needs it:** IATs and IAT distributions are critical for beaconing detection, temporal pattern analysis, and flow classification [zhang2025beacon, ramos2023cobalt, garcia2018efficient]. Without timestamps, these features cannot be computed.

**Evidence to collect:**
- Inspect PCAP file headers for timestamp precision (microsecond or nanosecond resolution preferred).
- Compute IATs for a sample of multi-packet flows.
- Verify that IAT values span a meaningful range.

**Strong evidence:** Timestamps are present with microsecond precision, and IATs can be computed for representative flows.

**Weak evidence:** Timestamps are present but with low precision (e.g., second-level only), or many flows have only one packet.

---

### 3.14 Benign Traffic

**What it means:** The dataset contains flows labeled as benign (normal, legitimate, non-malicious) from real or realistic application usage.

**Why ETTH needs it:** ETTH's research question requires distinguishing suspicious traffic from benign traffic. Without benign samples, a binary classifier cannot be trained or evaluated.

**Evidence to collect:**
- Dataset documentation describing benign traffic sources.
- Label distribution showing benign class presence.
- For synthetic benign traffic: documentation of the generation methodology.

**Strong evidence:** Benign traffic is documented as originating from real user activity or well-validated simulation, with clear labeling.

**Weak evidence:** Benign traffic exists but its origin is poorly documented, or it is synthetic with no validation against real traffic.

---

### 3.15 Malware Traffic

**What it means:** The dataset contains flows labeled as malicious, originating from known malware families, C2 frameworks, or attack tools.

**Why ETTH needs it:** ETTH's research question is about detecting suspicious encrypted connections. Without malicious samples, the experiment reduces to application classification, which is not the primary research question.

**Evidence to collect:**
- Dataset documentation listing malware families or attack types.
- Label distribution showing malicious class presence.
- For sandbox-collected malware: documentation of the sandbox environment and known biases.

**Strong evidence:** Malware traffic is documented with family names, collection methodology, and known bias accommodations.

**Weak evidence:** Malware traffic exists but is labeled only as "malicious" without family or tool attribution, or collection methodology is undocumented.

---

### 3.16 C2 Traffic (Where Available)

**What it means:** The dataset contains traffic from command-and-control (C2) frameworks (e.g., Cobalt Strike, Metasploit, custom malware) with multi-session temporal patterns.

**Why ETTH needs it:** C2 beaconing is a primary detection target for ETTH. Multi-flow temporal features (dur_mean, dur_std, int_mean, int_std) require multiple sessions between the same host pairs. If C2 traffic is present, ETTH can evaluate beaconing-specific features.

**Evidence to collect:**
- Dataset documentation listing C2 tools or frameworks.
- Sample inspection showing repeated connections between the same hosts.
- Documentation of beaconing parameters (jitter, sleep intervals).

**Strong evidence:** Dataset explicitly includes C2 traffic with documented tools and parameters.

**Weak evidence:** C2 traffic may be present but is not explicitly identified or documented.

**Note:** C2 traffic is HIGHLY IMPORTANT but not strictly mandatory. If absent, ETTH can still evaluate binary malicious/benign classification using other malware types.

---

### 3.17 Quality of Labels

**What it means:** Labels are assigned through a documented, reproducible process with known error rates. Label sources include manual verification, sandbox automation with validation, or ground-truth capture from controlled environments.

**Why ETTH needs it:** Supervised machine learning requires reliable labels. If labels are wrong, the model will learn incorrect patterns and the evaluation metrics will be meaningless.

**Evidence to collect:**
- Dataset paper or documentation describing the labeling process.
- Reported label accuracy or inter-annotator agreement.
- Known sources of label noise (e.g., sandbox artifacts, misclassified flows).

**Strong evidence:** Labels are produced by a documented automated or manual process with reported accuracy, and known noise sources are identified.

**Weak evidence:** Labels exist but the assignment process is undocumented, or label accuracy is unknown.

---

### 3.18 Class Balance

**What it means:** The dataset has a sufficient number of samples per class for stratified train/test splitting, and the class distribution is documented.

**Why ETTH needs it:** Extreme class imbalance biases classifiers toward the majority class and inflates accuracy while hiding poor minority-class performance. ETTH must report per-class precision, recall, and F1-score.

**Evidence to collect:**
- Exact sample count per class.
- Ratio of majority to minority class.
- After filtering to encrypted flows: per-class counts in the filtered subset.

**Strong evidence:** Class counts are documented, the majority/minority ratio is no worse than 10:1, and filtered counts are available or can be computed.

**Weak evidence:** Class counts exist but the ratio is extreme (e.g., 50:1 or worse), or filtered counts are unknown.

---

### 3.19 Capture Environment Information

**What it means:** The dataset documents the network environment where traffic was captured: hardware used, operating systems, network topology, time of day, and any filtering or preprocessing applied during capture.

**Why ETTH needs it:** Capture environment artifacts (timing precision, offload behavior, OS TCP stack differences) can become spurious features that inflate classifier accuracy without representing real traffic patterns. Anderson & McGrew (2017) explicitly accommodate sandbox bias; ETTH must do the same.

**Evidence to collect:**
- Dataset paper or documentation section on collection methodology.
- Hardware and software configuration details.
- Any preprocessing applied to raw captures before release.

**Strong evidence:** Collection environment is fully documented, and known artifacts are identified.

**Weak evidence:** Collection environment is partially documented or inferred from context.

---

### 3.20 Dataset Size

**What it means:** The dataset contains enough samples to support stratified train/test splitting with sufficient samples per class for reliable statistical evaluation.

**Why ETTH needs it:** Small datasets produce high-variance performance estimates. ETTH requires enough samples to train a classifier, hold out a stratified test set, and repeat with multiple random seeds.

**Evidence to collect:**
- Total number of flows or sessions.
- Number of flows per class.
- After encrypted-flow filtering: estimated remaining sample count.

**Strong evidence:** Total sample count is in the tens of thousands or higher, and filtered counts are estimated to remain above minimum thresholds.

**Weak evidence:** Total sample count is in the low thousands, or filtered counts may fall below usable thresholds.

---

### 3.21 Temporal Information

**What it means:** Packet timestamps or flow start/end times are present with sufficient precision for computing inter-arrival times, flow durations, and multi-flow temporal features.

**Why ETTH needs it:** IATs, flow duration, and multi-flow temporal statistics (dur_mean, dur_std, int_mean, int_std) all depend on accurate timestamps. Without them, Experiments A, D, and E cannot extract their core behavioral features.

**Evidence to collect:**
- PCAP timestamp precision.
- Flow feature files with start_time, end_time, or duration fields.
- Sample IAT computation verifying meaningful values.

**Strong evidence:** Timestamps are present with microsecond precision, and IAT/duration values are computable and non-degenerate.

**Weak evidence:** Timestamps are present but with low precision, or many flows have zero or near-zero duration due to capture truncation.

---

### 3.22 Licensing / Accessibility

**What it means:** The dataset is publicly available under a license or terms of use that permit research use, and the data can be downloaded without unreasonable barriers (registration, approval delays, cost, or geographic restrictions).

**Why ETTH needs it:** If the dataset cannot be obtained and used by other researchers, the experiment is not reproducible. Reproducibility is a core requirement for scientific research.

**Evidence to collect:**
- Official dataset page with download links.
- License terms or usage agreement.
- Confirmation that download does not require institutional approval or payment.

**Strong evidence:** Dataset is freely downloadable from an official source with no registration required, and the license explicitly permits research use.

**Weak evidence:** Dataset is available but requires free registration, or license terms are vague about research use.

---

### 3.23 Reproducibility

**What it means:** The dataset has been used in at least one peer-reviewed publication, and the collection or processing pipeline is documented well enough that another researcher could recreate or verify the dataset.

**Why ETTH needs it:** Reproducibility is required for scientific validity. If other researchers cannot obtain the same data or process it the same way, ETTH's results cannot be independently verified.

**Evidence to collect:**
- Peer-reviewed paper describing the dataset.
- Documentation of collection tools, parameters, and preprocessing steps.
- Availability of raw captures or reproducible generation scripts.

**Strong evidence:** Dataset has been used in peer-reviewed work, and the collection methodology is fully documented with tools and parameters.

**Weak evidence:** Dataset is mentioned in publications but the collection methodology is poorly documented, or only preprocessed features are available without raw captures.

---

### 3.24 Known Leakage Risks

**What it means:** The dataset contains features that can trivially identify the class without learning real traffic patterns, such as raw IP addresses, port numbers, SNI values, flow IDs, or timestamps that encode session identity.

**Why ETTH needs it:** Wickramasinghe et al. (2025) and Zhao et al. (2025) demonstrate that classifiers achieve inflated accuracy by learning dataset-specific shortcuts (SNI, IP addresses, flow IDs) rather than generalizable traffic patterns. ETTH must identify and mask these features.

**Evidence to collect:**
- Inventory of all features in the dataset.
- Documentation or prior work identifying shortcut features.
- Assessment of whether features can be masked without destroying useful signal.

**Strong evidence:** All features are inventoried, known leakage features are identified, and masking strategies are documented.

**Weak evidence:** Some leakage features are identified, but the full feature inventory is incomplete or masking has not been tested.

---

### 3.25 Dataset Age and Protocol Relevance

**What it means:** The dataset was collected recently enough that its TLS versions, cipher suites, application behaviors, and malware techniques are representative of current or near-current network conditions.

**Why ETTH needs it:** TLS 1.3 adoption, ECH deployment, QUIC usage, and malware C2 techniques have all evolved significantly since 2016. A dataset collected in 2015 cannot represent TLS 1.3 traffic, modern JA4 behavior, or current malware TLS usage.

**Evidence to collect:**
- Collection date or date range for each traffic capture.
- Dominant TLS versions and cipher suites.
- Comparison of application versions and malware families to current landscape.

**Strong evidence:** Dataset was collected within the last 3–5 years, includes TLS 1.3 traffic, and documents modern application and malware versions.

**Weak evidence:** Dataset is older than 5 years, dominated by legacy TLS 1.2 or earlier, with deprecated cipher suites and outdated application versions.

---

## 4. Overall Suitability Classification

After scoring all 25 criteria, assign one of the following overall classifications.

| Classification | Meaning |
|---------------|---------|
| **VERY HIGH** | All MANDATORY and HIGHLY IMPORTANT criteria score 2 or 3. No weak scores on critical items. Dataset can support all five experiments (A–E) with minimal preprocessing. |
| **HIGH** | All MANDATORY criteria score 2 or 3. Most HIGHLY IMPORTANT criteria score 2 or 3. Dataset can support most experiments, possibly with some preprocessing or scope adjustments. |
| **MEDIUM** | All MANDATORY criteria score at least 1, and most score 2 or 3. Some HIGHLY IMPORTANT criteria score 1. Dataset can support a subset of experiments or requires significant preprocessing. Results may have limited generalizability. |
| **LOW** | One or more MANDATORY criteria score 1, or multiple HIGHLY IMPORTANT criteria score 0–1. Dataset can support only a narrow subset of experiments, or results are likely to be compromised by fundamental limitations. |
| **UNUSABLE** | Any MANDATORY criterion scores 0, or the dataset fails a rejection condition in Section 5. Dataset cannot support ETTH's experimental requirements. |

### How to determine the classification

1. Check rejection conditions first (Section 5). If any apply, classify as UNUSABLE.
2. Check that all MANDATORY criteria score at least 1. If any score 0, classify as UNUSABLE.
3. Count the number of HIGHLY IMPORTANT criteria scoring 0 or 1.
4. Consider whether the dataset can actually support the intended experiments, not just whether individual criteria are met.
5. If serious leakage or label problems exist, downgrade by one level.

---

## 5. Dataset Rejection Conditions

A dataset must be classified as **UNUSABLE** if any of the following conditions apply, regardless of its scores on other criteria.

### 5.1 Hard Rejection Conditions

| Condition | Reason |
|-----------|--------|
| No raw PCAP files, and the experiment requires JA3/JA4 computation | Fingerprints cannot be computed without raw packet data. |
| No TLS ClientHello packets with required fields | JA3, JA3S, JA4, and JA4S cannot be computed. |
| No ground-truth labels | Supervised classification is impossible. |
| Labels are known to be wrong or randomly assigned | Model training and evaluation would be meaningless. |
| Severe data leakage with no feasible masking strategy | Classifier would learn dataset-specific shortcuts rather than traffic patterns. |
| Only one traffic class when the experiment requires comparison between classes | No basis for classification or performance measurement. |
| No reproducible access (paywall, geographic restriction, license prohibits research) | Results cannot be independently verified. |
| Dataset is entirely synthetic with no validation against real traffic | Results do not generalize to real networks. |

### 5.2 Soft Rejection Conditions (Downgrade to LOW or UNUSABLE)

| Condition | Reason |
|-----------|--------|
| Less than 50 encrypted flows total after filtering | Insufficient samples for stratified splitting. |
| Less than 10 samples per class after filtering | Per-class metrics are unreliable. |
| No temporal information (timestamps) when flow features are required | IATs and flow duration cannot be computed. |
| Only pre-extracted CSV features, and the required cryptographic fields are missing | JA4 cannot be reconstructed from aggregated statistics. |
| Dataset age is >10 years and used to claim modern TLS relevance | Traffic patterns and protocol versions are obsolete. |

---

## 6. Evidence Hierarchy

Not all evidence is equally reliable. When evaluating a criterion, prefer evidence from higher levels.

| Level | Source Type | Example |
|-------|-------------|---------|
| **1** | Original dataset publication | Peer-reviewed paper introducing the dataset. |
| **2** | Official dataset repository | University, research group, or conference website hosting the data. |
| **3** | Official dataset documentation | README, data sheet, or technical report from the dataset authors. |
| **4** | Official supplementary material | Appendices, code repositories, or verification scripts published by the authors. |
| **5** | Independent peer-reviewed evaluation | A separate research group that independently tested or used the dataset. |
| **6** | Secondary technical documentation | Blog posts, third-party tutorials, or community wiki pages. |
| **7** | Anecdotal / forum evidence | GitHub issues, Stack Overflow, or unverified claims. |

**Rule:** Important claims (especially those affecting the MANDATORY and HIGHLY IMPORTANT criteria) should be supported by evidence at Level 1–4 whenever possible. If only Level 5–7 evidence is available, the criterion should receive a lower score.

---

## 7. Uncertainty Rules

Use the following status labels when recording findings. Never treat missing information as confirming a positive claim.

| Status | Meaning |
|--------|---------|
| **VERIFIED** | The property has been confirmed by direct evidence (Level 1–4). |
| **NOT VERIFIED** | The property has not been confirmed. It may be true or false; evidence has not been collected. |
| **VERIFIED ABSENT** | The property has been confirmed to be absent by direct evidence. |
| **NOT APPLICABLE** | The property does not apply to this dataset (e.g., QUIC representation for a TCP-only dataset). |

### Examples

**Correct:**
- "JA4 computability: NOT VERIFIED. Sample PCAP extraction has not been performed."
- "Raw PCAP availability: VERIFIED. Official download page lists PCAP files, confirmed by sample inspection."

**Incorrect:**
- "JA4 is probably available because the dataset contains TLS traffic." (This is NOT VERIFIED, not a positive claim.)
- "Raw PCAPs are assumed to exist because the dataset is widely used." (This is NOT VERIFIED.)

---

## 8. Criteria Importance Summary

| Criterion | Importance | Notes |
|-----------|-----------|-------|
| 1. Raw PCAP availability | MANDATORY | Required for JA3/JA4 computation. |
| 2. Bidirectional traffic availability | MANDATORY | Required for bidirectional flow features. |
| 3. TLS ClientHello availability | MANDATORY | Required for JA3/JA4 computation. |
| 4. TLS ServerHello availability | MANDATORY | Required for JA3S/JA4S computation. |
| 5. TLS 1.2 representation | HIGHLY IMPORTANT | Baseline for JA4 evaluation. |
| 6. TLS 1.3 representation | HIGHLY IMPORTANT | Critical gap in current candidates. |
| 7. QUIC representation | OPTIONAL | Useful but not required for current experiments. |
| 8. JA3 computability | MANDATORY | Required for Experiments B and D. |
| 9. JA3S computability | MANDATORY | Required for Experiments B and D. |
| 10. JA4 computability | MANDATORY | Required for Experiments C and E (central research question). |
| 11. Flow feature computability | MANDATORY | Required for all experiments. |
| 12. Packet-size sequence availability | MANDATORY | Core flow feature for all experiments. |
| 13. Inter-arrival-time availability | MANDATORY | Core flow feature for all experiments. |
| 14. Benign traffic | MANDATORY | Required for supervised classification. |
| 15. Malware traffic | MANDATORY | Required for ETTH's threat-hunting research question. |
| 16. C2 traffic | HIGHLY IMPORTANT | Enables beaconing-specific feature evaluation. |
| 17. Quality of labels | MANDATORY | Required for scientifically valid supervised learning. |
| 18. Class balance | HIGHLY IMPORTANT | Extreme imbalance invalidates classifier evaluation. |
| 19. Capture environment information | HIGHLY IMPORTANT | Needed to identify and mitigate spurious features. |
| 20. Dataset size | HIGHLY IMPORTANT | Insufficient size prevents reliable stratified evaluation. |
| 21. Temporal information | MANDATORY | Required for IAT and flow-duration features. |
| 22. Licensing / accessibility | MANDATORY | Required for reproducibility. |
| 23. Reproducibility | MANDATORY | Core scientific requirement. |
| 24. Known leakage risks | MANDATORY | Required for masking and valid experimental design. |
| 25. Dataset age and protocol relevance | HIGHLY IMPORTANT | Affects generalizability of conclusions. |

---

## 9. Application Procedure

When evaluating a new candidate dataset:

1. Obtain the dataset and its official documentation.
2. For each of the 25 criteria, collect evidence and assign a score (0–3).
3. Record the evidence source for every score.
4. Check rejection conditions (Section 5). If any apply, classify as UNUSABLE and stop.
5. Check that all MANDATORY criteria score at least 1. If any score 0, classify as UNUSABLE.
6. Apply the overall suitability classification rules (Section 4).
7. Document uncertainties using the status labels in Section 7.
8. If any MANDATORY or HIGHLY IMPORTANT criterion is NOT VERIFIED, add a verification task to Phase 6 and do not finalize the classification until verification is complete.

---

## Files Created

- `docs/research/dataset-acceptance-criteria.md` — this document

## Files Modified

- None. This document is additive and does not modify any existing research files.

## Important Design Decisions

1. **25 discrete criteria** were selected to cover technical, labeling, reproducibility, and leakage aspects. No criterion was combined with another to keep scoring transparent.
2. **0–3 scale** was chosen over a more complex weighted system to avoid hidden math. The classification rules in Section 4 provide qualitative guidance for combining scores.
3. **Raw PCAP is MANDATORY** because JA4 cannot be reconstructed from CSV features. This is the single most important constraint on dataset selection.
4. **ClientHello and ServerHello are both MANDATORY** because JA3S/JA4S are required for the JA3-only and JA4-only experiments.
5. **TLS 1.3 representation is HIGHLY IMPORTANT** (not optional) because the current candidate set entirely lacks modern TLS 1.3 data, making it the highest-priority gap.
6. **Rejection conditions are explicit** to prevent a dataset from being accepted because it scores well on easy criteria while failing on critical ones.
7. **Evidence hierarchy prevents anecdotal claims** from supporting mandatory criteria.
8. **Uncertainty rules forbid inferring positive claims from missing evidence.** A dataset does not "probably" support JA4 just because it has TLS traffic.

## Unresolved Questions

1. The exact minimum sample-count thresholds for "sufficient size" (criterion 3.20) are not set here. They will be determined during Phase 6 verification based on the selected classifier and desired statistical power.
2. The weight of C2 traffic (criterion 3.16) may be adjusted if ETTH's scope shifts away from beaconing detection toward general malware classification.
3. QUIC representation (criterion 3.7) may be upgraded to HIGHLY IMPORTANT if ETTH decides to include QUIC-specific experiments in a later phase.

## Validation Result

- File created at: `docs/research/dataset-acceptance-criteria.md`
- All 25 criteria are present.
- No individual dataset is evaluated or selected.
- No fabricated research claims are included.
- Scoring system, importance classifications, rejection conditions, evidence hierarchy, and uncertainty rules are all defined.

## Git Status

```
On branch main
Untracked files:
  docs/research/dataset-acceptance-criteria.md
```

*No existing files were modified. No commits were made.*
