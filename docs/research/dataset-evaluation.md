# Dataset Evaluation for ETTH

**Date:** 2026-08-14  
**Purpose:** Evaluate candidate datasets for Phase 5 experimental work  
**Research Question:** Does combining TLS fingerprint features (JA4/JA3S) with encrypted-flow behavioral features provide statistically significant improvement in detection performance compared to using either feature family in isolation?

---

## Evaluation Criteria

Each dataset is evaluated against the following criteria:

1. Dataset name
2. Original source
3. Publication / research paper associated with it
4. Dataset purpose
5. Traffic type
6. Benign traffic availability
7. Malicious/suspicious traffic availability
8. Number/type of classes
9. PCAP availability
10. Whether raw packet-level information is available
11. Whether TLS traffic exists
12. Whether TLS ClientHello information can potentially be extracted
13. Whether JA3 can potentially be computed
14. Whether JA4 can potentially be computed
15. Whether flow-level features can be extracted
16. Whether timestamps are available
17. Whether IP/port information is available
18. Dataset size
19. Known limitations
20. Known data leakage risks
21. Known class imbalance issues
22. Whether the dataset is suitable for our exact research question
23. Suitability rating: HIGH / MEDIUM / LOW
24. Reason for the rating

---

## Dataset 1: ISCXVPN2016

### 1. Dataset Name
ISCXVPN2016 (also called VPN-nonVPN dataset)

### 2. Original Source
University of New Brunswick, Canadian Institute for Cybersecurity (CIC)  
URL: https://www.unb.ca/cic/datasets/vpn.html

### 3. Publication / Research Paper
Gerard Drapper Gil, Arash Habibi Lashkari, Mohammad Mamun, Ali A. Ghorbani. "Characterization of Encrypted and VPN Traffic Using Time-Related Features." *Proceedings of the 2nd International Conference on Information Systems Security and Privacy (ICISSP 2016)*, pages 407-414, Rome, Italy.

### 4. Dataset Purpose
Characterize and classify encrypted and VPN traffic using time-related features. The dataset was designed to enable research on traffic classification for VPN and non-VPN encrypted applications.

### 5. Traffic Type
- VPN traffic (OpenVPN UDP mode using external VPN service provider)
- Non-VPN traffic (encrypted application traffic)
- Applications: Browsing (Firefox, Chrome), Email (SMTPS, POP3S, IMAPS), Chat (ICQ, AIM, Skype, Facebook, Hangouts), Streaming (Vimeo, YouTube), File Transfer (Skype, FTPS, SFTP via Filezilla), VoIP (Facebook, Skype, Hangouts), P2P (uTorrent, Transmission)

### 6. Benign Traffic Availability
Yes. Non-VPN traffic serves as benign baseline. Includes browsing, email, chat, streaming, file transfer, VoIP, and P2P.

### 7. Malicious/Suspicious Traffic Availability
No. This dataset contains only benign traffic (VPN and non-VPN). There is no malware or malicious traffic.

### 8. Number/Type of Classes
12 classes total:
- 6 non-VPN classes: Browsing, Email, Chat, Streaming, File Transfer, VoIP, P2P (some sources count 7)
- 6 VPN classes: corresponding VPN-encrypted versions of the above

### 9. PCAP Availability
Yes. Full packet captures in PCAP format are publicly available. Total size: approximately 28GB.

### 10. Raw Packet-Level Information
Yes. PCAP files contain full packet headers and payloads (layers 2-7).

### 11. TLS Traffic Exists
Yes. Contains TLS-encrypted traffic including SMTPS, POP3S, IMAPS, HTTPS, FTPS, and SFTP.

### 12. TLS ClientHello Information
UNKNOWN — REQUIRES VERIFICATION. The PCAP files contain raw packets, so ClientHello information is potentially present in TLS flows. However, this has not been verified by examining the actual PCAP contents. The dataset was collected in 2015-2016, so TLS 1.2 is the dominant version.

### 13. JA3 Possible
Potentially YES — but REQUIRES VERIFICATION. Since PCAP files are available, JA3 fingerprints can theoretically be computed from ClientHello packets using open-source tools. However, the age of the dataset (pre-2018) means many applications may use older TLS libraries. Verification requires actually extracting JA3 hashes from the PCAPs.

### 14. JA4 Possible
Potentially YES — but REQUIRES VERIFICATION. Same reasoning as JA3. JA4 requires the same ClientHello fields (with sorting and GREASE stripping). If ClientHello packets are present and contain sufficient fields, JA4 can be computed. However, JA4 was not designed until 2023, so no precomputed JA4 values exist in the dataset.

### 15. Flow-Level Features
Yes. The dataset is accompanied by CICFlowMeter-generated CSV files with flow features. Flow features can also be extracted from PCAPs using Zeek or similar tools.

### 16. Timestamps Available
Yes. PCAP files contain packet timestamps. CICFlowMeter CSV files also include flow timestamps.

### 17. IP/Port Information
Yes. PCAP files contain source/destination IP addresses and ports. CICFlowMeter CSV files include Flow Id, Source IP, Destination IP, Source Port, Destination Port.

### 18. Dataset Size
- Total: approximately 28GB of PCAP data
- 12 classes of traffic
- Captured using Wireshark and tcpdump

### 19. Known Limitations
- **High unencrypted traffic percentage:** Wickramasinghe et al. (2025) report 98.9% unencrypted traffic in ISCXVPN2016. This is a critical limitation for encrypted traffic classification research.
- **Deprecated cipher suites:** Contains traffic encrypted with outdated algorithms such as AES-CBC, 3DES, and RC4, which are deprecated in TLS 1.3 [wickramasinghe2025sok].
- **Pre-2018 collection:** Collected in 2015-2016, does not reflect modern TLS 1.3 traffic patterns.
- **Class imbalance:** Some classes have significantly more samples than others [wickramasinghe2025sok].
- **VPN tunneling:** VPN traffic may obscure underlying application patterns, making it difficult to distinguish application-level behavior.
- **No malware traffic:** Only contains benign VPN and non-VPN traffic. No malicious samples for binary malicious/benign classification.

### 20. Known Data Leakage Risks
- **IP addresses:** Source and destination IP addresses are present in PCAP and CSV files. These can serve as strong identifiers (data leakage) if not properly masked [wickramasinghe2025sok].
- **SNI exposure:** ClientHello packets likely contain SNI values that can leak destination information.
- **Port numbers:** Some applications use default ports, which can act as shortcuts.
- **Flow ID and timestamps:** CICFlowMeter CSV files include Flow ID and Timestamp fields that can enable data leakage if used in training.

### 21. Known Class Imbalance Issues
Yes. Reported by Wickramasinghe et al. (2025). Some traffic classes (e.g., P2P) have significantly more samples than others (e.g., Chat). This can detrimentally affect deep learning model performance.

### 22. Suitability for Exact Research Question
Partial. ISCXVPN2016 is suitable for evaluating flow-feature-only and TLS-fingerprint-only configurations on benign encrypted application traffic. However, it has critical limitations for ETTH's research question:
- No malicious traffic means binary malicious/benign classification is not possible.
- High unencrypted traffic percentage (98.9%) undermines the "encrypted traffic" premise.
- Deprecated cipher suites limit applicability to modern TLS 1.3.
- JA3/JA4 computability is unverified.

### 23. Suitability Rating
MEDIUM

### 24. Reason for Rating
ISCXVPN2016 provides raw PCAPs and flow features for benign encrypted application classification, but its 98.9% unencrypted traffic, lack of malicious samples, deprecated ciphers, and pre-2018 collection date limit its suitability for ETTH's research question. It can serve as a supplementary dataset for application classification tasks but should not be the primary dataset for malicious/benign detection.

---

## Dataset 2: CIC-Darknet2020

### 1. Dataset Name
CIC-Darknet2020 (also called DIDarknet)

### 2. Original Source
Canadian Institute for Cybersecurity (CIC), University of New Brunswick  
URL: https://www.unb.ca/cic/datasets/darknet2020.html

### 3. Publication / Research Paper
Arash Habibi Lashkari, Gurdip Kaur, Abir Rahali. "DIDarknet: A Contemporary Approach to Detect and Characterize the Darknet Traffic using Deep Image Learning." *Proceedings of the 10th International Conference on Communication and Network Security (ICCNS 2020)*, Tokyo, Japan, November 2020.

### 4. Dataset Purpose
Detect and characterize VPN and Tor traffic (darknet traffic) by amalgamating ISCXTor2016 and ISCXVPN2016 datasets. Designed for binary classification (darknet vs. benign) and multi-class application-type classification.

### 5. Traffic Type
- VPN traffic (from ISCXVPN2016)
- Tor traffic (from ISCXTor2016)
- Non-VPN, non-Tor benign traffic (surface web)
- Application categories: Audio-Streaming, Browsing, Chat, Email, File Transfer, P2P, Video-Streaming, VoIP

### 6. Benign Traffic Availability
Yes. Non-Tor, non-VPN traffic serves as benign baseline. 117,218 benign samples reported.

### 7. Malicious/Suspicious Traffic Availability
Partially. The dataset includes Tor and VPN traffic, which are often associated with malicious/obfuscated communication. However, the dataset does not contain actual malware traffic—it contains anonymized traffic (Tor/VPN) generated by legitimate applications.

### 8. Number/Type of Classes
Hierarchical labeling:
- Top layer: Tor, non-Tor, VPN, non-VPN (4 classes)
- Application layer: Audio-Streaming, Browsing, Chat, Email, File Transfer, P2P, Video-Streaming, VoIP (8 classes)
- Total: 158,659 samples

### 9. PCAP Availability
UNKNOWN — REQUIRES VERIFICATION. The official dataset page and Kaggle distributions provide CSV files (Darknet.CSV, 73.33 MB) generated by CICFlowMeter, not raw PCAP files. The original PCAPs may exist from ISCXTor2016 and ISCXVPN2016, but the CIC-Darknet2020 distribution itself appears to be feature-level CSV data.

### 10. Raw Packet-Level Information
No (in the CIC-Darknet2020 distribution). The dataset provides CICFlowMeter-extracted features, not raw packet data. Original PCAPs from constituent datasets (ISCXVPN2016, ISCXTor2016) are available separately.

### 11. TLS Traffic Exists
Yes. The constituent datasets (ISCXVPN2016, ISCXTor2016) contain TLS traffic. However, the CIC-Darknet2020 CSV distribution contains only flow features, not raw TLS handshake data.

### 12. TLS ClientHello Information
No (in the CIC-Darknet2020 distribution). The CSV files contain flow-level statistics, not raw ClientHello packets. To extract ClientHello information, one would need to obtain the original PCAP files from ISCXVPN2016 and ISCXTor2016 separately.

### 13. JA3 Possible
Not from CIC-Darknet2020 alone. The CSV distribution does not contain raw packets or ClientHello data. JA3 computation would require obtaining the original PCAP files from the constituent datasets.

### 14. JA4 Possible
Not from CIC-Darknet2020 alone. Same reasoning as JA3. The CSV distribution does not support JA4 computation.

### 15. Flow-Level Features
Yes. The dataset provides 81+ flow features extracted by CICFlowMeter, including flow duration, packet counts, byte counts, IATs, packet lengths, protocol, and IP/port information.

### 16. Timestamps Available
Yes. CICFlowMeter CSV files include Timestamp field.

### 17. IP/Port Information
Yes. Source IP, Destination IP, Source Port, Destination Port are present in the CSV files. This is a significant data leakage risk.

### 18. Dataset Size
- 158,659 samples
- Darknet.CSV: 73.33 MB
- Highly imbalanced: Tor only 1,393 samples; Non-Tor 93,357 samples

### 19. Known Limitations
- **No raw PCAPs in distribution:** The dataset provides only CICFlowMeter CSV features, not raw packets. This prevents TLS fingerprint extraction.
- **Extreme class imbalance:** Tor class has only 1,393 samples compared to 93,357 non-Tor samples [rust-nguyen2022].
- **Data leakage features:** IP addresses, ports, and protocol fields are present and can be used as shortcuts [wickramasinghe2025sok, wang2025bias].
- **Legacy encryption:** Constituent datasets contain deprecated cipher suites and unencrypted traffic.
- **Not malware traffic:** Tor/VPN traffic is anonymized, not necessarily malicious. This may not align with ETTH's threat-hunting focus.
- **Precomputed features only:** Cannot extract new features or recompute TLS fingerprints without original PCAPs.

### 20. Known Data Leakage Risks
High. The dataset includes Source IP, Destination IP, Source Port, Destination Port, and Protocol fields. Prior work [wickramasinghe2025sok] shows that IP addresses and ports can serve as Strong Identification Information (SII), enabling data leakage overfitting. The dataset was designed for deep image learning, not for feature-level analysis without IP/port leakage.

### 21. Known Class Imbalance Issues
Yes. Severe imbalance:
- Non-Tor: 93,357 samples
- Non-VPN: 23,864 samples
- VPN: 22,920 samples
- Tor: 1,393 samples

Tor is the minority class by a factor of ~67:1 compared to non-Tor.

### 22. Suitability for Exact Research Question
Low. CIC-Darknet2020 does not contain raw PCAPs, making JA3/JA4 computation impossible without obtaining separate datasets. The extreme class imbalance, presence of IP/port leakage features, and lack of actual malicious traffic further limit its suitability.

### 23. Suitability Rating
LOW

### 24. Reason for Rating
No raw packet data prevents TLS fingerprint extraction. Extreme class imbalance and IP/port leakage features introduce significant bias. The dataset focuses on Tor/VPN anonymization rather than malware detection, which may not align with ETTH's threat-hunting objectives.

---

## Dataset 3: USTC-TFC2016

### 1. Dataset Name
USTC-TFC2016 (University of Science and Technology of China - Traffic Flow Classification 2016)

### 2. Original Source
University of Science and Technology of China (USTC) and Institute of Acoustics, Chinese Academy of Sciences  
URL: https://github.com/yungshenglu/USTC-TFC2016

### 3. Publication / Research Paper
Wei Wang, Ming Zhu, Xuewen Zeng, Xiaozhou Ye, Yiqiang Sheng. "Malware Traffic Classification Using Convolutional Neural Network for Representation Learning." *2017 International Conference on Information Networking (ICOIN)*, pp. 712-717, 2017.  
Also: Wang Wei, "Research on Network Traffic Classification and Anomaly Detection Methods Based on Deep Learning," Ph.D. Thesis, University of Science and Technology of China, 2018.

### 4. Dataset Purpose
Malware traffic classification using deep learning. Designed to enable research on distinguishing malicious network traffic from benign application traffic.

### 5. Traffic Type
- Benign traffic: BitTorrent, Facetime, FTP, Gmail, MySQL, Outlook, Skype, SMB, Weibo, WorldOfWarcraft
- Malware traffic: Cridex, Geodo, Htbot, Miuref, Neris, Nsis-ay, Shifu, Tinba, Virut, Zeus
- Malware traffic sourced from CTU dataset (Czech Technical University), collected from real environments 2011-2015
- Benign traffic generated by network instrument simulation

### 6. Benign Traffic Availability
Yes. 10 benign classes: BitTorrent, Facetime, FTP, Gmail, MySQL, Outlook, Skype, SMB, Weibo, WorldOfWarcraft.

### 7. Malicious/Suspicious Traffic Availability
Yes. 10 malware families: Cridex, Geodo, Htbot, Miuref, Neris, Nsis-ay, Shifu, Tinba, Virut, Zeus. Sourced from real malware captures in the CTU dataset.

### 8. Number/Type of Classes
20 classes total:
- 10 benign classes
- 10 malware classes

### 9. PCAP Availability
Yes. Raw PCAP files are available via GitHub repository. Some files are compressed (7z) to save space. Total uncompressed size: 3.71GB.

### 10. Raw Packet-Level Information
Yes. PCAP files contain full packet headers and payloads.

### 11. TLS Traffic Exists
Yes. The dataset includes TLS-encrypted traffic (e.g., Gmail uses HTTPS, Skype uses proprietary/TLS, BitTorrent may use encrypted transports). However, the Wickramasinghe SoK (2025) reports that USTC-TFC2016 contains 94.7% unencrypted traffic, suggesting many flows are not TLS-encrypted.

### 12. TLS ClientHello Information
UNKNOWN — REQUIRES VERIFICATION. Since raw PCAP files are available, ClientHello packets are potentially present in TLS flows. However, this requires verification by examining the actual PCAP contents. The malware traffic dates from 2011-2015, so TLS 1.0/1.2 is dominant.

### 13. JA3 Possible
Potentially YES — but REQUIRES VERIFICATION. Since PCAP files are available, JA3 fingerprints can theoretically be computed from ClientHello packets. However, the high percentage of unencrypted traffic (94.7%) means many flows may not have TLS handshakes. Verification requires actually extracting JA3 hashes from the PCAPs.

### 14. JA4 Possible
Potentially YES — but REQUIRES VERIFICATION. Same reasoning as JA3. If ClientHello packets are present with sufficient fields, JA4 can be computed. No precomputed JA4 values exist.

### 15. Flow-Level Features
Yes. Flow features can be extracted from PCAPs using Zeek, CICFlowMeter, or similar tools. The USTC-TK2016 toolkit provides PowerShell scripts for session splitting and processing.

### 16. Timestamps Available
Yes. PCAP files contain packet timestamps.

### 17. IP/Port Information
Yes. PCAP files contain source/destination IP addresses and ports.

### 18. Dataset Size
- Total uncompressed size: 3.71GB
- 20 PCAP files (10 benign, 10 malware)
- Some files compressed in 7z format

### 19. Known Limitations
- **High unencrypted traffic:** Wickramasinghe et al. (2025) report 94.7% unencrypted traffic. This severely limits applicability for encrypted traffic classification.
- **Deprecated cipher suites:** Contains traffic encrypted with AES-CBC, 3DES, and RC4 [wickramasinghe2025sok].
- **Pre-2018 collection:** Malware traffic collected 2011-2015; benign traffic generated in 2016. Does not reflect modern TLS 1.3.
- **Small size:** 3.71GB is relatively small compared to modern datasets. May not provide sufficient samples for deep learning.
- **Synthetic benign traffic:** Benign traffic was generated by network instrument simulation, not real users. May not reflect real-world benign patterns.
- **Malware sandbox origin:** Malware traffic from CTU dataset was collected in controlled environments, which may not reflect real-world C2 behavior [anderson2016deciphering].

### 20. Known Data Leakage Risks
- **IP addresses and ports:** Present in raw PCAPs. Must be masked to prevent overfitting.
- **Packet timing artifacts:** Session-based splitting may introduce timing artifacts that serve as shortcuts.

### 21. Known Class Imbalance Issues
UNKNOWN — REQUIRES VERIFICATION. The dataset appears to have roughly balanced classes (10 benign, 10 malware), but per-class sample counts within each PCAP file are not documented in the sources consulted. Verification requires examining the actual data distribution.

### 22. Suitability for Exact Research Question
Partial. USTC-TFC2016 is the strongest candidate among the three because it contains both benign and malware traffic in PCAP format, enabling JA3/JA4 computation and flow feature extraction. However, its 94.7% unencrypted traffic and deprecated cipher suites are critical limitations for encrypted traffic research.

### 23. Suitability Rating
MEDIUM

### 24. Reason for Rating
USTC-TFC2016 provides raw PCAPs with both benign and malware traffic, enabling TLS fingerprint computation and flow feature extraction. However, 94.7% unencrypted traffic, deprecated cipher suites, and pre-2018 collection limit its applicability to modern encrypted traffic classification. It is the best available option among the three candidates but requires careful preprocessing to isolate encrypted flows.

---

## Comparison Table

| Dataset | PCAP | TLS | ClientHello | JA3 possible | JA4 possible | Flow features | Labels | Main limitation | Suitability |
|---------|------|-----|-------------|--------------|--------------|---------------|--------|-----------------|-------------|
| ISCXVPN2016 | Yes | Yes | UNKNOWN — REQUIRES VERIFICATION | Potentially — REQUIRES VERIFICATION | Potentially — REQUIRES VERIFICATION | Yes (CICFlowMeter + raw) | 12 classes (benign + VPN) | 98.9% unencrypted; no malware; deprecated ciphers | MEDIUM |
| CIC-Darknet2020 | No (CSV only) | Yes (in constituent datasets) | No (not in distribution) | No (no raw packets) | No (no raw packets) | Yes (precomputed CICFlowMeter) | 4/8 classes (Tor/VPN + apps) | No raw PCAPs; extreme imbalance; IP/port leakage | LOW |
| USTC-TFC2016 | Yes | Yes (partial) | UNKNOWN — REQUIRES VERIFICATION | Potentially — REQUIRES VERIFICATION | Potentially — REQUIRES VERIFICATION | Yes (extractable) | 20 classes (benign + malware) | 94.7% unencrypted; deprecated ciphers; synthetic benign | MEDIUM |

---

## Recommended Dataset Strategy

### Primary Recommendation

**Do not rely on any single candidate dataset as the sole evaluation basis.** The three currently proposed datasets share critical limitations:

1. **High unencrypted traffic percentages:** ISCXVPN2016 (98.9%) and USTC-TFC2016 (94.7%) contain predominantly unencrypted traffic, undermining the encrypted traffic classification premise [wickramasinghe2025sok].
2. **Deprecated cipher suites:** All three datasets contain traffic encrypted with AES-CBC, 3DES, and RC4, which are deprecated in TLS 1.3.
3. **Limited or no raw packet access:** CIC-Darknet2020 provides only CSV features, preventing TLS fingerprint extraction.
4. **No modern TLS 1.3 representation:** None of the datasets contain significant TLS 1.3 traffic with AEAD cipher suites.

### Recommended Strategy

**Tiered approach:**

#### Tier 1: USTC-TFC2016 (best available option)
- Use as the primary dataset for proof-of-concept experiments.
- Preprocess to isolate TLS-encrypted flows only (filter out unencrypted traffic).
- Compute JA3/JA4 fingerprints from raw PCAPs after verifying ClientHello presence.
- Extract flow features using Zeek or CICFlowMeter.
- Acknowledge dataset limitations (deprecated ciphers, synthetic benign traffic) in results.

#### Tier 2: ISCXVPN2016 (supplementary)
- Use for application classification benchmarks (flow-only and TLS-only configurations).
- Provides larger sample size and diverse applications.
- Preprocess to isolate encrypted flows.
- Useful for comparing flow-feature performance across different applications.

#### Tier 3: CIC-Darknet2026 (limited role)
- Use only for flow-feature-only baselines where raw PCAPs are not required.
- Acknowledge that JA3/JA4 cannot be computed from this dataset.
- Extreme class imbalance requires careful handling (stratified splits, per-class metrics).

#### Tier 4: Supplement with modern dataset
**Strongly consider adding a modern TLS 1.3 dataset** to address the critical gap in current candidates. Potential alternatives:

- **CSTNET-TLS1.3:** Contains exclusively TLS 1.3 traffic with modern AEAD cipher suites [wickramasinghe2025sok]. However, availability and access must be verified.
- **CipherSpectrum:** Introduced by Wickramasinghe et al. (2025), contains 120,000 sessions encrypted with TLS 1.3 AEAD ciphers. Publicly available. This is the most rigorous modern option but may require formal request.
- **Self-collected traffic:** If public datasets are insufficient, consider collecting a small, controlled dataset of modern TLS 1.3 traffic from common applications (browsers, email, chat). This ensures TLS 1.3 representation and enables JA4 computation.

### Preprocessing Requirements (All Datasets)

Regardless of dataset selection, the following preprocessing is mandatory:

1. **Filter to encrypted flows only:** Remove unencrypted flows to align with ETTH's research question.
2. **Mask IP addresses:** Zero or remove source/destination IP addresses to prevent data leakage.
3. **Extract timestamps:** Ensure packet-level timestamps are available for IAT computation.
4. **Extract flow features:** Use Zeek or CICFlowMeter with identical parameters across datasets.
5. **Compute TLS fingerprints:** Extract JA3 and JA4 from ClientHello packets using open-source libraries.
6. **Stratified splitting:** Preserve class distribution in train/test splits.
7. **Document class distribution:** Record exact sample counts per class in train and test sets.

### Critical Uncertainties

The following must be verified before downloading any dataset:

1. **JA3/JA4 computability:** Whether ClientHello packets are present and complete enough in ISCXVPN2016 and USTC-TFC2016 PCAPs. This requires examining actual PCAP contents, not just documentation.
2. **TLS flow percentage:** Exact percentage of TLS-encrypted flows in each dataset, after filtering out unencrypted traffic.
3. **Cipher suite distribution:** Whether modern cipher suites are present or only deprecated ones.
4. **Class balance after filtering:** How many samples remain per class after removing unencrypted flows.
5. **CSTNET-TLS1.3 availability:** Whether this dataset can be obtained and used.
6. **CipherSpectrum access:** Whether the dataset is publicly accessible and what license restrictions apply.

### Does the Current Experimental Design Need Modification?

**Yes, potentially.** The current experimental design assumes all three datasets are equally usable. The evaluation reveals:

1. **CIC-Darknet2020 should be downgraded** from primary to supplementary role because it lacks raw PCAPs.
2. **USTC-TFC2016 should become the primary dataset** despite its limitations, because it is the only candidate with both raw PCAPs and malware traffic.
3. **A modern TLS 1.3 dataset should be added** to the experimental design. Without this, all experiments will be conducted on legacy traffic, limiting the validity of conclusions for modern networks.
4. **JA4 computation must be treated as unverified** until actual PCAP examination confirms ClientHello field availability.

---

## Files Created

- `docs/research/dataset-evaluation.md` — this document

## Sources Consulted

1. Draper Gil et al. (2016) — ISCXVPN2016 original paper
2. Lashkari et al. (2020) — CIC-Darknet2020 original paper
3. Wang et al. (2017) — USTC-TFC2016 original paper
4. UNB CIC dataset pages (vpn.html, darknet2020.html)
5. GitHub repositories (yungshenglu/USTC-TFC2016, Marzoug-Nabil/CIC-darknet2020)
6. Wickramasinghe et al. (2025) — SoK on encrypted network traffic classifiers
7. Rust-Nguyen & Stamp (2022) — Darknet traffic classification and adversarial attacks
8. Marim et al. (2023) — Darknet traffic classification with decision trees
9. Sharma (SJSU) — Classification of darknet traffic by application type
10. MFF paper (Electronics 2024) — multimodal feature fusion for encrypted traffic

## Dataset Recommendations

| Dataset | Role | Rationale |
|---------|------|-----------|
| USTC-TFC2016 | Primary | Raw PCAPs + malware traffic + benign traffic. Best available option despite limitations. |
| ISCXVPN2016 | Supplementary | Larger sample size, diverse applications, raw PCAPs. Useful for application classification benchmarks. |
| CIC-Darknet2020 | Limited | Flow features only, no raw packets. Useful for flow-only baselines where JA3/JA4 are not required. |
| Modern TLS 1.3 dataset (TBD) | Essential | Critical gap. Current candidates lack modern TLS 1.3 representation. |

## Major Uncertainties

1. JA3/JA4 computability from ISCXVPN2016 and USTC-TFC2016 PCAPs — requires PCAP examination
2. Exact TLS flow percentages after filtering — requires dataset analysis
3. Availability of modern TLS 1.3 datasets (CSTNET-TLS1.3, CipherSpectrum)
4. Class balance after removing unencrypted flows from USTC-TFC2016

## What Must Be Verified Before Downloading Any Dataset

1. Download sample PCAPs from ISCXVPN2016 and USTC-TFC2016 and verify TLS ClientHello presence.
2. Compute JA3 hashes on sample PCAPs to verify extraction pipeline works.
3. Attempt JA4 computation on sample PCAPs to verify field availability.
4. Filter each dataset to encrypted flows only and record class distribution.
5. Verify CipherSpectrum or CSTNET-TLS1.3 access conditions and licensing.
6. Confirm computational feasibility (storage, processing time) for selected datasets.

## Experimental Design Implications

The current experimental design (Experiments A-E) remains valid in structure, but dataset selection must be updated:

- **Experiment A (Flow-only):** Can use all three datasets.
- **Experiment B (JA3-only) and C (JA4-only):** Cannot use CIC-Darknet2020 (no raw packets). Must use ISCXVPN2016 and/or USTC-TFC2016.
- **Experiments D and E (Combined):** Cannot use CIC-Darknet2020. Must use ISCXVPN2016 and/or USTC-TFC2016, plus a modern TLS 1.3 dataset if obtained.

**If no modern TLS 1.3 dataset can be obtained**, the experimental scope must be narrowed to:
- Legacy TLS 1.2 traffic only
- Explicit acknowledgment that results may not generalize to TLS 1.3 and ECH
- Focus on methodological comparison (flow-only vs. TLS-only vs. combined) rather than modern deployment readiness
