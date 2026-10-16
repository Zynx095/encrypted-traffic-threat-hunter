# Encrypted Traffic Threat Hunter: Evaluating TLS Fingerprints and Behavioral Flow Fusion for Zero-Decryption Network Intrusion Detection

**Authors:** ETTH Academic Research Group  
**Target Submission:** Research in Attacks, Intrusions, and Defenses (RAID) / Annual Computer Security Applications Conference (ACSAC)  
**Status:** Working Draft (Post-Phase 7 Controlled Pilot & Phase 11 Sensor Architecture)  

---

## Abstract

The near-universal adoption of Transport Layer Security (TLS 1.2 and TLS 1.3) has rendered traditional deep packet inspection (DPI) obsolete for modern network intrusion detection. While organizations increasingly deploy TLS-intercepting middleboxes, payload decryption introduces severe privacy violations, high computational overhead, and cryptographic vulnerabilities. In response, this paper presents **Encrypted Traffic Threat Hunter (ETTH)**, an open, zero-decryption threat detection architecture designed to investigate whether fusing observable client TLS fingerprints (JA3 and JA4) with bidirectional encrypted-flow behavioral features provides measurable advantages over isolated feature families. 

We evaluate five controlled experimental configurations (Tracks A–E) across 2,549 network flows under a group-aware cross-validation protocol (`GroupShuffleSplit`) that strictly isolates repetitive malware beaconing geometries (`behavioral_hash`) and strips all deterministic host and environmental identifiers. Our engineering pilot demonstrates that the multi-track pipeline executes deterministically without data leakage. However, our rigorous statistical audit reveals a critical methodological limitation: existing academic evaluations frequently suffer from severe **dataset-source confounding**. In our pilot corpus (2,543 malicious flows from Malware-Traffic-Analysis.net vs. 6 benign validation flows from CipherSpectrum), classifiers achieved near-perfect performance (PR-AUC 1.000, F1 0.999) by trivially separating virtualization artifacts of malware sandboxes rather than genuine threat signatures. We formulate a comprehensive research claim ledger, document the exact pre-submission criteria needed to resolve source confounding, and introduce an extensible multi-sensor ingestion layer supporting Zeek JSON, Suricata EVE, and Linux eBPF telemetry without payload decryption.

---

## 1. Keywords
Network Security, Encrypted Traffic Analysis, Transport Layer Security (TLS), JA3/JA4 Fingerprinting, Zero-Decryption Detection, Dataset Leakage, Source Confounding, Zeek, Suricata, eBPF.

---

## 2. Introduction
Encrypted network protocols now account for over 95% of enterprise and consumer web traffic. While this transition protects user privacy against eavesdropping, adversaries routinely weaponize encryption to conceal command-and-control (C2) beaconing, data exfiltration, and lateral malware staging. Security operations centers (SOCs) have historically responded by deploying enterprise decryption proxies ("TLS break-and-inspect"). However, decryption breaks end-to-end security guarantees, introduces compliance liability under regulations such as GDPR and HIPAA, and is rendered increasingly infeasible by emerging protocol standards such as Encrypted ClientHello (ECH) and TLS 1.3 0-RTT session resumption.

The central challenge of modern network defense is therefore **detecting threats inside encrypted sessions without decrypting payload contents**.

---

## 3. Research Motivation & Problem Definition
Network analysts can passively observe two distinct feature families from encrypted flows:
1. **TLS Handshake Metadata**: The unencrypted cryptographic parameters exchanged during session negotiation (TLS version, cipher suite vectors, extension arrays, supported elliptic curves, ALPN tokens, and client fingerprints such as Salesforce JA3 and FoxIO JA4).
2. **Behavioral Flow Dynamics**: Statistical geometries of packet transmissions (packet sizes, directional byte ratios, burstiness, inter-arrival time distributions, and duration).

While prior literature has explored handshake hashing and flow modeling independently, there is a lack of rigorous, leakage-controlled research examining:
- Does fusing modern client fingerprints (JA4) with flow dynamics provide statistically measurable detection gains over flow-only baselines?
- How severely does environmental and dataset-source confounding artificially inflate published benchmark metrics in encrypted traffic research?

---

## 4. Research Questions & Hypotheses

- **RQ1 (Feature Fusion Advantage):** Does combining TLS client fingerprints (JA3/JA4) with encrypted-flow behavioral statistics improve malicious flow detection compared to using either feature family in isolation?
  - *Hypothesis $H_1$:* Fusion configurations (Tracks D and E) will achieve higher Precision-Recall AUC on mixed benign/malicious traffic than flow-only (Track A) or fingerprint-only (Tracks B and C) models.
- **RQ2 (Fingerprint Evolution):** Does FoxIO JA4 provide superior discriminative power and lower collision rates than legacy JA3 MD5 hashes in identifying malicious C2 agents?
  - *Hypothesis $H_2$:* JA4 will reduce false-positive rates on diverse benign applications due to its structured protocol framing and extension hashing.
- **RQ3 (Source Confounding Impact):** To what extent do capture-environment discrepancies between benign and malicious datasets introduce spurious correlation in encrypted traffic classification?
  - *Hypothesis $H_3$:* High reported classification metrics on disparate datasets reflect environment separation rather than malicious pattern detection.

---

## 5. Related Work
- **Encrypted Traffic Analysis & Flow Statistics:** Anderson and McGrew (Cisco Systems, 2016; 2017) pioneered the use of unencrypted TLS metadata combined with packet length and time sequences for malware detection, demonstrating that C2 channels exhibit distinct statistical geometries.
- **TLS Handshake Fingerprinting:** Althouse et al. (Salesforce, 2017) introduced **JA3** and **JA3S**, constructing MD5 hashes over ClientHello and ServerHello parameter tuples. In 2023, Brotherston (FoxIO) formulated **JA4+**, modernizing fingerprinting by incorporating protocol framing, extension sorting, and ALPN awareness to mitigate hashing collisions.
- **Dataset Leakage & Confounding in NIDS:** Arp et al. ("Dos and Don'ts of Machine Learning in Computer Security", USENIX Security 2022) and Sommer and Paxson ("Outside the Closed World", IEEE S&P 2010) demonstrated that network intrusion datasets frequently suffer from severe sampling biases, temporal artifacts, and source confounding, leading to artificially inflated evaluation scores that collapse in operational deployments.

---

## 6. Threat Model & Scope
- **Adversary Capabilities:** The adversary deploys modern malware families (e.g., Lumma Stealer, Remcos RAT, XWorm, DarkGate) communicating over standard TLS (v1.2 or v1.3). The adversary controls application payload data and may utilize legitimate public hosting or shared CDNs.
- **Defender Capabilities:** The defender operates passive network taps or host sensors (Zeek, Suricata, eBPF). The defender **cannot** access private session keys, install custom root CA certificates on endpoints, or terminate TLS sessions.
- **Out-of-Scope:** Attacks that do not generate network traffic, non-TLS encrypted protocols (e.g., custom raw cryptographic ciphers over UDP), and active man-in-the-middle attacks.

---

## 7. System Architecture
ETTH comprises an end-to-end modular architecture:
1. **Sensor Ingestion Layer:** Ingests live packets via Scapy/Npcap, Zeek JSON logs (`conn.log`, `ssl.log`), Suricata EVE JSON (`flow`, `tls`, `alert`), and Linux eBPF socket events.
2. **Bidirectional Flow Reconstructor:** Reconstructs canonical 5-tuples using a 15-second idle timeout and TCP FIN/RST tracking.
3. **Leakage-Controlled Feature Engine:** Derives 80 behavioral statistical features and extracts unencrypted JA3/JA4 fingerprints while stripping all IP, port, and timestamp identifiers.
4. **Target Attribution Engine (`TargetResolver`):** Implements time-aware DNS correlation and dot-prefixed subdomain validation to attribute flows to logical monitoring targets while rejecting suffix-spoofing attacks.
5. **Real-Time Inference & WebSocket Engine:** Routes normalized flows through five experimental tracks and broadcasts validated `ETTHStreamEvent` envelopes to an interactive research dashboard.

---

## 8. Dataset Provenance & Acquisition
ETTH integrates verified datasets with full SHA-256 cryptographic provenance:
- **DS-008 (Malware-Traffic-Analysis.net):** Primary malicious corpus comprising real-world malware sandbox captures (AsyncRAT, Lumma Stealer, Remcos RAT, XWorm, DarkGate, GuLoader, Pikabot, Meduza Stealer). Reconstructed malicious flows: **2,543**.
- **DS-004 (CipherSpectrum):** Benign validation baseline containing pristine TLS 1.2 and 1.3 handshakes across verified web services. Reconstructed benign flows: **6**.
- **Dataset Integrity Safeguards:** All source archives (`MTA-C003.zip` through `MTA-C049.zip`) are cryptographically audited and permanently protected against mutation.

---

## 9. Feature Extraction & TLS Fingerprinting
- **Behavioral Statistics (80 features):** Extracted from forward and reverse packet lengths, inter-arrival times (mean, variance, skewness, 10th–90th percentiles), byte volume asymmetry, packets per second, and burst-to-idle ratios.
- **TLS Handshake Fingerprints:**
  - `JA3`: $\text{MD5}(\text{Version},\text{Ciphers},\text{Extensions},\text{EllipticCurves},\text{PointFormats})$
  - `JA4`: Formatted string encoding protocol (`t` for TCP), TLS version (`13`), SNI presence (`d`), extension counts, and SHA-256 truncated hashes of sorted ciphers and extensions.
- **Semantic Null Preservation:** If a flow lacks a ClientHello, fingerprint values evaluate strictly to `None`. No dummy hashes or zero-imputations are injected.

---

## 10. Experimental Methodology
We evaluate five mutually exclusive feature tracks:
- **Track A (Flow-only):** 80 behavioral flow statistics; zero TLS metadata.
- **Track B (JA3-only):** Isolated JA3 MD5 client hash.
- **Track C (JA4-only):** Isolated JA4 string fingerprint.
- **Track D (JA3 + Flow):** 81 features (JA3 hash + 80 flow statistics).
- **Track E (JA4 + Flow):** 81 features (JA4 signature + 80 flow statistics).

---

## 11. Leakage Prevention & Evaluation Protocol
To prevent optimistic evaluation bias:
1. **Identifier Stripping:** Source/destination IP addresses, ports, MAC addresses, raw SNI domain strings, timestamps, and capture session IDs are excluded from feature matrices.
2. **Group-Aware Splitting:** Malware sandbox captures generate repetitive beaconing flows with identical feature vectors. Standard K-Fold cross-validation leaks duplicate vectors across splits. ETTH computes `behavioral_hash` (SHA-256 of the 80 flow features) and enforces `GroupShuffleSplit(n_splits=5, test_size=0.2, random_state=42)`.
3. **Training-Only Transformers:** Imputation, standard scaling, and categorical encoders are fitted strictly inside training folds.

---

## 12. Baselines & Classifiers
We evaluate three canonical estimators suitable for low-latency operational deployment:
1. **L2-Regularized Logistic Regression** (Linear baseline).
2. **Random Forest Classifier** (Non-linear ensemble; 100 estimators, balanced class weights).
3. **Extreme Gradient Boosting (XGBoost)** (Gradient boosted decision trees; learning rate 0.1, max depth 6).

---

## 13. Results & Empirical Evaluation

### Controlled Pilot Results (Phase 7 Step 5)

| Track | Features | Total Samples | Malicious | Benign | Best Model | Avg PR-AUC | Avg F1 | Avg ROC-AUC |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Track A** (Flow) | 80 | 2,549 | 2,543 | 6 | Logistic Regression | 1.000 | 1.000 | 1.000 |
| **Track B** (JA3) | 1 | 200 | 194 | 6 | Logistic Regression | 0.997 | 0.982 | 0.958 |
| **Track C** (JA4) | 1 | 200 | 194 | 6 | Random Forest | 0.998 | 0.982 | 0.979 |
| **Track D** (JA3+Flow) | 81 | 200 | 194 | 6 | Logistic Regression | 1.000 | 0.997 | 1.000 |
| **Track E** (JA4+Flow) | 81 | 200 | 194 | 6 | Logistic Regression | 1.000 | 0.997 | 1.000 |

*Note: In fingerprint-dependent tracks (B, C, D, E), sample count is 200 because only flows possessing valid unencrypted ClientHello messages are eligible. All missing fingerprints remain semantic nulls.*

---

## 14. Statistical Analysis & Uncertainty
While the pilot evaluation proves that the ETTH feature extraction and model pipelines function mechanically without runtime exceptions, the statistical confidence of the results is severely bounded:
- Benign validation sample size ($N=6$) yields an effective test set of only 1–2 benign instances per fold.
- The 95% confidence intervals around F1 and PR-AUC cannot be reliably parameterized due to extreme zero-variance in the majority class.

---

## 15. Error Analysis & Source-Confounding Audit
An in-depth inspection of feature weights revealed that the linear classifier assigned overwhelming importance to `flow_duration` and `inter_arrival_time_min`. In DS-008, sandbox execution overhead introduced microsecond scheduling jitter absent from DS-004 web server captures. 
Consequently, **the classifiers achieved perfect scores by detecting virtualization artifacts rather than malicious communication behavior**. This finding underscores the necessity of unconfounded dataset acquisition before asserting scientific claims.

---

## 16. Explainability
Feature importance rankings generated by Random Forest and XGBoost indicate that packet length variance and directional byte asymmetry provide the strongest signals within flow features. However, feature correlation must not be equated with causality; observable feature presence indicates associative correlation within the evaluated corpus.

---

## 17. Limitations & Threats to Validity
1. **Dataset-Source Confounding:** The primary threat to external validity is the disparate capture environments of DS-008 and DS-004.
2. **Encrypted ClientHello (ECH):** ECH encrypts the `ClientHelloOuter` payload, concealing SNI and extensions from passive observers. Under full ECH deployment, fingerprinting must rely on Outer extensions or pure behavioral flow geometry.
3. **Fingerprint Collisions:** Malware leveraging standard operating system network stacks (e.g. `wininet.dll` or standard Windows cURL) exhibits identical JA3/JA4 hashes to benign software on the same host.

---

## 18. Ethical & Privacy Considerations
ETTH strictly adheres to ethical network measurement standards. All processed traffic is derived from public research repositories or synthetic software fixtures. Zero payload inspection is performed, preventing exposure of user credentials, session cookies, or personal communications.

---

## 19. Reproducibility
All experimental code, group-aware cross-validation splits, and pipeline configurations are fully reproducible via the provided repository test suite and replication scripts using Python 3.12 and fixed random seed 42.

---

## 20. Conclusion & Future Work
This paper presented the architecture and controlled pilot evaluation of the Encrypted Traffic Threat Hunter platform. We demonstrated that multi-track feature fusion pipelines can be constructed under strict zero-decryption and leakage-controlled constraints. More importantly, our empirical audit demonstrated that without independent, unconfounded benign corpora, machine learning models yield deceptive benchmark performance. Future work will complete Phase 8 benign dataset acquisition, benchmark generalized performance across expanded threat families, and evaluate Linux eBPF kernel sequence models.

---

## 21. References
1. Anderson, B., & McGrew, D. (2016). Identifying encrypted malware traffic with contextual flow data. *ACM AISec*, 35–46.
2. Anderson, B., & McGrew, D. (2017). Machine learning for encrypted malware traffic classification: Accounting for passive and active adversaries. *IEEE Transactions on Network and Service Management*, 14(4), 1058–1070.
3. Althouse, J., Atkinson, J., Blum, N., & Stearns, C. (2017). Open-sourcing JA3: TLS fingerprinting for threat intelligence. *Salesforce Engineering Blog*.
4. Brotherston, J. (2023). JA4+ Network Fingerprinting. *FoxIO Technical Report*.
5. Arp, D., Quiring, E., Pendlebury, F., Warnecke, A., Pierazzi, F., Dos Santos, C., Cavallaro, L., & Rieck, K. (2022). Dos and don'ts of machine learning in computer security. *USENIX Security Symposium*, 3971–3988.
6. Sommer, R., & Paxson, V. (2010). Outside the closed world: On using machine learning for network intrusion detection. *IEEE Symposium on Security and Privacy (S&P)*, 305–316.
7. Paxson, V. (1999). Bro: a system for detecting network intruders in real-time. *Computer Networks*, 31(23-24), 2435–2463.
8. Roesch, M. (1999). Snort: Lightweight intrusion detection for networks. *LISA*, 99(1), 229–238.
