# Section 3 — Flow-Based Network Intrusion/Anomaly Detection

## Objective

Identify flow-level features that survive TLS encryption, establish baseline NIDS approaches, and characterize malware C2 traffic and obfuscation detection as adjacent tasks.

## Research Questions

- Which flow features (size, timing, byte ratios, inter-arrival times) retain discriminative power over TLS?
- How does encrypted C2 traffic differ statistically from legitimate application traffic?
- What are the limitations of existing flow-based NIDS when deployed on encrypted traffic?

## Subsections

### 3.1 Classic NIDS Feature Sets

**Placeholder:** Classic NIDS feature sets (KDD Cup, NSL-KDD) are not directly evaluated in the current corpus. The literature focuses on encrypted-traffic-specific features. This subsection should be expanded with classic NIDS sources in a later phase.

### 3.2 Encrypted Traffic NIDS: Surviving Features

Multiple papers confirm that specific feature families retain discriminative power under TLS encryption:

| Feature Family | Evidence | Notes |
|----------------|----------|-------|
| Packet size statistics (mean, std, min, max, quantiles) | garcia2018efficient, akem2024realtime, akbari2022traffic, martinramos2022cobalt, ramos2023cobalt | Universally effective; unaffected by encryption |
| Inter-arrival times (IATs) and IAT distributions | garcia2018efficient, akem2024realtime, akbari2022traffic, zhang2025beacon | Key for beaconing and temporal pattern detection |
| Flow duration | martinramos2022cobalt, barut2020tls | Used but noted as variable due to network latency; martinramos2022cobalt excluded it from their final model |
| Byte counts (orig/resp) | martinramos2022cobalt, ramos2023cobalt | Distinguishes upload/download patterns; useful for beacon payload characterization |
| Packet counts | martinramos2022cobalt | Simple but effective; combined with byte counts for byte-ratio uniformity |
| Connection state/history | martinramos2022cobalt | Zeek-specific; captures transaction patterns via history codes |
| Distribution-derived features (histograms, KSD bins) | garcia2018efficient | Outperforms simple statistical moments (std dev, variance, skew, kurtosis) |
| Coefficient of Variation (CV) of intervals | zhang2025beacon, ramos2023cobalt | Identifies low-jitter periodic flows; CV < 0.2 threshold used for beacon candidates |
| Multi-flow temporal features (dur_mean, dur_std, int_mean, int_std) | ramos2023cobalt | Captures cross-session behavioral patterns; critical for jittered beacon detection |

**Distribution-derived features:**
Garcia et al. (2018) specifically evaluate histogram-based features using Kolmogorov-Smirnov Discretization (KSD) for packet-size and IAT distributions. They find that adaptive KSD outperforms uniform and probabilistic binning, and that histogram-based features improve on statistical moments while requiring lower computational complexity.

### 3.3 Early Flow Classification

Akem et al. (2024) demonstrate that packet-size and IAT statistics alone (max, min, total, mean, median, std dev, quantiles, skew, kurtosis) enable in-switch encrypted traffic classification with 87.2–95.3% accuracy. This supports ETTH's ability to classify flows early, before sufficient packets accumulate for deep inspection.

### 3.4 Malware C2 Detection Over TLS

**Cobalt Strike detection:**
- Martin Ramos et al. (2022) detect ~50% of real-world Cobalt Strike C&C traces with 1.4% FPR using single-flow features (proto, service, history, orig_bytes, resp_bytes, orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes). Random Forest was the best-performing model for low-FPR deployment.
- Ramos et al. (2023) improve detection to 90.9% TPR with 0.4% FPR using multi-flow features derived from TLS session groups: nses, cltmoredata, clt1stappdata, dur, dur_mean, dur_std, int_mean, int_std. Neural network with L-BFGS solver achieved the best performance.
- Key insight: Multi-flow features that capture inherent Beacon characteristics (data jitter, sleep jitter, session patterns) significantly outperform single-flow approaches.

**Beaconing detection:**
- Zhang et al. (2025) detect Beacon behavior in encrypted SCADA/ICS traffic using only Zeek conn.log metadata. Isolation Forest achieves 94.59% accuracy using CV < 0.2 threshold and inter-arrival time statistics. Hybrid approach combines heuristic CV analysis and iForest.
- The approach is payload-independent and suitable for real-time monitoring.

**General malware detection:**
- Anderson & McGrew (2017) demonstrate that malware TLS usage differs from benign enterprise traffic: malware uses weaker ciphersuites ~20% more than DMZ traffic, and family attribution reaches 90.3% accuracy from a single encrypted flow.

**Flow interaction patterns:**
- Fu et al. (2024) propose HyperVision, which constructs a compact in-memory graph of flow interaction patterns. Malicious flows exhibit distinct interaction patterns (e.g., spam bots to SMTP servers) even when individual flows resemble benign traffic. More than 50% of attacks in their evaluation evaded all supervised baseline methods.

### 3.5 VPN, Tor, and Proxy Obfuscation Detection

**Placeholder:** The corpus does not contain dedicated studies on VPN/Tor/proxy obfuscation detection as adjacent tasks. This subsection should be expanded with additional sources in a later phase.

## Evidence Log

- garcia2018efficient: KSD histogram features outperform moments; packet-size and IAT distributions effective for video/VoIP classification.
- akem2024realtime: Packet-size and IAT statistics alone achieve 87.2-95.3% accuracy in-switch; tree-based models excel with encrypted traffic.
- akbari2022traffic: Flow statistics + traffic shape + handshake bytes effective; non-handshake packets redundant.
- martinramos2022cobalt: Single-flow RF detects ~50% Cobalt Strike with 1.4% FPR; feature selection critical.
- ramos2023cobalt: Multi-flow features achieve 90.9% TPR/0.4% FPR; handles jittered beacons.
- zhang2025beacon: Zeek metadata + Isolation Forest detects encrypted beacons at 94.59% accuracy; CV < 0.2 threshold.
- fu2024hypervision: Flow interaction graph detects unknown encrypted attacks; >50% of attacks evade supervised methods.
- anderson2016deciphering: Malware uses weaker ciphersuites; 90.3% family attribution per single flow.

## Synthesis

**Established:**
- Packet-size statistics, IATs, and flow duration are universally effective features for encrypted traffic classification, unaffected by payload encryption.
- Distribution-derived features (histograms, KSD bins) outperform simple statistical moments for capturing packet-size and IAT patterns.
- Multi-flow behavioral features (cross-session temporal patterns, byte ratios, session counts) are critical for detecting jittered C2 beacons.
- Beaconing detection via low CV of inter-arrival times is a validated signal, achieving >94% accuracy in lab settings.
- Flow interaction patterns (graph-based) reveal malicious behavior even when individual flows appear benign.

**Uncertain:**
- Generalization of beaconing detection thresholds (CV < 0.2) to diverse network environments with varied legitimate periodic traffic (NTP, updates, telemetry).
- Effectiveness of distribution-derived features for application categories beyond video/VoIP.
- Robustness of flow features against proxy-based adversarial modification.

## Research Implications

- ETTH should prioritize packet-size distributions, IAT patterns, flow durations, and byte ratios as core behavioral features.
- Multi-flow temporal features (cross-session patterns) should be incorporated for C2 detection, following Ramos et al. (2023).
- CV-based beaconing heuristics provide a lightweight baseline but must be calibrated against legitimate periodic traffic.
- Flow interaction graphs (HyperVision) offer an unsupervised complementary signal for unknown attack detection.
