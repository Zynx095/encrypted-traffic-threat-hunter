# ETTH Research Foundation

## 1. Research Domain

The Encrypted Traffic Threat Hunter (ETTH) project falls within the domain of Network Security, specifically focusing on Encrypted Traffic Analysis. As modern network communications increasingly adopt encryption protocols like TLS (Transport Layer Security) to protect data privacy, traditional security monitoring techniques have become less effective. This research sits at the intersection of network traffic analysis, TLS fingerprinting (extracting metadata from encryption handshakes), and Machine Learning. By applying machine learning to network traffic metadata rather than payload contents, this domain seeks to identify malicious or suspicious network behaviors while respecting the privacy constraints of encrypted communications.

## 2. Background

Historically, network security heavily relied on Deep Packet Inspection (DPI) to look inside network packets and identify malware signatures or malicious commands. However, when normal network traffic becomes encrypted (e.g., using TLS 1.3), the payload—the actual content of the communication—is scrambled and unreadable to any intermediate observer.

This creates a significant problem for network defenders. Because the payload cannot be inspected without breaking encryption (which is computationally expensive, often impossible without the keys, and creates privacy issues), traditional payload-based detection becomes largely ineffective against modern threats that communicate over HTTPS or other encrypted channels.

Despite the payload being hidden, valuable information remains visible. During the initial connection setup (the TLS handshake), clients and servers must exchange unencrypted messages to agree on how to secure the connection. Furthermore, the overall flow of the connection—such as how many bytes are sent, how long the connection lasts, and the timing between packets—is observable. This traffic metadata can still provide rich, behavioral clues about the nature of the software generating the traffic, allowing defenders to analyze patterns without needing to see the underlying data.

## 3. Problem Statement

The core problem for ETTH is how to reliably detect suspicious or potentially malicious encrypted network connections without decrypting their underlying payloads. 

Specifically, this research investigates how to effectively combine unencrypted TLS handshake metadata (using JA4 fingerprinting) with flow-based network statistics (such as packet sizes and timing) to classify network behaviors. Using supervised machine learning, the system aims to evaluate these combined features to generate a probabilistic risk or suspicion signal. This output must be treated as an indicator of anomalous or threat-like behavior rather than a definitive, guaranteed malware verdict, providing security analysts with an explainable starting point for investigation.

## 4. Research Motivation

The motivation for this research stems from the rapid and widespread adoption of encrypted communication protocols across the internet, which, while beneficial for privacy, provides a dark space for threat actors to hide command-and-control (C2) communication and data exfiltration. 

Because payload-based inspection is increasingly limited by modern encryption, and decrypting traffic at scale introduces significant privacy concerns, legal hurdles, and performance bottlenecks, there is a pressing need for metadata-based analysis techniques. Analyzing traffic metadata allows defenders to maintain visibility into network health and security without compromising the privacy of the communication contents. Furthermore, as machine learning models are adopted for this purpose, there is a critical need for these tools to be explainable—analysts must understand *why* a connection was flagged as suspicious, rather than relying on a "black box" system.

## 5. Existing Approaches

Several approaches currently exist for analyzing encrypted network traffic, each with distinct advantages and limitations.

### 5.1 Payload-based inspection
Traditionally, security appliances used Deep Packet Inspection (DPI) to match the contents of network packets against known databases of malware signatures. While highly accurate when it works, this approach is fundamentally limited by encryption. If the payload is encrypted, the DPI engine simply sees random noise, rendering signature matching useless unless the organization intercepts and decrypts the traffic (TLS inspection), which breaks end-to-end security and is resource-intensive.

### 5.2 Statistical traffic analysis
This approach completely ignores the payload and instead looks at the shape and behavior of the network connection (the "flow"). It relies on statistical features such as total packet counts, the distribution of packet sizes, connection duration, the ratio of bytes sent versus received, and the timing (inter-arrival time) of packets. While this method respects privacy and works regardless of encryption, it can struggle to differentiate between complex applications that have similar traffic shapes.

### 5.3 TLS fingerprinting
TLS fingerprinting involves analyzing the unencrypted setup messages of a TLS connection, specifically the Client Hello packet sent by the client. Different client applications (e.g., Chrome, Firefox, a Python script, or a specific malware strain) use different cryptographic libraries and configure their TLS settings differently. By recording the specific ciphers, extensions, and versions a client offers, analysts can create a "fingerprint" that identifies the software generating the traffic, even if the subsequent data is encrypted.

### 5.4 JA3
JA3, developed by Salesforce researchers, was the first widely adopted standard for TLS fingerprinting. It works by taking specific fields from the TLS Client Hello (version, accepted ciphers, extensions, elliptic curves, and formats) and hashing them into a single MD5 string. While revolutionary for identifying malicious scripts and C2 tools, JA3 has limitations. It is brittle; a minor change in the order of extensions or ciphers completely changes the resulting hash, making it difficult to group similar clients, and it suffers from frequent "fingerprint drift" as modern browsers update.

### 5.5 JA4
JA4, created by FoxIO, is the modern successor to JA3 designed to address its brittleness. Instead of a single opaque hash, JA4 examines the TLS Client Hello and creates a segmented, human-readable fingerprint in an `a_b_c` format. 
* Part `a` contains observable metadata (protocol, version, SNI presence, and counts of ciphers/extensions).
* Part `b` is a hash of the *sorted* cipher suites.
* Part `c` is a hash of the *sorted* extensions.

Because JA4 sorts the extensions and ciphers before hashing, the ordering matters less, making it highly resilient to randomization techniques used by modern browsers. JA4 can tell us the general class of application and securely identify specific TLS configurations, but because many legitimate applications (and some malware) share underlying libraries like OpenSSL, a JA4 fingerprint alone cannot definitively prove a connection is malicious.

## 6. Machine Learning for Encrypted Traffic

Machine learning (ML) provides a method for classifying network connections by finding complex patterns within metadata features, rather than relying on static rules or payload signatures. 

In this context, the **features** are the measurable data points extracted from the traffic—such as the JA4 fingerprint parts, connection duration, and byte ratios. The **labels** are the ground-truth classifications applied during training (e.g., "normal" vs. "suspicious"). By feeding a **training dataset** of known traffic into an algorithm, the model learns the mathematical boundaries that separate different classes.

When deployed, the model performs **classification** on unseen traffic, outputting a **prediction probability** (e.g., an 85% chance this connection is suspicious). Because ML is probabilistic, it is subject to **false positives** (flagging benign traffic as malicious) and **false negatives** (missing actual malicious traffic). 

Simple, interpretable models such as Logistic Regression and Random Forest are appropriate starting points for this research. They are computationally efficient, less prone to overfitting on small datasets than deep learning, and critically, they allow researchers to extract feature importance, explaining which specific metadata attributes contributed most to a classification decision.

## 7. Research Gap

While TLS fingerprinting and flow-based statistical analysis are established concepts, significant challenges remain in the operational use of these technologies.

A primary research gap is the high rate of **false positives** caused by **shared TLS fingerprints**. Because malware often uses the same underlying cryptographic libraries (e.g., standard Python `requests` or Go's `crypto/tls`) as legitimate administrative scripts, a JA3 or JA4 fingerprint alone is frequently insufficient for classification.

Furthermore, many existing ML approaches for encrypted traffic suffer from **limited generalization** and heavy **dataset dependency**. Models trained on specific network captures often experience **concept drift**—their performance degrades when deployed in different environments or as normal network behavior changes over time. Finally, there is a persistent difficulty in explaining model decisions; complex models often flag traffic as malicious without providing actionable context to the analyst. This research addresses the gap by evaluating the specific incremental value of combining robust JA4 metadata with flow statistics to improve explainability and reduce false positives compared to using either approach in isolation.

## 8. Proposed Research Direction

The ETTH project intends to investigate the efficacy of a hybrid classification approach. The proposed system will combine TLS/JA4 metadata with flow-level behavioral features, using supervised machine learning to generate an explainable threat score.

The research will systematically investigate whether combining modern TLS fingerprint information (JA4) with traditional flow-level statistical features provides a more robust and useful signal for identifying suspicious encrypted connections than using flow statistics alone. By training baseline models on these combined feature sets, the project will evaluate if the fusion of initial handshake configuration and ongoing connection behavior can effectively mitigate the limitations of shared fingerprints.

## 9. Research Questions

To guide the investigation, this project will address the following measurable research questions:

1. How effectively can encrypted network connections be classified as suspicious or benign using metadata features without inspecting payload contents?
2. Does combining JA4 TLS fingerprint metadata with flow-level statistical features improve classification performance (measured by F1 score and ROC-AUC) compared to using flow-level statistics alone?
3. Which specific network features (flow-based vs. fingerprint-based) contribute the most weight to the model's classification of suspicious traffic?
4. What is the false-positive rate of the combined feature model under simulated, realistic traffic conditions?
5. How does the model generalize when tested on an encrypted traffic dataset collected from a different network environment than its training data?

## 10. Research Objectives

The project aims to achieve the following measurable objectives:

1. Build a reproducible, offline data processing pipeline capable of parsing PCAP files and extracting encrypted traffic metadata.
2. Implement feature extraction for both standard flow-level statistics (duration, packet counts, byte ratios) and TLS handshake data.
3. Integrate the generation of JA4 fingerprints for all observed TLS Client Hello packets.
4. Train baseline supervised machine learning models (e.g., Random Forest, Logistic Regression) on the extracted feature sets.
5. Systematically compare the classification performance of models trained on flow features alone versus models trained on combined flow and JA4 features.
6. Evaluate the models using standard metrics including precision, recall, F1-score, ROC-AUC, and the false-positive rate.

## 11. Research Hypothesis

**H1 (Alternative Hypothesis):** Combining JA4 TLS fingerprint features with flow-level behavioral features improves the classification performance (measured by F1-score and ROC-AUC) of suspicious encrypted network connections compared with using flow-level features alone.

**H0 (Null Hypothesis):** Combining JA4 TLS fingerprint features with flow-level behavioral features yields no significant improvement in the classification performance of suspicious encrypted network connections compared with using flow-level features alone.

## 12. Scope

To ensure the research remains focused and achievable, the bounds of the project are explicitly defined.

**IN SCOPE:**
* Analysis of TLS-encrypted network traffic.
* Offline, PCAP-based traffic analysis.
* Extraction and utilization of JA4 fingerprints.
* Extraction of flow-level network metadata (statistics and timing).
* Application of supervised machine learning for classification.
* Generation of explainable threat/risk scoring.
* Offline model evaluation and metric reporting.

**OUT OF SCOPE:**
* Decrypting TLS payloads or attempting to break encryption.
* Developing enterprise-scale, real-time traffic monitoring systems.
* Autonomous blocking or active network intervention (Intrusion Prevention).
* Providing guaranteed, definitive malware detection.
* Building a full production SIEM (Security Information and Event Management) replacement.
* Live, internet-wide traffic monitoring.

## 13. Important Technical Limitations

Several technical limitations must be acknowledged when interpreting the results of this research.

The adoption of Encrypted Client Hello (ECH) in modern TLS 1.3 deployments will increasingly obscure the Server Name Indication (SNI), reducing the metadata available to JA4 and flow analyzers. Furthermore, because benign and malicious applications often use the same network libraries, the challenge of shared JA4 fingerprints will persist, fundamentally limiting the precision of fingerprint-based rules. 

From a machine learning perspective, the models will be susceptible to dataset bias; if the training data does not accurately represent the diversity of real-world traffic, the model will suffer from poor generalization. The network environment is highly dynamic, meaning concept drift is inevitable as applications update their TLS behaviors (e.g., changing browser fingerprints), requiring models to be frequently retrained. Finally, network traffic inherently suffers from class imbalance (malicious traffic is rare compared to benign traffic), making false positives a persistent operational challenge that must be carefully managed.

## 14. Preliminary Research Pipeline

The planned methodology follows a structured, offline pipeline:

1. **PCAP Collection:** Obtain labeled packet capture (PCAP) files containing both benign and malicious encrypted traffic.
2. **Network/TLS Extraction:** Parse the PCAPs to identify network flows and isolate TLS handshakes.
3. **JA4 Generation:** Process the TLS Client Hello packets to generate JA4 fingerprints.
4. **Flow Feature Extraction:** Calculate statistical and timing features for each identified network connection.
5. **Dataset Creation:** Merge the JA4 metadata, flow features, and ground-truth labels into a structured dataset for machine learning.
6. **ML Modeling:** Train baseline classification models on the prepared dataset.
7. **Evaluation:** Assess model performance using holdout datasets and standard classification metrics.
8. **Explainability:** Extract feature importance to understand model decision-making.
9. **Threat Scoring:** Output a probabilistic risk score for evaluated connections.

*(Note: This pipeline represents the conceptual design; no implementation has been executed at this stage.)*

## 15. References

1. Alomar, K., & Al-Qurishi, M. (2020). "Deep Learning for Encrypted Traffic Classification: A Comprehensive Review." *IEEE Access*. DOI: 10.1109/ACCESS.2020.3031021.
2. Anderson, B., & McGrew, D. (2017). "Machine Learning for Encrypted Malware Traffic Classification: Accounting for Noisy Labels and Non-Stationarity." *Proceedings of the 23rd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining*. DOI: 10.1145/3097983.3098163.
3. FoxIO. (2023). "JA4+ Network Fingerprinting." Official GitHub Repository. URL: https://github.com/FoxIO-LLC/ja4.
4. Salesforce Engineering. (2017). "JA3: A new way to profile SSL/TLS Clients." URL: https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-24736285e3ee.
5. Zeek Project. (2024). "Zeek Network Security Monitor Documentation." URL: https://docs.zeek.org/
6. Zheng, W., et al. (2020). "An Efficient Encrypted Traffic Classification Method Based on Flow Features." *IEEE Internet of Things Journal*. DOI: 10.1109/JIOT.2020.2995393.
