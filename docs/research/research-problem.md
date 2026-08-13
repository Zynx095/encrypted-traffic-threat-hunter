# Research Problem

## Background

Network traffic is increasingly encrypted by default. TLS 1.3 and QUIC now dominate web and application traffic, rendering deep packet inspection (DPI) of payload contents infeasible for most network operators. However, even when payloads are encrypted, metadata remains observable: flow-level statistics (packet sizes, inter-arrival times, byte ratios), TLS handshake parameters (cipher suites, extensions, TLS version), and connection behaviors (session patterns, duration, direction) all survive encryption and carry discriminative signal.

TLS fingerprinting extracts identifiers from the ClientHello and ServerHello packets. JA3, introduced in 2017, hashes five ClientHello fields into an MD5 fingerprint; JA3S does the same for the server side. JA4, introduced in 2023, improves on JA3 by sorting cipher and extension lists before hashing, stripping GREASE values, using truncated SHA-256, and producing human-readable output. Flow-level behavioral analysis examines packet-size distributions, inter-arrival times, and multi-session temporal patterns to detect anomalies such as C2 beaconing.

The Encrypted Traffic Threat Hunter (ETTH) project investigates whether these two signal families—TLS fingerprinting and flow-level behavioral metadata—can be combined into a unified, explainable scoring framework that helps security analysts prioritize suspicious encrypted connections for investigation.

## Existing Research

The literature establishes several relevant findings:

- **Metadata-only analysis is feasible.** Multiple peer-reviewed papers confirm that flow statistics, packet-size distributions, IATs, and TLS handshake metadata carry sufficient signal for classification without payload decryption [akbari2022traffic, oh2021survey, papadogiannaki2021survey, barut2020tls, garcia2018efficient].

- **Malware TLS behavior differs from benign traffic.** Anderson & McGrew (2017) demonstrate that malware family attribution reaches 90.3% accuracy from a single encrypted flow using only observable TLS parameters, though sandbox bias must be accommodated.

- **JA3 is foundational but insufficient alone.** Multiple sources confirm collision rates, extension-ordering instability, and MD5 obsolescence [matousek2021reliability, matousek2025towards, anderson2020accurate]. Combined JA3+JA3S reduces false positives compared to JA3 alone [althouse2019ja3s].

- **JA4 introduces design improvements but lacks independent validation.** JA4 sorts cipher/extension lists, strips GREASE, uses truncated SHA-256, and supports QUIC/DTLS [althouse2023ja4]. Only one peer-reviewed comparative study directly compares JA3 and JA4 [matousek2025towards].

- **Flow-level behavioral features detect encrypted C2.** Packet-size statistics, IAT patterns, coefficient of variation (CV) of intervals, and multi-flow temporal features achieve >90% accuracy in beaconing detection [zhang2025beacon, ramos2023cobalt, martinramos2022cobalt, garcia2018efficient].

- **Tree-based models dominate flow-feature classification.** Random Forest and XGBoost are the most commonly used models for tabular flow features, while deep learning suffers from evaluation flaws (SNI leakage, per-packet splits, legacy datasets) [wickramasinghe2025sok, zhao2025sugar].

- **Explainability methods exist but are not yet applied to hybrid fingerprint-behavior models.** SHAP and LIME are used for flow-feature-based IDS, but no source addresses explainability for decisions combining JA4/JA3 hashes with behavioral metadata [grabowski2025explainable, singh2025interpretable].

- **ECH encrypts SNI and ALPN, threatening traditional visibility.** RFC 9849 defines the standard; Cisco documents operational impact [rfc9849, cisco2025ech]. The effect on JA4 fingerprint quality is not quantified.

## Identified Gap

The literature leaves a specific gap at the intersection of three research threads:

**What has already been studied:**
- TLS fingerprinting (JA3/JA4) for application identification and malware detection, evaluated largely in isolation from flow-level behavioral features.
- Flow-level behavioral features (packet-size distributions, IATs, beaconing scores) for encrypted C2 detection, evaluated without TLS fingerprinting.
- Explainability methods (SHAP, LIME) for flow-feature-based IDS.

**What has been studied separately but not combined:**
- No published study in the current corpus explicitly combines JA4/JA3S fingerprints with flow-level behavioral features (packet-size distributions, IAT patterns, multi-flow temporal statistics) in a unified detection or scoring framework.
- No study evaluates explainability for a hybrid system that must justify both fingerprint matches and behavioral anomalies to security analysts.

**What remains insufficiently studied:**
- Whether the combination of JA4/JA3S fingerprints and flow-level behavioral features provides measurable detection improvement over either feature family alone.
- Whether such a combined system can be made explainable in a way that is useful for security analysts.
- How JA4 performs under ECH conditions where SNI is encrypted, and whether behavioral features can compensate for reduced fingerprint visibility.

## Proposed Research Direction

ETTH proposes to experimentally investigate a unified encrypted-traffic scoring framework that combines:

1. **TLS fingerprint features** (JA4 client fingerprints, JA4S server fingerprints, and JA3 for baseline comparison where applicable), and
2. **Encrypted-flow behavioral features** (packet-size distributions, inter-arrival times, byte ratios, multi-flow temporal patterns, beaconing heuristics),

under a single machine learning classifier with explainability via SHAP.

The research does not assume that this combination will succeed. Instead, it is designed to measure whether the combination provides statistically significant improvement in detection performance, false-positive behavior, and analyst explainability compared to using either feature family in isolation.

The investigation will be conducted on public encrypted-traffic datasets, using rigorous evaluation methodology (per-flow splits, SNI masking, frozen-encoder checks where applicable) to avoid the overfitting pitfalls documented by Wickramasinghe et al. (2025) and Zhao et al. (2025).
