# Citation

Nimesha Wickramasinghe, Arash Shaghaghi, Gene Tsudik, and Sanjay Jha. 2025. "SoK: Decoding the Enigma of Encrypted Network Traffic Classifiers." *IEEE Symposium on Security and Privacy (S&P)*. https://doi.org/10.1109/SP61157.2025.00165

## Research Problem

Machine learning-based network traffic classification (NTC) has produced many proposed classifiers, but their design choices, benchmarking suites, and underlying assumptions are often poorly justified. The problem is to systematize ML-based NTC studies, identify common pitfalls, and empirically validate whether state-of-the-art classifiers actually work on modern encrypted traffic.

## Objective

To comprehensively analyze ML-based NTC studies, develop a taxonomy of design choices, reveal widespread reliance on outdated datasets and unsubstantiated assumptions, and provide strategic insights for building real-world applicable NTC methodologies.

## Methodology

- Systematic literature survey across JSTOR, SCOPUS, EBSCO, and Google Scholar (2015 onward).
- Developed taxonomy of NTC design choices: traffic granularity, data extraction strategy, raw features, Strong Identification Information (SII).
- Evaluated 19 public datasets across VPN, malware, and encrypted application classification tasks.
- Conducted 348 feature occlusion experiments on state-of-the-art classifiers (ET-BERT, YaTC).
- Introduced CipherSpectrum, a new contemporary dataset with TLS 1.3 AEAD ciphers.

## Dataset / Data

- 19 public datasets (ISCXVPN2016, USTC-TFC2016, CSE-CIC-IDS2018, CIC-Darknet2020, etc.).
- New CipherSpectrum dataset with modern TLS 1.3 cipher suites.
- Evaluation focused on 10 classes per dataset for occlusion experiments.

## Features

- Raw packet bytes (per-packet and per-flow splits).
- TLS handshake fields (SNI, cipher info, extensions).
- Flow features (SPLT, BD).
- Strong Identification Information (SII): IP addresses, TCP sequence numbers, timestamps.

## Models / Algorithms

- ET-BERT (pre-trained transformer for traffic classification).
- YaTC (lightweight CNN-based classifier).
- Various SOTA classifiers referenced in taxonomy.

## Results

- Majority of proposed encrypted traffic classifiers have mistakenly used unencrypted traffic due to legacy datasets.
- 348 occlusion experiments reveal three types of overfitting: data leakage overfitting (SII), contextual overfitting, temporal overfitting.
- SNI data leakage causes significant accuracy inflation; masking SNI drops performance substantially.
- Per-packet split enables flow-ID shortcuts; models learn implicit flow IDs rather than traffic patterns.
- Frozen encoder evaluation shows representation learning models (ET-BERT, etc.) produce non-informative representations; performance drops below 30% when encoder is frozen.
- TLS 1.3 datasets often contain deprecated cipher suites (3DES, RC4) or unencrypted traffic.

## Limitations

- Scope limited to raw-information-based NTC (excludes side-channel and multimodal methods).
- CipherSpectrum focuses on cipher-agnostic classification; may not cover all application-level tasks.
- Some findings may not apply to flow-feature-based methods (e.g., CICFlowMeter features).
- Evaluation limited to specific model architectures and datasets.

## Relevance to ETTH

**Very High.** This SoK directly identifies the methodological pitfalls that ETTH must avoid. The findings on SNI leakage, per-packet split data leakage, and frozen encoder evaluation are immediately applicable to ETTH's experimental design. The revelation that many published classifiers fail on modern encrypted traffic underscores the importance of rigorous evaluation for ETTH's proposed methodology.

## Evidence We Can Use

1. **Dataset selection:** Avoid pre-2018 datasets containing unencrypted traffic or deprecated cipher suites.
2. **Feature selection:** Mask SNI and other SII during training to prevent data leakage overfitting.
3. **Data splitting:** Use per-flow splits, not per-packet splits, to prevent flow-ID shortcut learning.
4. **Representation learning:** If using pre-trained models, evaluate with frozen encoders to verify representation quality.
5. **Evaluation rigor:** 348 occlusion experiments provide a template for systematic feature importance validation.

## Questions Raised

1. How can ETTH ensure its own dataset and evaluation methodology avoid the pitfalls identified in this SoK?
2. Do JA4 fingerprints constitute SII that could enable shortcut learning?
3. How should ETTH balance feature utility (e.g., SNI for labeling) against overfitting risk?
4. What is the minimal set of features that provides robust classification without relying on environmental shortcuts?
