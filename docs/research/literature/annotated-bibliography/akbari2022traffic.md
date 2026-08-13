# Citation

Iman Akbari, Mohammad A. Salahuddin, Leni Aniva, Noura Limam, Raouf Boutaba, Bertrand Mathieu, Stephanie Moteau, and Stephane Tuffin. 2022. "Traffic Classification in an Increasingly Encrypted Web." *Communications of the ACM* 65, 10 (2022), 98–106. https://doi.org/10.1145/3559439

## Research Problem

Deep learning models for encrypted traffic classification often treat encrypted traffic as generic raw input, ignoring domain-specific considerations. Many models implement simple logic based on TLS handshake header fields (canary features like SNI and cipher info), limiting their robustness to future protocol versions. The problem is to design protocol-agnostic features and architectures that generalize across encrypted Web protocols.

## Objective

To propose a novel feature engineering approach for encrypted traffic classification focusing on protocol-agnostic aspects, and to develop a DL architecture based on CNN and stacked LSTM that generalizes across service- and application-level classification objectives and across encrypted Web protocols (HTTP/2, QUIC).

## Methodology

- Extracted flows using YAF (5-tuple: src/dst IP/port, protocol).
- Filtered TLS flows; extracted basic flow information and statistical features using CICFlowMeter.
- Constructed time series of packet sizes, directions, and inter-arrival times (IATs).
- Vectorized raw traffic bytes from up to three handshake packets (masked IPs, removed cipher info, masked SNI, truncated/zero-padded).
- Trained DL model combining:
  - Stacked LSTM layers for flow time-series features (packet sizes, directions, IATs).
  - CNN layers as alternative to LSTM.
  - Fully connected network for flow statistics.
- Evaluated on real-world ISP mobile traffic dataset and public QUIC dataset.

## Dataset / Data

- Real-world mobile traffic dataset from major ISP and mobile network operator (service-level classification: 8 classes).
- Public QUIC dataset (application-level classification: finer granularity).
- Traffic masked to remove IP addresses, cipher information, and SNI records to prevent canary feature reliance.

## Features

- **Flow statistics:** mean, std dev, min, max, median of packet sizes, IATs, TCP flag counts, flow duration, packet count, byte count (from CICFlowMeter).
- **Flow time series:** packet sizes, directions (±1), IATs (max length 1024).
- **Raw handshake bytes:** up to three TLS handshake packets (ClientHello, ServerHello, etc.).
- **Masked/removed fields:** IP addresses zeroed, cipher info removed, SNI masked.

## Models / Algorithms

- Stacked LSTM (3 layers, bidirectional) for flow time-series features.
- 1D CNN for flow time-series features (alternative architecture).
- Fully connected (dense) network for flow statistics.
- Combined multi-input DL architecture.

## Evaluation Metrics

- Accuracy.
- False classification rate (compared to state-of-the-art).

## Results

- Achieved >95% accuracy for service-level classification on ISP mobile traffic dataset.
- Outperformed state-of-the-art (Rezaei et al.) by nearly 50% fewer false classifications.
- Achieved 99% accuracy on public QUIC dataset with finer application-level granularity.
- Model generalizes across classification objectives (service-level vs. application-level) and protocols (HTTP/2 vs. QUIC) by simply changing training data.
- Raw traffic apart from TLS handshake does not contribute to performance and adds complexity/overfitting.
- CNN variant requires lower training time while achieving higher accuracy than state-of-the-art.

## Limitations

- Evaluation on real-world ISP dataset not publicly available, limiting reproducibility.
- QUIC evaluation uses public dataset with different class composition than ISP dataset.
- May still overfit to session-specific artifacts if not carefully masked.
- Requires distributed preprocessing (Apache Spark) for large datasets.

## Relevance to ETTH

**Very High.** This paper directly supports ETTH's metadata-only approach. The feature set (flow statistics + traffic shape + handshake bytes) is highly aligned with ETTH's planned methodology. The finding that non-handshake traffic is redundant and the emphasis on protocol-agnostic features provide strong justification for ETTH's design choices. The masking of SNI and cipher info also aligns with ETTH's need to avoid canary feature reliance.

## Evidence We Can Use

1. **Feature set validation:** Flow statistics + packet size/IAT/direction time series + handshake bytes is an effective protocol-agnostic feature set.
2. **Redundancy elimination:** Non-handshake packets do not improve classification and increase overfitting risk.
3. **Generalization:** Same architecture adapts to HTTP/2 and QUIC by changing only training data.
4. **Preprocessing pipeline:** YAF for flow extraction, CICFlowMeter for flow statistics, session grouping by TLS session ID.
5. **Masking strategy:** Zero IPs, remove cipher info, mask SNI, truncate/pad to MTU.

## Questions Raised

1. How does the ISP-grade feature set perform when applied to datasets with TLS 1.3 and ECH?
2. Can the LSTM/CNN architecture be replaced with simpler tree-based models (RF, XGBoost) without significant accuracy loss?
3. How does the model perform under data drift when deployed in a different network environment?
4. What is the minimal number of handshake packets required for effective classification?
