# Citation

Chuanpu Fu, Qi Li, and Ke Xu. 2024. "Flow Interaction Graph Analysis: Unknown Encrypted Malicious Traffic Detection." *IEEE/ACM Transactions on Networking*. https://doi.org/10.1109/TNET.2024.3370851

## Research Problem

Existing encrypted malicious traffic detection methods are supervised and rely on prior knowledge of known attacks (labeled datasets). They cannot detect unknown encrypted malicious traffic with novel patterns. The problem is to detect unknown encrypted attacks without requiring any labeled datasets of known attacks.

## Objective

To propose HyperVision, a real-time unsupervised machine learning system that detects unknown encrypted malicious traffic by analyzing flow interaction patterns using a compact in-memory graph, without requiring prior knowledge of attack signatures.

## Methodology

- Constructed compact in-memory graph of flow interaction patterns from network flows.
- Classified flows into short and long flows; aggregated similar short flows into edges.
- Fitted distributions of packet features in long flows to construct high-fidelity edges.
- Developed unsupervised graph learning method to detect abnormal interaction patterns by analyzing graph structural features (connectivity, sparsity, statistical features).
- Used lightweight K-Means clustering for edge feature clustering.
- Established information theory model to prove effectiveness.

## Dataset / Data

- 92 real-world datasets including 48 encrypted attacks.
- Traffic from multiple attack types and network environments.

## Features

- Flow interaction patterns (graph edges between IP addresses).
- Short flow aggregation features.
- Long flow packet feature distributions.
- Graph structural features: connectivity, sparsity, statistical features.
- Per-packet feature sequences for short flows.
- Fitted feature distributions for long flows.

## Models / Algorithms

- Unsupervised graph learning.
- K-Means clustering for edge feature clustering.
- Information theory model for performance bound analysis.

## Evaluation Metrics

- AUC (Area Under ROC Curve): ≥ 0.92.
- F1 score: ≥ 0.86.
- Detection throughput: ≥ 80.6 Gb/s.
- Detection latency: average 0.83s.
- Accuracy improvement over state-of-the-art: 13.9%.

## Results

- HyperVision detects unknown encrypted malicious traffic without labeled attack datasets.
- Achieves at least 0.92 AUC and 0.86 F1 across 92 datasets with 48 attacks.
- More than 50% of attacks in experiments can evade all supervised baseline methods.
- Outperforms state-of-the-art by 13.9% accuracy improvement.
- Achieves 15.82 Mpps detection throughput with 0.29s average latency (cited in abstract; 80.6 Gb/s / 0.83s in body).
- Flow interaction patterns are distinct from benign patterns even when individual flows appear similar.

## Limitations

- Requires real-time graph construction and maintenance.
- Evaluation limited to specific attack types; unknown how well it generalizes to all attack categories.
- Graph density reduction may lose fine-grained interaction information.
- Computational overhead of graph construction for very large networks not fully quantified.
- Does not explicitly incorporate TLS-specific features (e.g., JA4 fingerprints) into the graph.

## Relevance to ETTH

**Very High.** HyperVision demonstrates that flow interaction patterns—not individual flow features—can reveal encrypted malicious traffic. This supports ETTH's focus on flow-level behavioral metadata. The unsupervised detection paradigm is particularly relevant because ETTH aims to identify suspicious connections that deserve investigation, which may include unknown or novel attack patterns. The graph-based approach could be extended to incorporate JA4 fingerprints as additional node/edge attributes.

## Evidence We Can Use

1. **Flow interaction patterns:** Malicious flows exhibit distinct interaction patterns (e.g., spam bots to SMTP servers) even when individual flows resemble benign traffic.
2. **Unsupervised detection:** Graph-based unsupervised learning can detect unknown attacks without labeled data.
3. **Graph construction:** Short flows aggregated into edges; long flows fitted with distributions; compact in-memory representation enables real-time operation.
4. **Performance bounds:** Information theory model proves the graph approaches ideal theoretical detection bounds.
5. **Baseline comparison:** Supervised methods fail to detect >50% of attacks in the evaluation, highlighting the need for unsupervised approaches.

## Questions Raised

1. Can HyperVision's graph construction be extended to include TLS handshake features (JA4, cipher suites) as edge/node attributes?
2. How does the system perform under concept drift as attack patterns evolve over time?
3. What is the memory and computational overhead of maintaining the interaction graph in a high-speed enterprise network?
4. Can the graph-based approach be combined with explainable ML techniques to provide threat scores for analysts?
