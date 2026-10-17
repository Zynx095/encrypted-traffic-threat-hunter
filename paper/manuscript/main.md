# Do TLS Fingerprints Add Value to Encrypted-Flow Features? A Source-Aware Exploratory Evaluation Without Decryption

**Authors:** ETTH project (author list to be finalised)
**Status:** WORKING DRAFT. Not submitted and **not publication-ready**.
- All empirical results are **exploratory** and **source-confounded**: every dataset contributes a single class.
- No confirmatory evaluation has been run. It is blocked on independent benign data.
- Every number below comes from persisted artefacts and has been re-verified with `python -m ml verify`: 124/124 experiment records reproduce from their stored out-of-fold predictions. The evidence ledger is `docs/research/RESEARCH_CLAIM_LEDGER.md`.

**Reconciliation note (integration of Phases 8–12).** An earlier Phase 12 draft of this manuscript was written against the Phase 7 pilot (2,543 malicious vs 6 benign flows). Its results, the claimed feature-importance narrative, the "15-second idle timeout", the "80 features", the "mutually exclusive tracks" and several references were incorrect or unsupported. This version replaces them with the executed Phase 8–10 results. The superseded draft is preserved in Git history (branch `research/phase-12-paper-manuscript`).

---

## Abstract

TLS encrypts application payloads, but passive observers can still see the cleartext handshake (summarised as JA3/JA4 client fingerprints) and the size and timing of encrypted packets.

**Question.** We ask whether combining fingerprints with encrypted-flow behavioural features improves malicious-traffic detection over either feature family alone, without decrypting payloads.

**Setup.**
- Five feature tracks (A: flow; B: JA3; C: JA4; D: JA3+flow; E: JA4+flow).
- A corpus of 577,238 flows from 25 public packet captures: 19 malicious captures from two sources, and 6 benign captures from one source.
- Leakage-audited protocol: capture-grouped nested cross-validation, allow-list feature governance, validation-only calibration and thresholds, capture-level bootstrap and Holm-corrected paired contrasts.

**Results.**
- On the shared TLS population, flow-only and fusion models are both near ceiling. The pre-declared primary model shows no evidence that adding JA3 or JA4 to flow features increases average precision (AP).
- Fingerprint-only models separate the sources rather than maliciousness. Under capture-grouped evaluation they flag about 98% of benign flows whose client stack was not seen in training (18.4–18.6% test FPR at a validation-selected 1% FPR threshold). A held-out malicious source is detected at 0% or 100%.
- JA4 identifies the collection source perfectly (AP 1.000).
- Flow-only AP falls from 0.931 to 0.710 when whole malware families are held out.
- Handshake-presence flags alone reach AP 0.765 against a prevalence floor of 0.600.
- The commonly used behavioural-hash holdout reports near-perfect scores (AP 1.000 for all fingerprint tracks), which hide these effects.
- First-64-packet CNN and GRU models do not outperform information-matched tabular baselines.

**Conclusion.** In this corpus, apparent fingerprint value is client-stack memorisation. The central question remains open until benign data from independent environments is available. We release the leakage-audited benchmark harness, the evidence ledger, and a sensor-agnostic flow contract that refuses semantically incompatible inputs.

## 1. Keywords

Encrypted traffic analysis; TLS fingerprinting; JA3; JA4; flow features; dataset shift; source confounding; evaluation methodology; negative results.

## 2. Introduction

Encrypted transport removes payload content from network monitoring. Two kinds of observable metadata remain:
- **The cleartext TLS handshake.** In particular the ClientHello, which JA3 [3] and JA4 [4] condense into client fingerprints.
- **Encrypted-flow behaviour.** Packet sizes, directions, timing and volume, which earlier work combined with TLS metadata for malware detection [1, 2].

Fusing the two families is intuitive. Prior work, however, warns that learning-based security evaluations are often inflated by sampling bias and spurious correlations [6, 7]. Fingerprints are especially exposed to this: they identify the client software stack, and in public datasets the client stack is frequently a property of the collection environment rather than of maliciousness.

This draft reports an exploratory evaluation designed to make that confound visible rather than hide it. It distinguishes engineering properties that were verified from empirical findings that remain exploratory.

## 3. Problem Definition

Let a flow be described by:
- flow behavioural features **F**: 74 statistics of counts, rates, packet lengths, inter-arrival times and bursts;
- TLS structural metadata **S**: ClientHello/ServerHello/SNI presence, offered TLS version, first offered ALPN;
- a fingerprint **J**: JA3 or JA4.

The question is whether adding J to (F, S) increases detection quality, and whether adding (F, S) to J does. The evaluation must hold under conditions that approximate deployment: unseen captures, unseen malware families and unseen sources. All of this must be done without decrypting payloads.

## 4. Research Questions and Hypotheses

- **RQ1 (fusion).** Does D or E outperform A on the same flows (JA3/JA4-available population)? Does D or E outperform B or C?
  - *H1:* fusion increases AP.
  - *Status:* **insufficient evidence** (§13.2).
- **RQ2 (generalisation).** Do the tracks transfer to held-out captures, families and sources?
  - *Status:* flow-only and fusion transfer to a held-out malicious source is **contradicted** (detection ≤ 35% at the validation threshold). Fingerprint-only transfer is **all-or-nothing** (§13.4).
- **RQ3 (confounding).** Do evaluation protocol and source identity explain the apparent performance?
  - *Status:* **preliminary support** (§15).
- **RQ4 (sequence models).** Do packet-sequence models add value over tabular baselines with the same information?
  - *Status:* **insufficient evidence**. The GRU is worse than the full-flow baseline in one contrast (§13.5).
- A comparison of JA4 against JA3 was proposed in the earlier draft. It was **not tested**: no pre-declared contrast exists, and the ETTH JA4 implementation is not FoxIO-conformant (§9).

## 5. Related Work

**TLS metadata for malware detection.**
- Anderson and McGrew combined unencrypted TLS handshake metadata, DNS and HTTP context with packet length and timing sequences [1].
- They later studied label noise and non-stationarity in encrypted malware classification, finding that feature representation mattered as much as the learning algorithm [2].

**Fingerprinting.**
- JA3 hashes ClientHello parameters (version, ciphers, extensions, curves, point formats) with MD5 [3].
- JA4 is a structured, partly sorted fingerprint (protocol, version, SNI, counts, ALPN, then truncated SHA-256 of sorted ciphers and of sorted extensions plus signature algorithms in wire order) [4, 5].
- Encrypted Client Hello (ECH) [8] removes SNI and other ClientHello fields from passive view.

**Evaluation pitfalls.**
- Sommer and Paxson describe why machine learning for intrusion detection differs from other domains [7].
- Arp et al. catalogue pitfalls including sampling bias, data snooping, spurious correlations and inappropriate baselines [6].
- Our design follows their recommendations: grouped splits, training-only preprocessing, explicit baselines and reporting of uncertainty.

**Systems.** Zeek [9] and Suricata [10] can log JA3/JA4 and flow records. We use them only as optional input formats (§7).

## 6. Threat Model and Scope

- **Adversary.** Malware communicating over TLS 1.2/1.3. It controls payloads, may use legitimate hosting, and may change its TLS library.
- **Defender.** Passive observation: packet capture, or logs from flow sensors. No keys, no interception, no endpoint certificates.
- **Out of scope:**
  - active MITM;
  - payload inspection;
  - non-TLS encrypted protocols;
  - QUIC (not reconstructed);
  - full-ECH traffic, where fingerprints degrade to the outer ClientHello.

## 7. System Architecture

ETTH comprises the following components.

1. **Corpus builder.** Checksum-verified PCAP ingestion and a dataset registry with capture-level provenance.
2. **Flow reconstruction.** Bidirectional 5-tuple flows with a 120 s idle timeout and FIN/RST termination.
   - Forward means the initiator, i.e. the first packet's source.
   - Lengths are IP lengths.
   - Only TCP and UDP are reconstructed.
3. **Feature extraction.** The 74 flow features plus TLS structural metadata. JA3 and ETTH-JA4 are computed from the ClientHello in the first TCP segment.
4. **Benchmark harness.** Allow-list governance, capture-grouped nested CV, calibration and threshold selection on validation captures only, bootstrap and Holm contrasts, and an append-only experiment registry (§11).
5. **Real-time path.**
   - A pickle-free, checksum-pinned model registry.
   - Schema-enforcing inference: incompatible flows are SKIPPED with a reason and never zero-filled.
   - Out-of-distribution and in-sample-replay flags.
   - A validated WebSocket event stream.
   - Live capture whose flows and features match the offline pipeline on identical synthetic packets (claim C20).
6. **Sensor adapters (engineering only).** Zeek, Suricata and eBPF-collector records are normalised into the same flow contract.
   - Their counters are tagged as sensor aggregates, and their JA4 as FoxIO.
   - Models trained on ETTH packet features refuse both (C18, C19).
   - The adapters are not connected to the live stream. No cross-sensor correlation and no eBPF program exist.
   - Detection on sensor telemetry is **blocked** (C21).

## 8. Datasets and Provenance

Corpus v3 has 577,238 flows from 25 captures. Every capture's SHA-256 and acquisition details are recorded (`data/corpus/`). Labels are **capture-level** and are propagated to flows.

| ID | Source | Class | Captures | Flows | ClientHello flows | Offered TLS version |
|---|---|---|---|---|---|---|
| DS-008 | Malware-Traffic-Analysis.net exercises [11] | malicious | 10 | 2,543 | 194 | 1.2 and 1.3 |
| DS-009 | Stratosphere Lab malware captures (MCFP) [12] | malicious | 9 | 447,563 | 66,612 | 1.2 only |
| DS-011 | Stratosphere Lab CTU-Normal captures [12, 13] | benign | 6 | 127,132 | 13,845 | 1.2 only |

Observations about this corpus:
- JA3 and JA4 values never occur in both classes: 0 of 90 JA3 and 0 of 82 JA4 values are shared (C03).
- The benign traffic is 2017 lab browsing. The READMEs of five of the six captures state Kali Linux with iceweasel 43, but the file names of three captures say "win"; the conflicts are recorded, not resolved. The malicious traffic comes from Windows hosts.
- Benign sufficiency for generalisation (level C) is **not met**: one benign source, no benign TLS 1.3, one benign environment (C02).
- The CipherSpectrum samples (DS-004, 6 flows) used in the Phase 7 pilot are not part of corpus v3. Further candidate datasets require registration, licence clarification or a provider request, and were not acquired.

## 9. Feature Extraction and TLS Fingerprinting

- **Flow features (74).**
  - 15 count, rate and ratio features.
  - 27 packet-length statistics: mean, median, std, min, max, p25, p75, p90, p95, for all, forward and reverse packets.
  - 27 inter-arrival statistics, with the same nine statistics and three directions.
  - 5 burst features with a 1.0 s idle threshold.
  - Features are undefined (NaN) where a direction has too few packets. They are imputed only with training-fold medians plus missing indicators.
- **TLS structural (5).**
  - `clienthello_present`, `serverhello_present`, `sni_present`.
  - `tls_version`, meaning *offered*: 1.3 if the ClientHello carries `supported_versions`, else 1.2.
  - `alpn_value`, the first offered ALPN.
- **JA3.** MD5 of `version,ciphers,extensions,curves,point_formats` with GREASE removed [3].
- **JA4 (ETTH implementation).** It deviates from the FoxIO specification [5] in six ways:
  - signature algorithms are sorted;
  - `n` is used instead of `i` for "no SNI";
  - the version code is derived from the presence of `supported_versions` only;
  - a trailing separator is hashed when there are no signature algorithms;
  - the empty cipher list is hashed instead of being written `000000000000`;
  - counts are not capped at 99.

  On the FoxIO reference ClientHello the ETTH value differs in the third component. Results labelled "JA4" in this draft therefore refer to the ETTH variant and are **not comparable to FoxIO JA4 in the literature**.
- **Limits of the parser.** Only the first TCP segment of the ClientHello is parsed. Fingerprints of segmented ClientHellos are flagged as possibly truncated: 13 such fingerprints in DS-008 and 1 in DS-009.

## 10. Experimental Design: Feature Tracks

The tracks are **not** mutually exclusive: D and E contain all of A's inputs.

| Track | Inputs | Population |
|---|---|---|
| A_FLOW | 74 flow + 5 TLS structural = 79 | all flows |
| B_JA3 | JA3 | JA3-available flows |
| C_JA4 | ETTH-JA4 | JA4-available flows |
| D_JA3_FLOW | A + JA3 = 80 | JA3-available flows |
| E_JA4_FLOW | A + JA4 = 80 | JA4-available flows |
| A@JA3POP / A@JA4POP | A's inputs | JA3/JA4 population (paired comparison with D/E) |
| A0_FLOW_STRICT | 74 flow features only | all flows (ablation) |
| P_AVAILABILITY_PROBE | 3 presence flags | all flows (shortcut probe) |

## 11. Leakage Prevention and Evaluation Protocol

1. **Feature governance.** A model can receive only allow-listed columns. Identifiers, endpoints, timestamps, capture, dataset and family annotations, raw SNI and labels are forbidden by name and by substring.
2. **Capture-balanced population.** At most 4,000 flows per capture, drawn deterministically, so that the largest captures do not dominate.
3. **Splits.** Outer capture-grouped stratified 5-fold CV, with inner capture-grouped folds for hyper-parameter selection on small pre-declared grids. Behavioural-duplicate groups that would cross train and test are purged from training.
4. **Training-only preprocessing.** Imputation, scaling and encoders are fitted on training folds. Platt calibration and the decision threshold for a 1% FPR are chosen on validation captures, never on test data.
5. **Additional protocols.**
   - leave-one-family-out;
   - leave-one-malicious-source-out;
   - a source-identifiability probe;
   - the legacy behavioural-hash `GroupShuffleSplit` holdout, kept only to quantify its optimism;
   - an encoding ablation;
   - a matched DS-009 vs DS-011 subset.
6. **Uncertainty.** A capture-level bootstrap with 1,000 replicates. With only 6 benign captures, every interval is flagged FEW_GROUPS and is probably too narrow.
7. **Contrasts.** Four pre-declared paired contrasts per suite and model, on identical rows, with Holm correction:
   - JA3 added to flow;
   - JA4 added to flow;
   - flow added to JA3;
   - flow added to JA4.

   The **primary model (random forest) was declared before any Phase 9 result**. Other models are sensitivity analyses.
8. **Status.** Every Phase 9/10 run is **exploratory**. The confirmatory policy (a frozen configuration evaluated once on a never-used source) could not be executed, because no independent source exists.

## 12. Baselines and Classifiers

Classifiers:
- a prevalence floor;
- L2 logistic regression (class-balanced);
- random forest (150 trees);
- histogram gradient boosting (100 iterations).

Phase 10 adds:
- masked 1-D CNN and GRU models on the first 64 packets (length, direction, timing, TCP flags; header metadata only), trained on CPU;
- information-matched tabular baselines on aggregates of the same 64 packets;
- full-flow tabular baselines, evaluated on identical folds.

No external state-of-the-art system was re-implemented.

## 13. Results (exploratory, source-confounded)

### 13.1 Capture-grouped CV (pooled population: 38,543 malicious / 24,000 benign flows)

| Track (random forest) | AP [95% capture-bootstrap CI] | Test FPR at val. 1% FPR | Recall at that threshold |
|---|---|---|---|
| A_FLOW | 0.931 [0.797, 0.986] | 5.8% | 49.5% |
| B_JA3 | 0.971 [0.868, 1.000] | 18.6% | 99.8% |
| C_JA4 | 0.994 [0.953, 1.000] | 18.4% | 99.4% |
| D_JA3_FLOW | 0.988 [0.931, 1.000] | 17.4% | 99.5% |
| E_JA4_FLOW | 0.991 [0.944, 1.000] | 12.1% | 99.6% |
| A_FLOW@JA3POP | 0.990 [0.946, 1.000] | 12.2% | 99.5% |
| A0_FLOW_STRICT | 0.929 [0.793, 0.984] | 6.1% | 42.5% |
| P_AVAILABILITY_PROBE | 0.765 [0.628, 0.897] | 0.1% | 24.2% |

All intervals are FEW_GROUPS. B–E and A@JA3POP use the JA3/JA4 population: 8,591 malicious and 2,629 benign flows.

### 13.2 Incremental value (RQ1)

**Primary model (random forest).**

| Contrast | ΔAP [CI] | Holm p |
|---|---|---|
| JA3 added to flow (A@JA3POP → D) | −0.002 [−0.015, 0.000] | 1.00 |
| JA4 added to flow (A@JA4POP → E) | +0.000 [−0.003, 0.001] | 1.00 |
| Flow added to JA3 (B → D) | +0.017 [−0.000, 0.072] | 0.52 |
| Flow added to JA4 (C → E) | −0.003 [−0.033, 0.014] | 1.00 |

There is **no evidence of a difference**. This is not evidence of equivalence: no equivalence margin was pre-registered. The matched DS-009 vs DS-011 suite gives ΔAP = 0.000, because every model scores ≈ 1.000.

**Sensitivity: logistic regression.**
- Adding JA3 or JA4 to flow gives ΔAP +0.0004 and +0.0005 on a baseline AP of 0.9994.
- Holm within the model: p = 0.032 and 0.042.
- Holm across all 12 model × contrast tests: p = 0.096 and 0.154.
- Gradient boosting does not reproduce the effect.

We read this as a statistically fragile, practically negligible difference at ceiling, on confounded data (claims C04–C07: INSUFFICIENT_EVIDENCE).

### 13.3 Protocol optimism (RQ3)

- **Legacy behavioural-hash holdout.**
  - A_FLOW AP 0.992, against 0.931 under capture-grouped CV.
  - Every fingerprint and fusion track reaches AP 1.000, with fingerprint-only FPR 0.4% at the validation threshold.
  - Claim C12.
- **Leave-one-family-out.** A_FLOW AP is 0.710 [0.456, 0.962] (C17).

### 13.4 Source effects (RQ2, RQ3)

**Unseen benign fingerprints (C16).**
- 18.8% of held-out benign TLS flows carry a fingerprint never seen in their training folds.
- At the validation threshold, fingerprint-only models flag 98.8% (JA3) and 98.2% (JA4) of those flows, and 0% of benign flows with seen fingerprints.
- This accounts for the ≈18% test FPR of B and C.

**Leave-one-malicious-source-out (C08), detection rate on the held-out source at the validation threshold:**

| Track | DS-008 held out | DS-009 held out |
|---|---|---|
| A | 3.8% | 15.3% |
| B and C | 0% | 100% |
| D | 28.9% | 3.4% |
| E | 35.1% | 26.2% |

- Flow-only and fusion transfer: **contradicted**.
- Fingerprint-only transfer: **insufficient evidence**. The outcome depends only on how unseen fingerprints are scored.
- No held-out benign source exists, so the benign false-positive rate on a new environment cannot be measured.

**Source identifiability.**
- JA4 alone separates DS-008 from DS-009 TLS flows with AP 1.000, against chance 0.023 (C11B).
- Flow features: AP 0.141 [0.090, 0.298] against chance 0.066. The evidence is insufficient (C11).

**Availability shortcut.** Handshake-presence flags alone reach AP 0.765, compared with a prevalence-floor baseline AP of 0.600 under the same protocol (C10).

### 13.5 Sequence models (RQ4; pooled population)

| Model | AP [CI] |
|---|---|
| Information-matched tabular (HGB on 64-packet aggregates) | 0.909 [0.759, 0.973] |
| Full-flow tabular RF | 0.904 [0.730, 0.984] |
| Full-flow tabular HGB | 0.886 [0.692, 0.983] |
| CNN | 0.871 [0.662, 0.979] |
| GRU | 0.828 [0.603, 0.972] |

Pre-declared contrasts (Holm over 4):

| Contrast | ΔAP [CI] | Holm p |
|---|---|---|
| CNN − matched | −0.039 [−0.118, 0.030] | 1.00 |
| GRU − matched | −0.082 [−0.171, 0.011] | 0.59 |
| CNN − full-flow | −0.015 [−0.060, 0.029] | 1.00 |
| GRU − full-flow | −0.058 [−0.105, −0.006] | 0.024 |

On the DS-009/DS-011 subset none of the contrasts is significant. Overall, sequence models add no detectable value here (C13). No transformer was trained.

### 13.6 Real-time engineering measurements

These are operational measurements, not model quality. The research-pilot RF models were replayed on 2,000 corpus flows in-process (`data/experiments/phase9/diagnostics/realtime_check.json`):
- A_FLOW: median inference latency 5.1 ms per flow.
- Fingerprint-only tracks: about 0.55 ms per flow.
- The deployable models were trained on all captures, so **every replayed flow was in-sample**. The engine flags each one `IN_SAMPLE_REPLAY`, and these scores are not evaluation evidence.

## 14. Statistical Analysis and Uncertainty

- **Effective sample size.** It is the number of captures, not flows: 6 benign and 19 malicious captures. Capture-bootstrap intervals with 6 benign groups are unstable and likely anti-conservative.
- **Seeds.** Each configuration was run with a single seed.
- **Multiplicity.** Holm is applied within each model's four contrasts. Claims rest on the pre-declared primary model, and cross-model multiplicity is reported as a sensitivity analysis (§13.2).
- **Equivalence.** Not claimed for any non-significant result.
- **Reproducibility.** Every reported metric reproduces from the persisted out-of-fold predictions (checksums verified, tolerance 1e-9).

## 15. Error Analysis and Source-Confounding Audit

The evidence is consistent with models learning **collection environment** rather than maliciousness:
- the classes do not share a single JA3 or JA4 value;
- JA4 identifies the malicious source perfectly;
- presence flags alone carry substantial label information;
- benign flows with novel client stacks are almost always flagged;
- performance collapses on held-out malicious sources.

Capture-level labels add noise. Background operating-system traffic inside malware captures is labelled malicious.

The earlier draft's attribution of the pilot result to "sandbox scheduling jitter" and specific features had no supporting artefact and has been removed.

## 16. Explainability

Permutation importance is computed on outer test folds, and impurity importance is reported separately (`python -m ml explain`). On source-confounded data, high importance indicates predictive association within this corpus, possibly a capture-environment shortcut. It is not causal, and it is not evidence of malicious behaviour. No SHAP or LIME analysis was performed.

## 17. Limitations and Threats to Validity

1. **Confounding.** Dataset identity equals class. There is a single benign source (2017 lab browsing, mostly Kali Linux per its READMEs), no benign TLS 1.3, and largely different operating systems between classes. This is the dominant threat; it blocks C02 and C09.
2. **Labels.** Labels are capture-level, not flow-level.
3. **JA4 conformance.** The ETTH JA4 variant is non-conformant (§9), and ClientHellos are parsed from the first segment only.
4. **Statistics.** There are few groups, a single seed, and no equivalence margin.
5. **External validity.** No held-out benign environment exists. The confirmatory evaluation was not run.
6. **Sensors.** Sensor integration was validated with synthetic fixtures only. Sensor telemetry cannot be scored by the current models (C21).
7. **ECH.** ECH [8] will remove SNI and most ClientHello detail from passive view.

## 18. Ethics and Privacy

- No traffic was decrypted, intercepted or collected from third parties.
- Datasets are public and used under their stated terms. Raw captures stay local and are not redistributed.
- Model inputs exclude IP addresses, ports, raw SNI and timestamps.
- Captures that require registration, a licence or provider permission were not acquired, and no access restriction was bypassed.

## 19. Reproducibility

Commands, seeds, artefact locations and environment are documented in `docs/research/REPRODUCIBILITY_GUIDE.md`. The checks used here:

```
python -m pytest -q -p no:cacheprovider   # engineering tests
python -m ml verify                       # re-checks every persisted result
python -m ml report                       # regenerates the claim ledger
```

Raw captures must be re-acquired from the recorded URLs; their checksums are recorded.

## 20. Conclusion and Future Work

On legitimately available public data, we find no evidence that JA3 or JA4 adds detection value to encrypted-flow features under realistic evaluation. We do find strong evidence that fingerprint "value" in such corpora reflects client-stack and source identity, and that the popular duplicate-grouped holdout hides this.

The research question stays open until the following are done:
1. benign data from independent environments comparable to the malicious hosts (Windows, modern browsers, enterprise software), each used as a held-out source;
2. a frozen confirmatory evaluation;
3. flow-level labels, or documented background-traffic filtering;
4. FoxIO-conformant JA4 and ClientHello reassembly;
5. multiple seeds and more benign captures;
6. an IOC (hash-lookup) baseline.

The contributions that can be claimed now:
- a leakage-audited benchmark harness;
- an evidence ledger generated from artefacts;
- a methodological negative result.

## 21. References

All entries were checked against the publisher, the venue or the canonical online source during the Phase 8–12 integration (2026-10-17). Web resources are cited with their access date.

1. B. Anderson and D. McGrew. Identifying Encrypted Malware Traffic with Contextual Flow Data. *Proceedings of the 2016 ACM Workshop on Artificial Intelligence and Security (AISec)*, pp. 35–46, 2016.
2. B. Anderson and D. McGrew. Machine Learning for Encrypted Malware Traffic Classification: Accounting for Noisy Labels and Non-Stationarity. *Proceedings of the 23rd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining (KDD)*, pp. 1723–1732, 2017.
3. J. Althouse. Open Sourcing JA3. *Salesforce Engineering Blog* (JA3 by J. B. Althouse, J. Atkinson and J. Atkins; code at github.com/salesforce/ja3). https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41/ (accessed 2026-10-17).
4. J. Althouse. JA4+ Network Fingerprinting. *FoxIO Blog*, 2023. https://blog.foxio.io/ja4-network-fingerprinting-9376fe9ca637 (accessed 2026-10-17).
5. FoxIO. JA4: TLS Client Fingerprinting, technical details. https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md (accessed 2026-10-17).
6. D. Arp, E. Quiring, F. Pendlebury, A. Warnecke, F. Pierazzi, C. Wressnegger, L. Cavallaro and K. Rieck. Dos and Don'ts of Machine Learning in Computer Security. *31st USENIX Security Symposium*, pp. 3971–3988, 2022.
7. R. Sommer and V. Paxson. Outside the Closed World: On Using Machine Learning for Network Intrusion Detection. *IEEE Symposium on Security and Privacy*, 2010. doi:10.1109/SP.2010.25.
8. E. Rescorla, K. Oku, N. Sullivan and C. A. Wood. TLS Encrypted Client Hello. RFC 9849, March 2026.
9. V. Paxson. Bro: A System for Detecting Network Intruders in Real-Time. *Computer Networks* 31(23–24), pp. 2435–2463, 1999.
10. Open Information Security Foundation. Suricata EVE JSON Format documentation. https://docs.suricata.io/en/latest/output/eve/eve-json-format.html (accessed 2026-10-17).
11. B. Duncan. Malware-Traffic-Analysis.net. https://www.malware-traffic-analysis.net/ (accessed 2026-10-17).
12. Stratosphere Laboratory, Czech Technical University in Prague. Stratosphere datasets (Malware Capture Facility Project and normal captures). https://www.stratosphereips.org/datasets-overview (accessed 2026-10-17).
13. S. García, M. Grill, J. Stiborek and A. Zunino. An Empirical Comparison of Botnet Detection Methods. *Computers & Security* 45, pp. 100–123, 2014.

*Removed from the earlier draft:*
- An "IEEE Transactions on Network and Service Management 14(4)" entry for Anderson and McGrew (2017). No such paper was found; the 2017 work is the KDD paper [2].
- The attribution of JA4+ to Brotherston. JA4+ is by J. Althouse (FoxIO); L. Brotherston authored the earlier FingerprinTLS.
- An incorrect co-author ("Dos Santos, C.") in Arp et al.
- Roesch (Snort, LISA 1999), which is no longer cited.
