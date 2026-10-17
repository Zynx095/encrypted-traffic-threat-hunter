# ETTH Research Report

Generated 2026-10-17T03:57:52.178674Z from persisted artefacts (`ml/reporting/report.py`). No value in this document was entered by hand.

## Research question

Does combining TLS fingerprint information, including JA3 and JA4 where available, with encrypted-flow behavioral features improve malicious encrypted-traffic detection compared with individual feature families, under realistic generalization conditions and without decrypting TLS application payloads?

## Status

- Implemented: True; tested: True; executed: True
- Scientifically validated: **False**; publication-ready: **False**
- Reason: All evaluations are exploratory on a corpus where dataset identity equals class; confirmatory evaluation is BLOCKED.

## Datasets

| ID | Name | State | Access | Flows |
|---|---|---|---|---|
| CAND-006 | CIC-IDS-2017 | ACCESS_PENDING | ACADEMIC_ACCESS_REQUIRED | UNKNOWN |
| CAND-007 | CIC-Bell-DNS-EXF-2021 | ACCESS_PENDING | ACADEMIC_ACCESS_REQUIRED | UNKNOWN |
| CAND-008 | CIRA-CIC-DoHBrw-2020 | ACCESS_PENDING | ACADEMIC_ACCESS_REQUIRED | UNKNOWN |
| DS-001 | ISCXVPN2016 | DISCOVERED | INSUFFICIENT_EVIDENCE | UNKNOWN |
| DS-002 | CIC-Darknet2020 | DISCOVERED | INSUFFICIENT_EVIDENCE | UNKNOWN |
| DS-003 | USTC-TFC2016 | DISCOVERED | INSUFFICIENT_EVIDENCE | UNKNOWN |
| DS-004 | CipherSpectrum | ACCESS_PENDING | ACADEMIC_ACCESS_REQUIRED | UNKNOWN |
| DS-005 | CSTNET-TLS1.3 | DISCOVERED | INSUFFICIENT_EVIDENCE | UNKNOWN |
| DS-006 | Beyond JA4+ / TLS fingerprinting datasets (Brno University of Technology) | BLOCKED | LICENSE_UNCLEAR | UNKNOWN |
| DS-007 | Annotated Encrypted Network Traffic (Brno University of Technology) | ACCESS_PENDING | ACADEMIC_ACCESS_REQUIRED | UNKNOWN |
| DS-008 | Malware-Traffic-Analysis.net (selected infection-traffic captures) | ADMITTED | VERIFIED_AVAILABLE | 2543 |
| DS-009 | Stratosphere Malware Capture Facility Project (MCFP), selected 2017 Windows malware captures | ADMITTED | VERIFIED_AVAILABLE | 447563 |
| DS-010 | IoT-23 | DISCOVERED | INSUFFICIENT_EVIDENCE | UNKNOWN |
| DS-011 | Stratosphere CTU-Normal HTTPS captures (CTU-Normal-20 to -32) | ADMITTED | VERIFIED_AVAILABLE | 127132 |

### Inclusion funnel (from data/corpus/admission_report.json)

| Dataset | In plan | Verified | Valid | In corpus | Flows | JA3 | JA4 |
|---|---|---|---|---|---|---|---|
| DS-004 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| DS-008 | 10 | 10 | 10 | 10 | 2543 | 194 | 194 |
| DS-009 | 9 | 9 | 9 | 9 | 447563 | 66612 | 66612 |
| DS-011 | 6 | 6 | 6 | 6 | 127132 | 13845 | 13845 |

Exclusions:
- DS004-sample1 (materialize): Raw file not present: data/samples/ds004/sample1.pcap
- DS004-sample2 (materialize): Raw file not present: data/samples/ds004/sample2.pcap
- DS004-sample3 (materialize): Raw file not present: data/samples/ds004/sample3.pcap
- DS004-sample4 (materialize): Raw file not present: data/samples/ds004/sample4.pcap
- DS004-sample5 (materialize): Raw file not present: data/samples/ds004/sample5.pcap
- DS004-sample6 (materialize): Raw file not present: data/samples/ds004/sample6.pcap
- DS008-MTA-C003 (plan): Stage 6.5 decision: Empirical testing failed or no useful TLS/JA4 data
- DS008-MTA-C039 (plan): Stage 6.5 decision: Only 1 TLS flow; redundant families (XLoader is in baseline, Remcos is in C040)

### Benign sufficiency

- A_pipeline: MET {'captures_per_class': True, 'flows_per_class': True}
- B_preliminary: MET {'captures_per_class': True, 'flows_per_class': True, 'fingerprinted_flows_per_class': True, 'behavioral_groups_per_class': True}
- C_generalization: NOT MET {'sources_per_class': False, 'captures_per_class': False, 'temporal_overlap_between_classes': True, 'tls13_in_both_classes': False, 'environments_per_class': False}
- D_publication: NOT MET {'sources_per_class': False, 'captures_per_class': False, 'independent_confirmatory_source': False, 'flow_level_labels': False}

## Fingerprint coverage (full corpus)

| Track | Rows | Coverage (all) | Malicious | Benign |
|---|---|---|---|---|
| A_FLOW | 577238 | 100.0% | 100.0% | 100.0% |
| B_JA3 | 80651 | 14.0% | 14.8% | 10.9% |
| C_JA4 | 80651 | 14.0% | 14.8% | 10.9% |
| D_JA3_FLOW | 80651 | 14.0% | 14.8% | 10.9% |
| E_JA4_FLOW | 80651 | 14.0% | 14.8% | 10.9% |
| A0_FLOW_STRICT | 577238 | 100.0% | 100.0% | 100.0% |

JA3 values shared between classes: 0 of 90; JA4: 0 of 82.

## Dataset-shift diagnostics

- Collection years by source: {'DS-008': [2024, 2025, 2026], 'DS-009': [2017], 'DS-011': [2017]}
- TLS-version share by source: {'DS-008': {'nan': 0.9237, '1.2': 0.0436, '1.3': 0.0326}, 'DS-009': {'nan': 0.8512, '1.2': 0.1488}, 'DS-011': {'nan': 0.8911, '1.2': 0.1089}}
- Median flow statistics by source: {'DS-008': {'flow_duration': 0.0033779144287109375, 'total_packets': 2.0, 'total_bytes': 80.0, 'packet_length_mean': 40.0, 'iat_mean': 0.03361084063847859}, 'DS-009': {'flow_duration': 0.01459100004285574, 'total_packets': 2.0, 'total_bytes': 92.0, 'packet_length_mean': 46.0, 'iat_mean': 0.021184727274389428}, 'DS-011': {'flow_duration': 0.02555549999988216, 'total_packets': 2.0, 'total_bytes': 186.0, 'packet_length_mean': 84.0, 'iat_mean': 0.03314970067352381}}

## Evaluation protocols

- **pooled_capture_cv** (CAPTURE_GROUP_KFOLD): All admitted captures; whole capture sessions held out (stratified group 5-fold). Tracks: A_FLOW, B_JA3, C_JA4, D_JA3_FLOW, E_JA4_FLOW, A_FLOW@JA3POP, A_FLOW@JA4POP, A0_FLOW_STRICT, P_AVAILABILITY_PROBE. Models: dummy_prior, logreg, random_forest, hist_gb.
- **matched_lab_capture_cv** (CAPTURE_GROUP_KFOLD): Least-confounded subset: DS-009 malware and DS-011 benign captures from the same laboratory and period. Tracks: A_FLOW, B_JA3, C_JA4, D_JA3_FLOW, E_JA4_FLOW, A_FLOW@JA3POP, A_FLOW@JA4POP, A0_FLOW_STRICT, P_AVAILABILITY_PROBE. Models: dummy_prior, logreg, random_forest, hist_gb.
- **leave_one_source_out** (LEAVE_ONE_SOURCE_OUT): Each dataset held out in turn; single-class test folds report detection rate or false-positive rate. Tracks: A_FLOW, B_JA3, C_JA4, D_JA3_FLOW, E_JA4_FLOW. Models: logreg, random_forest, hist_gb.
- **leave_one_family_out** (LEAVE_ONE_FAMILY_OUT): Each malware family group held out with one rotating benign capture. Tracks: A_FLOW, D_JA3_FLOW, E_JA4_FLOW. Models: random_forest, hist_gb.
- **legacy_behavioral_holdout** (BEHAVIORAL_HOLDOUT): Phase 7 protocol (GroupShuffleSplit on behavioral_hash, seed 42) for continuity; captures leak across sides. Tracks: A_FLOW, B_JA3, C_JA4, D_JA3_FLOW, E_JA4_FLOW. Models: logreg, random_forest.
- **encoding_ablation** (CAPTURE_GROUP_KFOLD): Fingerprint encoding strategies (one-hot, train-frequency, hashing) under capture-grouped CV. Tracks: B_JA3, C_JA4. Models: logreg.
- **source_identifiability** (CAPTURE_GROUP_KFOLD): Diagnostic, not detection: can features tell the two MALICIOUS sources (DS-008 vs DS-009) apart? Tracks: A_FLOW, C_JA4, E_JA4_FLOW. Models: random_forest.

Confirmatory evaluation: **BLOCKED** — All currently admitted sources (DS-008, DS-009, DS-011) are used in exploratory suites.

## Results by suite (exploratory)

### encoding_ablation — `encoding_ablation-20261016T163936Z`

Seed 42; evaluation population {'per_capture_cap': 4000, 'rows': 62543, 'rows_by_dataset': {'DS-008': 2543, 'DS-009': 36000, 'DS-011': 24000}, 'positives': 38543, 'negatives': 24000, 'captures': 25}

| Track | Model | Enc. | Status | Pos/Neg | AP [95% CI] (status) | ROC-AUC | Recall @ val-FPR≤1% | Test FPR | ECE | Brier |
|---|---|---|---|---|---|---|---|---|---|---|
| B_JA3 | logreg | onehot | COMPLETED | 8591/2629 | 0.970 [0.863, 1.000] (FEW_GROUPS) | 0.912 | 99.8% | 18.6% | 0.042 | 0.046 |
| B_JA3 | logreg | frequency | COMPLETED | 8591/2629 | 0.995 [0.965, 0.999] (FEW_GROUPS) | 0.979 | 97.7% | 0.0% | 0.022 | 0.018 |
| B_JA3 | logreg | hashing | COMPLETED | 8591/2629 | 0.995 [0.968, 1.000] (FEW_GROUPS) | 0.984 | 98.5% | 18.4% | 0.049 | 0.052 |
| C_JA4 | logreg | onehot | COMPLETED | 8591/2629 | 0.999 [0.990, 1.000] (FEW_GROUPS) | 0.997 | 99.3% | 18.4% | 0.045 | 0.047 |
| C_JA4 | logreg | frequency | COMPLETED | 8591/2629 | 0.995 [0.965, 0.999] (FEW_GROUPS) | 0.979 | 97.7% | 0.0% | 0.022 | 0.018 |
| C_JA4 | logreg | hashing | COMPLETED | 8591/2629 | 0.996 [0.973, 1.000] (FEW_GROUPS) | 0.988 | 98.9% | 18.4% | 0.046 | 0.049 |

Paired contrasts (logreg; Holm over 4 pre-declared contrasts):

| Contrast | Shared rows | AP A | AP B | ΔAP [95% CI] | Holm p | Interpretation |
|---|---|---|---|---|---|---|
| JA3 added to flow (A_FLOW@JA3POP→D_JA3_FLOW) | — | — | — | — [—, —] | — | NOT_RUN |
| JA4 added to flow (A_FLOW@JA4POP→E_JA4_FLOW) | — | — | — | — [—, —] | — | NOT_RUN |
| flow added to JA3 (B_JA3→D_JA3_FLOW) | — | — | — | — [—, —] | — | NOT_RUN |
| flow added to JA4 (C_JA4→E_JA4_FLOW) | — | — | — | — [—, —] | — | NOT_RUN |

### leave_one_family_out — `leave_one_family_out-20261016T181651Z`

Seed 42; evaluation population {'per_capture_cap': 4000, 'rows': 62543, 'rows_by_dataset': {'DS-008': 2543, 'DS-009': 36000, 'DS-011': 24000}, 'positives': 38543, 'negatives': 24000, 'captures': 25}

| Track | Model | Enc. | Status | Pos/Neg | AP [95% CI] (status) | ROC-AUC | Recall @ val-FPR≤1% | Test FPR | ECE | Brier |
|---|---|---|---|---|---|---|---|---|---|---|
| A_FLOW | random_forest | onehot | COMPLETED | 38543/40000 | 0.710 [0.456, 0.962] (FEW_GROUPS) | 0.825 | 37.1% | 8.0% | 0.182 | 0.184 |
| A_FLOW | hist_gb | onehot | COMPLETED | 38543/40000 | 0.630 [0.384, 0.962] (FEW_GROUPS) | 0.769 | 6.9% | 17.2% | 0.232 | 0.202 |
| D_JA3_FLOW | random_forest | onehot | COMPLETED | 8591/3979 | 0.992 [0.937, 1.000] (FEW_GROUPS) | 0.987 | 98.5% | 20.0% | 0.043 | 0.044 |
| D_JA3_FLOW | hist_gb | onehot | COMPLETED | 8591/3979 | 0.982 [0.856, 1.000] (FEW_GROUPS) | 0.973 | 60.9% | 15.2% | 0.056 | 0.022 |
| E_JA4_FLOW | random_forest | onehot | COMPLETED | 8591/3979 | 0.982 [0.918, 1.000] (FEW_GROUPS) | 0.982 | 99.0% | 17.8% | 0.043 | 0.043 |
| E_JA4_FLOW | hist_gb | onehot | COMPLETED | 8591/3979 | 0.982 [0.856, 1.000] (FEW_GROUPS) | 0.973 | 60.9% | 15.2% | 0.056 | 0.022 |

Per-capture flagged rate at the validation-selected FPR≤1% threshold (primary model random_forest; benign rows = false-positive rate, malicious rows = detection rate):

| Capture | Class | A_FLOW | D_JA3_FLOW | E_JA4_FLOW |
|---|---|---|---|---|
| DS008-C001 | MAL | 0.7% (n=1380) | 11.1% (n=45) | 20.0% (n=45) |
| DS008-C002 | MAL | 0.0% (n=74) | 35.3% (n=17) | 47.1% (n=17) |
| DS008-C003 | MAL | 0.8% (n=258) | 52.0% (n=50) | 72.0% (n=50) |
| DS008-C004 | MAL | 0.0% (n=9) | 50.0% (n=2) | 100.0% (n=2) |
| DS008-C005 | MAL | 0.0% (n=20) | 100.0% (n=8) | 100.0% (n=8) |
| DS008-C006 | MAL | 0.0% (n=27) | 0.0% (n=6) | 0.0% (n=6) |
| DS008-C007 | MAL | 7.6% (n=423) | 100.0% (n=10) | 100.0% (n=10) |
| DS008-C008 | MAL | 37.5% (n=16) | 100.0% (n=2) | 100.0% (n=2) |
| DS008-C009 | MAL | 0.5% (n=214) | 0.0% (n=51) | 64.7% (n=51) |
| DS008-C010 | MAL | 43.4% (n=122) | 100.0% (n=3) | 100.0% (n=3) |
| DS009-CTU-MCB-238-1 | MAL | 0.4% (n=4000) | 100.0% (n=1700) | 100.0% (n=1700) |
| DS009-CTU-MCB-240-1 | MAL | 0.2% (n=4000) | 100.0% (n=1725) | 100.0% (n=1725) |
| DS009-CTU-MCB-246-1 | MAL | 57.6% (n=4000) | 100.0% (n=1353) | 100.0% (n=1353) |
| DS009-CTU-MCB-248-1 | MAL | 74.8% (n=4000) | 100.0% (n=1494) | 100.0% (n=1494) |
| DS009-CTU-MCB-249-1 | MAL | 63.1% (n=4000) | 100.0% (n=1238) | 100.0% (n=1238) |
| DS009-CTU-MCB-259-1 | MAL | 60.5% (n=4000) | — | — |
| DS009-CTU-MCB-260-1 | MAL | 42.8% (n=4000) | 100.0% (n=887) | 100.0% (n=887) |
| DS009-CTU-MCB-264-1 | MAL | 35.4% (n=4000) | — | — |
| DS009-CTU-MCB-268-1 | MAL | 20.5% (n=4000) | — | — |
| DS011-CTU-Normal-20 | BEN | 0.0% (n=8000) | 0.0% (n=740) | 0.1% (n=740) |
| DS011-CTU-Normal-21 | BEN | 39.7% (n=8000) | 82.4% (n=966) | 73.4% (n=966) |
| DS011-CTU-Normal-23 | BEN | 0.1% (n=8000) | 0.0% (n=994) | 0.0% (n=994) |
| DS011-CTU-Normal-24 | BEN | 0.1% (n=8000) | 0.0% (n=423) | 0.0% (n=423) |
| DS011-CTU-Normal-26 | BEN | 0.0% (n=4000) | 0.0% (n=297) | 0.0% (n=297) |
| DS011-CTU-Normal-28 | BEN | 0.1% (n=4000) | 0.0% (n=559) | 0.0% (n=559) |

### leave_one_source_out — `leave_one_source_out-20261016T180916Z`

Seed 42; evaluation population {'per_capture_cap': 4000, 'rows': 62543, 'rows_by_dataset': {'DS-008': 2543, 'DS-009': 36000, 'DS-011': 24000}, 'positives': 38543, 'negatives': 24000, 'captures': 25}

| Track | Model | Enc. | Status | Pos/Neg | AP [95% CI] (status) | ROC-AUC | Recall @ val-FPR≤1% | Test FPR | ECE | Brier |
|---|---|---|---|---|---|---|---|---|---|---|
| A_FLOW | logreg | onehot | COMPLETED | 38543/0 | — [—, —] (INSUFFICIENT_GROUPS) | — | 0.3% | — | — | — |
| A_FLOW | random_forest | onehot | COMPLETED | 38543/0 | — [—, —] (INSUFFICIENT_GROUPS) | — | 14.5% | — | — | — |
| A_FLOW | hist_gb | onehot | COMPLETED | 38543/0 | — [—, —] (INSUFFICIENT_GROUPS) | — | 0.2% | — | — | — |
| B_JA3 | logreg | onehot | COMPLETED | 8591/0 | — [—, —] (INSUFFICIENT_GROUPS) | — | 97.7% | — | — | — |
| B_JA3 | random_forest | onehot | COMPLETED | 8591/0 | — [—, —] (INSUFFICIENT_GROUPS) | — | 97.7% | — | — | — |
| B_JA3 | hist_gb | onehot | COMPLETED | 8591/0 | — [—, —] (INSUFFICIENT_GROUPS) | — | 97.7% | — | — | — |
| C_JA4 | logreg | onehot | COMPLETED | 8591/0 | — [—, —] (INSUFFICIENT_GROUPS) | — | 97.7% | — | — | — |
| C_JA4 | random_forest | onehot | COMPLETED | 8591/0 | — [—, —] (INSUFFICIENT_GROUPS) | — | 97.7% | — | — | — |
| C_JA4 | hist_gb | onehot | COMPLETED | 8591/0 | — [—, —] (INSUFFICIENT_GROUPS) | — | 97.7% | — | — | — |
| D_JA3_FLOW | logreg | onehot | COMPLETED | 8591/0 | — [—, —] (INSUFFICIENT_GROUPS) | — | 99.1% | — | — | — |
| D_JA3_FLOW | random_forest | onehot | COMPLETED | 8591/0 | — [—, —] (INSUFFICIENT_GROUPS) | — | 4.0% | — | — | — |
| D_JA3_FLOW | hist_gb | onehot | COMPLETED | 8591/0 | — [—, —] (INSUFFICIENT_GROUPS) | — | 22.9% | — | — | — |
| E_JA4_FLOW | logreg | onehot | COMPLETED | 8591/0 | — [—, —] (INSUFFICIENT_GROUPS) | — | 99.0% | — | — | — |
| E_JA4_FLOW | random_forest | onehot | COMPLETED | 8591/0 | — [—, —] (INSUFFICIENT_GROUPS) | — | 26.4% | — | — | — |
| E_JA4_FLOW | hist_gb | onehot | COMPLETED | 8591/0 | — [—, —] (INSUFFICIENT_GROUPS) | — | 22.9% | — | — | — |

Per-capture flagged rate at the validation-selected FPR≤1% threshold (primary model random_forest; benign rows = false-positive rate, malicious rows = detection rate):

| Capture | Class | A_FLOW | C_JA4 | D_JA3_FLOW | E_JA4_FLOW |
|---|---|---|---|---|---|
| DS008-C001 | MAL | 0.9% (n=1380) | 0.0% (n=45) | 2.2% (n=45) | 2.2% (n=45) |
| DS008-C002 | MAL | 1.4% (n=74) | 0.0% (n=17) | 29.4% (n=17) | 29.4% (n=17) |
| DS008-C003 | MAL | 2.7% (n=258) | 0.0% (n=50) | 8.0% (n=50) | 26.0% (n=50) |
| DS008-C004 | MAL | 0.0% (n=9) | 0.0% (n=2) | 0.0% (n=2) | 0.0% (n=2) |
| DS008-C005 | MAL | 0.0% (n=20) | 0.0% (n=8) | 50.0% (n=8) | 75.0% (n=8) |
| DS008-C006 | MAL | 18.5% (n=27) | 0.0% (n=6) | 16.7% (n=6) | 33.3% (n=6) |
| DS008-C007 | MAL | 11.1% (n=423) | 0.0% (n=10) | 60.0% (n=10) | 60.0% (n=10) |
| DS008-C008 | MAL | 18.8% (n=16) | 0.0% (n=2) | 0.0% (n=2) | 0.0% (n=2) |
| DS008-C009 | MAL | 0.5% (n=214) | 0.0% (n=51) | 68.6% (n=51) | 68.6% (n=51) |
| DS008-C010 | MAL | 16.4% (n=122) | 0.0% (n=3) | 0.0% (n=3) | 0.0% (n=3) |
| DS009-CTU-MCB-238-1 | MAL | 0.3% (n=4000) | 100.0% (n=1700) | 3.1% (n=1700) | 27.3% (n=1700) |
| DS009-CTU-MCB-240-1 | MAL | 0.4% (n=4000) | 100.0% (n=1725) | 3.6% (n=1725) | 30.6% (n=1725) |
| DS009-CTU-MCB-246-1 | MAL | 33.0% (n=4000) | 100.0% (n=1353) | 8.5% (n=1353) | 42.6% (n=1353) |
| DS009-CTU-MCB-248-1 | MAL | 37.6% (n=4000) | 100.0% (n=1494) | 3.6% (n=1494) | 33.3% (n=1494) |
| DS009-CTU-MCB-249-1 | MAL | 29.7% (n=4000) | 100.0% (n=1238) | 0.3% (n=1238) | 9.9% (n=1238) |
| DS009-CTU-MCB-259-1 | MAL | 0.0% (n=4000) | — | — | — |
| DS009-CTU-MCB-260-1 | MAL | 9.1% (n=4000) | 100.0% (n=887) | 0.0% (n=887) | 1.5% (n=887) |
| DS009-CTU-MCB-264-1 | MAL | 4.0% (n=4000) | — | — | — |
| DS009-CTU-MCB-268-1 | MAL | 23.4% (n=4000) | — | — | — |

### legacy_behavioral_holdout — `legacy_behavioral_holdout-20261016T184825Z`

Seed 42; evaluation population {'per_capture_cap': 4000, 'rows': 62543, 'rows_by_dataset': {'DS-008': 2543, 'DS-009': 36000, 'DS-011': 24000}, 'positives': 38543, 'negatives': 24000, 'captures': 25}

| Track | Model | Enc. | Status | Pos/Neg | AP [95% CI] (status) | ROC-AUC | Recall @ val-FPR≤1% | Test FPR | ECE | Brier |
|---|---|---|---|---|---|---|---|---|---|---|
| A_FLOW | logreg | onehot | COMPLETED | 6042/3798 | 0.960 [0.925, 0.978] (FEW_GROUPS) | 0.931 | 39.9% | 1.1% | 0.126 | 0.118 |
| A_FLOW | random_forest | onehot | COMPLETED | 6042/3798 | 0.991 [0.976, 0.999] (FEW_GROUPS) | 0.983 | 95.0% | 1.1% | 0.022 | 0.032 |
| B_JA3 | logreg | onehot | COMPLETED | 1736/508 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 0.4% | 0.001 | 0.000 |
| B_JA3 | random_forest | onehot | COMPLETED | 1736/508 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 0.4% | 0.001 | 0.000 |
| C_JA4 | logreg | onehot | COMPLETED | 1736/508 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 0.4% | 0.001 | 0.000 |
| C_JA4 | random_forest | onehot | COMPLETED | 1736/508 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 0.4% | 0.001 | 0.001 |
| D_JA3_FLOW | logreg | onehot | COMPLETED | 1736/508 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 1.0% | 0.002 | 0.003 |
| D_JA3_FLOW | random_forest | onehot | COMPLETED | 1736/508 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 0.6% | 0.001 | 0.000 |
| E_JA4_FLOW | logreg | onehot | COMPLETED | 1736/508 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 1.2% | 0.002 | 0.003 |
| E_JA4_FLOW | random_forest | onehot | COMPLETED | 1736/508 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 0.6% | 0.001 | 0.000 |

Paired contrasts (logreg; Holm over 4 pre-declared contrasts):

| Contrast | Shared rows | AP A | AP B | ΔAP [95% CI] | Holm p | Interpretation |
|---|---|---|---|---|---|---|
| JA3 added to flow (A_FLOW@JA3POP→D_JA3_FLOW) | — | — | — | — [—, —] | — | NOT_RUN |
| JA4 added to flow (A_FLOW@JA4POP→E_JA4_FLOW) | — | — | — | — [—, —] | — | NOT_RUN |
| flow added to JA3 (B_JA3→D_JA3_FLOW) | 2244 | 1.0000 | 1.0000 | -0.0000 [-0.0000, 0.0000] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |
| flow added to JA4 (C_JA4→E_JA4_FLOW) | 2244 | 1.0000 | 1.0000 | -0.0000 [-0.0000, 0.0000] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |

Paired contrasts (random_forest; Holm over 4 pre-declared contrasts):

| Contrast | Shared rows | AP A | AP B | ΔAP [95% CI] | Holm p | Interpretation |
|---|---|---|---|---|---|---|
| JA3 added to flow (A_FLOW@JA3POP→D_JA3_FLOW) | — | — | — | — [—, —] | — | NOT_RUN |
| JA4 added to flow (A_FLOW@JA4POP→E_JA4_FLOW) | — | — | — | — [—, —] | — | NOT_RUN |
| flow added to JA3 (B_JA3→D_JA3_FLOW) | 2244 | 1.0000 | 1.0000 | 0.0000 [-0.0000, 0.0000] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |
| flow added to JA4 (C_JA4→E_JA4_FLOW) | 2244 | 1.0000 | 1.0000 | 0.0000 [-0.0000, 0.0000] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |

Per-capture flagged rate at the validation-selected FPR≤1% threshold (primary model random_forest; benign rows = false-positive rate, malicious rows = detection rate):

| Capture | Class | A_FLOW | C_JA4 | D_JA3_FLOW | E_JA4_FLOW |
|---|---|---|---|---|---|
| DS008-C001 | MAL | 85.0% (n=207) | 100.0% (n=11) | 100.0% (n=11) | 100.0% (n=11) |
| DS008-C002 | MAL | 36.4% (n=11) | 100.0% (n=4) | 100.0% (n=4) | 100.0% (n=4) |
| DS008-C003 | MAL | 50.0% (n=26) | 100.0% (n=14) | 100.0% (n=14) | 100.0% (n=14) |
| DS008-C004 | MAL | 100.0% (n=2) | — | — | — |
| DS008-C005 | MAL | 66.7% (n=3) | — | — | — |
| DS008-C006 | MAL | 100.0% (n=5) | — | — | — |
| DS008-C007 | MAL | 100.0% (n=55) | 100.0% (n=1) | 100.0% (n=1) | 100.0% (n=1) |
| DS008-C008 | MAL | 50.0% (n=2) | — | — | — |
| DS008-C009 | MAL | 41.7% (n=48) | 100.0% (n=13) | 100.0% (n=13) | 100.0% (n=13) |
| DS008-C010 | MAL | 80.0% (n=15) | — | — | — |
| DS009-CTU-MCB-238-1 | MAL | 77.5% (n=570) | 100.0% (n=331) | 100.0% (n=331) | 100.0% (n=331) |
| DS009-CTU-MCB-240-1 | MAL | 86.8% (n=544) | 100.0% (n=330) | 100.0% (n=330) | 100.0% (n=330) |
| DS009-CTU-MCB-246-1 | MAL | 99.7% (n=609) | 100.0% (n=273) | 100.0% (n=273) | 100.0% (n=273) |
| DS009-CTU-MCB-248-1 | MAL | 98.1% (n=574) | 100.0% (n=303) | 100.0% (n=303) | 100.0% (n=303) |
| DS009-CTU-MCB-249-1 | MAL | 99.1% (n=559) | 100.0% (n=267) | 100.0% (n=267) | 100.0% (n=267) |
| DS009-CTU-MCB-259-1 | MAL | 100.0% (n=811) | — | — | — |
| DS009-CTU-MCB-260-1 | MAL | 100.0% (n=754) | 100.0% (n=189) | 100.0% (n=189) | 100.0% (n=189) |
| DS009-CTU-MCB-264-1 | MAL | 100.0% (n=742) | — | — | — |
| DS009-CTU-MCB-268-1 | MAL | 99.8% (n=505) | — | — | — |
| DS011-CTU-Normal-20 | BEN | 0.3% (n=687) | 1.3% (n=77) | 1.3% (n=77) | 1.3% (n=77) |
| DS011-CTU-Normal-21 | BEN | 3.3% (n=523) | 0.0% (n=87) | 1.1% (n=87) | 1.1% (n=87) |
| DS011-CTU-Normal-23 | BEN | 0.8% (n=640) | 0.0% (n=99) | 0.0% (n=99) | 0.0% (n=99) |
| DS011-CTU-Normal-24 | BEN | 1.0% (n=673) | 0.0% (n=93) | 1.1% (n=93) | 1.1% (n=93) |
| DS011-CTU-Normal-26 | BEN | 0.1% (n=694) | 1.8% (n=57) | 0.0% (n=57) | 0.0% (n=57) |
| DS011-CTU-Normal-28 | BEN | 1.7% (n=581) | 0.0% (n=95) | 0.0% (n=95) | 0.0% (n=95) |

### matched_lab_capture_cv — `matched_lab_capture_cv-20261016T172459Z`

Seed 42; evaluation population {'per_capture_cap': 4000, 'rows': 60000, 'rows_by_dataset': {'DS-009': 36000, 'DS-011': 24000}, 'positives': 36000, 'negatives': 24000, 'captures': 15}

| Track | Model | Enc. | Status | Pos/Neg | AP [95% CI] (status) | ROC-AUC | Recall @ val-FPR≤1% | Test FPR | ECE | Brier |
|---|---|---|---|---|---|---|---|---|---|---|
| A_FLOW | dummy_prior | onehot | COMPLETED | 36000/24000 | 0.535 [0.469, 0.745] (FEW_GROUPS) | 0.389 | 0.0% | 0.0% | 0.180 | 0.258 |
| A_FLOW | logreg | onehot | COMPLETED | 36000/24000 | 0.780 [0.636, 0.926] (FEW_GROUPS) | 0.774 | 6.7% | 1.9% | 0.182 | 0.202 |
| A_FLOW | random_forest | onehot | COMPLETED | 36000/24000 | 0.934 [0.846, 0.984] (FEW_GROUPS) | 0.916 | 50.8% | 5.6% | 0.131 | 0.136 |
| A_FLOW | hist_gb | onehot | COMPLETED | 36000/24000 | 0.885 [0.746, 0.974] (FEW_GROUPS) | 0.860 | 50.5% | 7.1% | 0.100 | 0.142 |
| B_JA3 | dummy_prior | onehot | COMPLETED | 8397/2629 | 0.691 [0.644, 0.830] (FEW_GROUPS) | 0.320 | 0.0% | 0.0% | 0.138 | 0.195 |
| B_JA3 | logreg | onehot | COMPLETED | 8397/2629 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 0.0% | 0.000 | 0.000 |
| B_JA3 | random_forest | onehot | COMPLETED | 8397/2629 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 0.0% | 0.000 | 0.000 |
| B_JA3 | hist_gb | onehot | COMPLETED | 8397/2629 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 11.3% | 0.000 | 0.000 |
| C_JA4 | dummy_prior | onehot | COMPLETED | 8397/2629 | 0.691 [0.644, 0.830] (FEW_GROUPS) | 0.320 | 0.0% | 0.0% | 0.138 | 0.195 |
| C_JA4 | logreg | onehot | COMPLETED | 8397/2629 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 0.0% | 0.000 | 0.000 |
| C_JA4 | random_forest | onehot | COMPLETED | 8397/2629 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 0.0% | 0.000 | 0.000 |
| C_JA4 | hist_gb | onehot | COMPLETED | 8397/2629 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 11.3% | 0.000 | 0.000 |
| D_JA3_FLOW | dummy_prior | onehot | COMPLETED | 8397/2629 | 0.691 [0.644, 0.830] (FEW_GROUPS) | 0.320 | 0.0% | 0.0% | 0.138 | 0.195 |
| D_JA3_FLOW | logreg | onehot | COMPLETED | 8397/2629 | 0.999 [0.998, 1.000] (FEW_GROUPS) | 0.999 | 100.0% | 0.7% | 0.005 | 0.001 |
| D_JA3_FLOW | random_forest | onehot | COMPLETED | 8397/2629 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 15.3% | 0.001 | 0.000 |
| D_JA3_FLOW | hist_gb | onehot | COMPLETED | 8397/2629 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 30.3% | 0.000 | 0.000 |
| E_JA4_FLOW | dummy_prior | onehot | COMPLETED | 8397/2629 | 0.691 [0.644, 0.830] (FEW_GROUPS) | 0.320 | 0.0% | 0.0% | 0.138 | 0.195 |
| E_JA4_FLOW | logreg | onehot | COMPLETED | 8397/2629 | 0.999 [0.998, 1.000] (FEW_GROUPS) | 0.999 | 100.0% | 0.7% | 0.005 | 0.001 |
| E_JA4_FLOW | random_forest | onehot | COMPLETED | 8397/2629 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 13.1% | 0.001 | 0.000 |
| E_JA4_FLOW | hist_gb | onehot | COMPLETED | 8397/2629 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 30.3% | 0.000 | 0.000 |
| A_FLOW@JA3POP | dummy_prior | onehot | COMPLETED | 8397/2629 | 0.691 [0.644, 0.830] (FEW_GROUPS) | 0.320 | 0.0% | 0.0% | 0.138 | 0.195 |
| A_FLOW@JA3POP | logreg | onehot | COMPLETED | 8397/2629 | 0.999 [0.997, 1.000] (FEW_GROUPS) | 0.999 | 100.0% | 0.8% | 0.009 | 0.001 |
| A_FLOW@JA3POP | random_forest | onehot | COMPLETED | 8397/2629 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 13.4% | 0.001 | 0.000 |
| A_FLOW@JA3POP | hist_gb | onehot | COMPLETED | 8397/2629 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 30.3% | 0.000 | 0.000 |
| A_FLOW@JA4POP | dummy_prior | onehot | COMPLETED | 8397/2629 | 0.691 [0.644, 0.830] (FEW_GROUPS) | 0.320 | 0.0% | 0.0% | 0.138 | 0.195 |
| A_FLOW@JA4POP | logreg | onehot | COMPLETED | 8397/2629 | 0.999 [0.997, 1.000] (FEW_GROUPS) | 0.999 | 100.0% | 0.8% | 0.009 | 0.001 |
| A_FLOW@JA4POP | random_forest | onehot | COMPLETED | 8397/2629 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 13.4% | 0.001 | 0.000 |
| A_FLOW@JA4POP | hist_gb | onehot | COMPLETED | 8397/2629 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 30.3% | 0.000 | 0.000 |
| A0_FLOW_STRICT | dummy_prior | onehot | COMPLETED | 36000/24000 | 0.535 [0.469, 0.745] (FEW_GROUPS) | 0.389 | 0.0% | 0.0% | 0.180 | 0.258 |
| A0_FLOW_STRICT | logreg | onehot | COMPLETED | 36000/24000 | 0.767 [0.629, 0.926] (FEW_GROUPS) | 0.768 | 5.6% | 1.9% | 0.151 | 0.190 |
| A0_FLOW_STRICT | random_forest | onehot | COMPLETED | 36000/24000 | 0.923 [0.826, 0.982] (FEW_GROUPS) | 0.898 | 52.2% | 6.7% | 0.113 | 0.137 |
| A0_FLOW_STRICT | hist_gb | onehot | COMPLETED | 36000/24000 | 0.888 [0.731, 0.984] (FEW_GROUPS) | 0.888 | 49.8% | 8.4% | 0.109 | 0.116 |
| P_AVAILABILITY_PROBE | dummy_prior | onehot | COMPLETED | 36000/24000 | 0.535 [0.469, 0.745] (FEW_GROUPS) | 0.389 | 0.0% | 0.0% | 0.180 | 0.258 |
| P_AVAILABILITY_PROBE | logreg | onehot | COMPLETED | 36000/24000 | 0.726 [0.646, 0.853] (FEW_GROUPS) | 0.600 | 25.8% | 0.1% | 0.142 | 0.214 |
| P_AVAILABILITY_PROBE | random_forest | onehot | COMPLETED | 36000/24000 | 0.726 [0.646, 0.853] (FEW_GROUPS) | 0.600 | 25.8% | 0.1% | 0.141 | 0.214 |
| P_AVAILABILITY_PROBE | hist_gb | onehot | COMPLETED | 36000/24000 | 0.726 [0.646, 0.853] (FEW_GROUPS) | 0.600 | 25.8% | 0.1% | 0.141 | 0.214 |

Paired contrasts (logreg; Holm over 4 pre-declared contrasts):

| Contrast | Shared rows | AP A | AP B | ΔAP [95% CI] | Holm p | Interpretation |
|---|---|---|---|---|---|---|
| JA3 added to flow (A_FLOW@JA3POP→D_JA3_FLOW) | 11026 | 0.9992 | 0.9994 | 0.0002 [0.0000, 0.0008] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |
| JA4 added to flow (A_FLOW@JA4POP→E_JA4_FLOW) | 11026 | 0.9992 | 0.9994 | 0.0002 [0.0000, 0.0008] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |
| flow added to JA3 (B_JA3→D_JA3_FLOW) | 11026 | 1.0000 | 0.9994 | -0.0006 [-0.0024, 0.0000] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |
| flow added to JA4 (C_JA4→E_JA4_FLOW) | 11026 | 1.0000 | 0.9994 | -0.0006 [-0.0024, 0.0000] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |

Paired contrasts (random_forest; Holm over 4 pre-declared contrasts):

| Contrast | Shared rows | AP A | AP B | ΔAP [95% CI] | Holm p | Interpretation |
|---|---|---|---|---|---|---|
| JA3 added to flow (A_FLOW@JA3POP→D_JA3_FLOW) | 11026 | 1.0000 | 1.0000 | 0.0000 [-0.0000, 0.0000] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |
| JA4 added to flow (A_FLOW@JA4POP→E_JA4_FLOW) | 11026 | 1.0000 | 1.0000 | 0.0000 [-0.0000, 0.0000] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |
| flow added to JA3 (B_JA3→D_JA3_FLOW) | 11026 | 1.0000 | 1.0000 | 0.0000 [-0.0000, 0.0000] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |
| flow added to JA4 (C_JA4→E_JA4_FLOW) | 11026 | 1.0000 | 1.0000 | 0.0000 [-0.0000, 0.0000] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |

Paired contrasts (hist_gb; Holm over 4 pre-declared contrasts):

| Contrast | Shared rows | AP A | AP B | ΔAP [95% CI] | Holm p | Interpretation |
|---|---|---|---|---|---|---|
| JA3 added to flow (A_FLOW@JA3POP→D_JA3_FLOW) | 11026 | 1.0000 | 1.0000 | 0.0000 [-0.0000, 0.0000] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |
| JA4 added to flow (A_FLOW@JA4POP→E_JA4_FLOW) | 11026 | 1.0000 | 1.0000 | 0.0000 [-0.0000, 0.0000] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |
| flow added to JA3 (B_JA3→D_JA3_FLOW) | 11026 | 1.0000 | 1.0000 | -0.0000 [-0.0002, 0.0000] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |
| flow added to JA4 (C_JA4→E_JA4_FLOW) | 11026 | 1.0000 | 1.0000 | -0.0000 [-0.0002, 0.0000] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |

Per-capture flagged rate at the validation-selected FPR≤1% threshold (primary model random_forest; benign rows = false-positive rate, malicious rows = detection rate):

| Capture | Class | A_FLOW | C_JA4 | D_JA3_FLOW | E_JA4_FLOW |
|---|---|---|---|---|---|
| DS009-CTU-MCB-238-1 | MAL | 50.6% (n=4000) | 100.0% (n=1700) | 100.0% (n=1700) | 100.0% (n=1700) |
| DS009-CTU-MCB-240-1 | MAL | 49.6% (n=4000) | 100.0% (n=1725) | 100.0% (n=1725) | 100.0% (n=1725) |
| DS009-CTU-MCB-246-1 | MAL | 39.0% (n=4000) | 100.0% (n=1353) | 100.0% (n=1353) | 100.0% (n=1353) |
| DS009-CTU-MCB-248-1 | MAL | 52.7% (n=4000) | 100.0% (n=1494) | 100.0% (n=1494) | 100.0% (n=1494) |
| DS009-CTU-MCB-249-1 | MAL | 71.2% (n=4000) | 100.0% (n=1238) | 100.0% (n=1238) | 100.0% (n=1238) |
| DS009-CTU-MCB-259-1 | MAL | 100.0% (n=4000) | — | — | — |
| DS009-CTU-MCB-260-1 | MAL | 54.0% (n=4000) | 100.0% (n=887) | 100.0% (n=887) | 100.0% (n=887) |
| DS009-CTU-MCB-264-1 | MAL | 40.4% (n=4000) | — | — | — |
| DS009-CTU-MCB-268-1 | MAL | 0.0% (n=4000) | — | — | — |
| DS011-CTU-Normal-20 | BEN | 0.0% (n=4000) | 0.0% (n=370) | 0.3% (n=370) | 1.1% (n=370) |
| DS011-CTU-Normal-21 | BEN | 33.4% (n=4000) | 0.0% (n=483) | 83.2% (n=483) | 70.4% (n=483) |
| DS011-CTU-Normal-23 | BEN | 0.0% (n=4000) | 0.0% (n=497) | 0.0% (n=497) | 0.0% (n=497) |
| DS011-CTU-Normal-24 | BEN | 0.0% (n=4000) | 0.0% (n=423) | 0.0% (n=423) | 0.0% (n=423) |
| DS011-CTU-Normal-26 | BEN | 0.0% (n=4000) | 0.0% (n=297) | 0.0% (n=297) | 0.0% (n=297) |
| DS011-CTU-Normal-28 | BEN | 0.2% (n=4000) | 0.0% (n=559) | 0.0% (n=559) | 0.0% (n=559) |

### pooled_capture_cv — `pooled_capture_cv-20261016T164118Z`

Seed 42; evaluation population {'per_capture_cap': 4000, 'rows': 62543, 'rows_by_dataset': {'DS-008': 2543, 'DS-009': 36000, 'DS-011': 24000}, 'positives': 38543, 'negatives': 24000, 'captures': 25}

| Track | Model | Enc. | Status | Pos/Neg | AP [95% CI] (status) | ROC-AUC | Recall @ val-FPR≤1% | Test FPR | ECE | Brier |
|---|---|---|---|---|---|---|---|---|---|---|
| A_FLOW | dummy_prior | onehot | COMPLETED | 38543/24000 | 0.600 [0.433, 0.834] (FEW_GROUPS) | 0.463 | 0.0% | 0.0% | 0.069 | 0.243 |
| A_FLOW | logreg | onehot | COMPLETED | 38543/24000 | 0.875 [0.762, 0.954] (FEW_GROUPS) | 0.872 | 6.8% | 1.7% | 0.098 | 0.143 |
| A_FLOW | random_forest | onehot | COMPLETED | 38543/24000 | 0.931 [0.797, 0.986] (FEW_GROUPS) | 0.909 | 49.5% | 5.8% | 0.104 | 0.121 |
| A_FLOW | hist_gb | onehot | COMPLETED | 38543/24000 | 0.898 [0.686, 0.987] (FEW_GROUPS) | 0.886 | 24.8% | 7.8% | 0.123 | 0.135 |
| B_JA3 | dummy_prior | onehot | COMPLETED | 8591/2629 | 0.767 [0.556, 0.923] (FEW_GROUPS) | 0.475 | 0.0% | 0.0% | 0.047 | 0.181 |
| B_JA3 | logreg | onehot | COMPLETED | 8591/2629 | 0.970 [0.863, 1.000] (FEW_GROUPS) | 0.912 | 99.8% | 18.6% | 0.042 | 0.046 |
| B_JA3 | random_forest | onehot | COMPLETED | 8591/2629 | 0.971 [0.868, 1.000] (FEW_GROUPS) | 0.912 | 99.8% | 18.6% | 0.040 | 0.045 |
| B_JA3 | hist_gb | onehot | COMPLETED | 8591/2629 | 0.999 [0.990, 1.000] (FEW_GROUPS) | 0.997 | 98.6% | 18.4% | 0.038 | 0.028 |
| C_JA4 | dummy_prior | onehot | COMPLETED | 8591/2629 | 0.767 [0.556, 0.923] (FEW_GROUPS) | 0.475 | 0.0% | 0.0% | 0.047 | 0.181 |
| C_JA4 | logreg | onehot | COMPLETED | 8591/2629 | 0.999 [0.990, 1.000] (FEW_GROUPS) | 0.997 | 99.3% | 18.4% | 0.045 | 0.047 |
| C_JA4 | random_forest | onehot | COMPLETED | 8591/2629 | 0.993 [0.953, 1.000] (FEW_GROUPS) | 0.978 | 99.4% | 18.4% | 0.041 | 0.045 |
| C_JA4 | hist_gb | onehot | COMPLETED | 8591/2629 | 0.999 [0.991, 1.000] (FEW_GROUPS) | 0.997 | 98.7% | 18.4% | 0.017 | 0.014 |
| D_JA3_FLOW | dummy_prior | onehot | COMPLETED | 8591/2629 | 0.767 [0.556, 0.923] (FEW_GROUPS) | 0.475 | 0.0% | 0.0% | 0.047 | 0.181 |
| D_JA3_FLOW | logreg | onehot | COMPLETED | 8591/2629 | 1.000 [0.999, 1.000] (FEW_GROUPS) | 0.999 | 99.6% | 1.9% | 0.003 | 0.004 |
| D_JA3_FLOW | random_forest | onehot | COMPLETED | 8591/2629 | 0.988 [0.931, 1.000] (FEW_GROUPS) | 0.971 | 99.5% | 17.4% | 0.021 | 0.023 |
| D_JA3_FLOW | hist_gb | onehot | COMPLETED | 8591/2629 | 0.995 [0.963, 1.000] (FEW_GROUPS) | 0.989 | 99.5% | 10.1% | 0.008 | 0.009 |
| E_JA4_FLOW | dummy_prior | onehot | COMPLETED | 8591/2629 | 0.767 [0.556, 0.923] (FEW_GROUPS) | 0.475 | 0.0% | 0.0% | 0.047 | 0.181 |
| E_JA4_FLOW | logreg | onehot | COMPLETED | 8591/2629 | 1.000 [0.999, 1.000] (FEW_GROUPS) | 0.999 | 99.6% | 1.2% | 0.002 | 0.004 |
| E_JA4_FLOW | random_forest | onehot | COMPLETED | 8591/2629 | 0.990 [0.944, 1.000] (FEW_GROUPS) | 0.976 | 99.6% | 12.1% | 0.018 | 0.022 |
| E_JA4_FLOW | hist_gb | onehot | COMPLETED | 8591/2629 | 0.995 [0.963, 1.000] (FEW_GROUPS) | 0.989 | 99.5% | 10.1% | 0.008 | 0.009 |
| A_FLOW@JA3POP | dummy_prior | onehot | COMPLETED | 8591/2629 | 0.767 [0.556, 0.923] (FEW_GROUPS) | 0.475 | 0.0% | 0.0% | 0.047 | 0.181 |
| A_FLOW@JA3POP | logreg | onehot | COMPLETED | 8591/2629 | 0.999 [0.994, 1.000] (FEW_GROUPS) | 0.998 | 99.6% | 1.4% | 0.003 | 0.005 |
| A_FLOW@JA3POP | random_forest | onehot | COMPLETED | 8591/2629 | 0.990 [0.946, 1.000] (FEW_GROUPS) | 0.976 | 99.5% | 12.2% | 0.018 | 0.022 |
| A_FLOW@JA3POP | hist_gb | onehot | COMPLETED | 8591/2629 | 0.983 [0.909, 1.000] (FEW_GROUPS) | 0.969 | 99.5% | 12.1% | 0.005 | 0.016 |
| A_FLOW@JA4POP | dummy_prior | onehot | COMPLETED | 8591/2629 | 0.767 [0.556, 0.923] (FEW_GROUPS) | 0.475 | 0.0% | 0.0% | 0.047 | 0.181 |
| A_FLOW@JA4POP | logreg | onehot | COMPLETED | 8591/2629 | 0.999 [0.994, 1.000] (FEW_GROUPS) | 0.998 | 99.6% | 1.4% | 0.003 | 0.005 |
| A_FLOW@JA4POP | random_forest | onehot | COMPLETED | 8591/2629 | 0.990 [0.946, 1.000] (FEW_GROUPS) | 0.976 | 99.5% | 12.2% | 0.018 | 0.022 |
| A_FLOW@JA4POP | hist_gb | onehot | COMPLETED | 8591/2629 | 0.983 [0.909, 1.000] (FEW_GROUPS) | 0.969 | 99.5% | 12.1% | 0.005 | 0.016 |
| A0_FLOW_STRICT | dummy_prior | onehot | COMPLETED | 38543/24000 | 0.600 [0.433, 0.834] (FEW_GROUPS) | 0.463 | 0.0% | 0.0% | 0.069 | 0.243 |
| A0_FLOW_STRICT | logreg | onehot | COMPLETED | 38543/24000 | 0.861 [0.746, 0.939] (FEW_GROUPS) | 0.860 | 3.7% | 1.8% | 0.100 | 0.146 |
| A0_FLOW_STRICT | random_forest | onehot | COMPLETED | 38543/24000 | 0.929 [0.793, 0.984] (FEW_GROUPS) | 0.909 | 42.5% | 6.1% | 0.095 | 0.120 |
| A0_FLOW_STRICT | hist_gb | onehot | COMPLETED | 38543/24000 | 0.876 [0.635, 0.987] (FEW_GROUPS) | 0.867 | 23.3% | 11.6% | 0.098 | 0.126 |
| P_AVAILABILITY_PROBE | dummy_prior | onehot | COMPLETED | 38543/24000 | 0.600 [0.433, 0.834] (FEW_GROUPS) | 0.463 | 0.0% | 0.0% | 0.069 | 0.243 |
| P_AVAILABILITY_PROBE | logreg | onehot | COMPLETED | 38543/24000 | 0.765 [0.628, 0.897] (FEW_GROUPS) | 0.649 | 24.2% | 0.1% | 0.051 | 0.205 |
| P_AVAILABILITY_PROBE | random_forest | onehot | COMPLETED | 38543/24000 | 0.765 [0.628, 0.897] (FEW_GROUPS) | 0.649 | 24.2% | 0.1% | 0.049 | 0.205 |
| P_AVAILABILITY_PROBE | hist_gb | onehot | COMPLETED | 38543/24000 | 0.765 [0.628, 0.897] (FEW_GROUPS) | 0.648 | 24.2% | 0.2% | 0.050 | 0.205 |

Paired contrasts (logreg; Holm over 4 pre-declared contrasts):

| Contrast | Shared rows | AP A | AP B | ΔAP [95% CI] | Holm p | Interpretation |
|---|---|---|---|---|---|---|
| JA3 added to flow (A_FLOW@JA3POP→D_JA3_FLOW) | 11220 | 0.9994 | 0.9998 | 0.0004 [0.0000, 0.0053] | 0.0320 | AP higher for B than A (Holm-adjusted); exploratory, source-confounded data |
| JA4 added to flow (A_FLOW@JA4POP→E_JA4_FLOW) | 11220 | 0.9994 | 0.9999 | 0.0005 [0.0000, 0.0054] | 0.0420 | AP higher for B than A (Holm-adjusted); exploratory, source-confounded data |
| flow added to JA3 (B_JA3→D_JA3_FLOW) | 11220 | 0.9703 | 0.9998 | 0.0295 [-0.0004, 0.1356] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |
| flow added to JA4 (C_JA4→E_JA4_FLOW) | 11220 | 0.9989 | 0.9999 | 0.0010 [-0.0003, 0.0093] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |

Paired contrasts (random_forest; Holm over 4 pre-declared contrasts):

| Contrast | Shared rows | AP A | AP B | ΔAP [95% CI] | Holm p | Interpretation |
|---|---|---|---|---|---|---|
| JA3 added to flow (A_FLOW@JA3POP→D_JA3_FLOW) | 11220 | 0.9904 | 0.9881 | -0.0023 [-0.0152, 0.0000] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |
| JA4 added to flow (A_FLOW@JA4POP→E_JA4_FLOW) | 11220 | 0.9904 | 0.9905 | 0.0001 [-0.0030, 0.0012] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |
| flow added to JA3 (B_JA3→D_JA3_FLOW) | 11220 | 0.9710 | 0.9881 | 0.0171 [-0.0000, 0.0718] | 0.5200 | No evidence of a difference (this is not evidence of equivalence) |
| flow added to JA4 (C_JA4→E_JA4_FLOW) | 11220 | 0.9935 | 0.9905 | -0.0030 [-0.0330, 0.0141] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |

Paired contrasts (hist_gb; Holm over 4 pre-declared contrasts):

| Contrast | Shared rows | AP A | AP B | ΔAP [95% CI] | Holm p | Interpretation |
|---|---|---|---|---|---|---|
| JA3 added to flow (A_FLOW@JA3POP→D_JA3_FLOW) | 11220 | 0.9831 | 0.9946 | 0.0115 [-0.0002, 0.0575] | 0.9840 | No evidence of a difference (this is not evidence of equivalence) |
| JA4 added to flow (A_FLOW@JA4POP→E_JA4_FLOW) | 11220 | 0.9831 | 0.9946 | 0.0115 [-0.0002, 0.0575] | 0.9840 | No evidence of a difference (this is not evidence of equivalence) |
| flow added to JA3 (B_JA3→D_JA3_FLOW) | 11220 | 0.9989 | 0.9946 | -0.0044 [-0.0299, 0.0000] | 0.2800 | No evidence of a difference (this is not evidence of equivalence) |
| flow added to JA4 (C_JA4→E_JA4_FLOW) | 11220 | 0.9990 | 0.9946 | -0.0044 [-0.0299, 0.0000] | 0.2800 | No evidence of a difference (this is not evidence of equivalence) |

Per-capture flagged rate at the validation-selected FPR≤1% threshold (primary model random_forest; benign rows = false-positive rate, malicious rows = detection rate):

| Capture | Class | A_FLOW | C_JA4 | D_JA3_FLOW | E_JA4_FLOW |
|---|---|---|---|---|---|
| DS008-C001 | MAL | 0.9% (n=1380) | 100.0% (n=45) | 64.4% (n=45) | 73.3% (n=45) |
| DS008-C002 | MAL | 0.0% (n=74) | 100.0% (n=17) | 94.1% (n=17) | 100.0% (n=17) |
| DS008-C003 | MAL | 1.6% (n=258) | 40.0% (n=50) | 82.0% (n=50) | 86.0% (n=50) |
| DS008-C004 | MAL | 0.0% (n=9) | 100.0% (n=2) | 100.0% (n=2) | 100.0% (n=2) |
| DS008-C005 | MAL | 0.0% (n=20) | 0.0% (n=8) | 50.0% (n=8) | 50.0% (n=8) |
| DS008-C006 | MAL | 18.5% (n=27) | 100.0% (n=6) | 0.0% (n=6) | 0.0% (n=6) |
| DS008-C007 | MAL | 12.1% (n=423) | 0.0% (n=10) | 30.0% (n=10) | 30.0% (n=10) |
| DS008-C008 | MAL | 37.5% (n=16) | 100.0% (n=2) | 100.0% (n=2) | 100.0% (n=2) |
| DS008-C009 | MAL | 35.0% (n=214) | 100.0% (n=51) | 100.0% (n=51) | 100.0% (n=51) |
| DS008-C010 | MAL | 13.9% (n=122) | 100.0% (n=3) | 100.0% (n=3) | 100.0% (n=3) |
| DS009-CTU-MCB-238-1 | MAL | 38.8% (n=4000) | 100.0% (n=1700) | 100.0% (n=1700) | 100.0% (n=1700) |
| DS009-CTU-MCB-240-1 | MAL | 41.4% (n=4000) | 100.0% (n=1725) | 100.0% (n=1725) | 100.0% (n=1725) |
| DS009-CTU-MCB-246-1 | MAL | 48.3% (n=4000) | 100.0% (n=1353) | 100.0% (n=1353) | 100.0% (n=1353) |
| DS009-CTU-MCB-248-1 | MAL | 77.4% (n=4000) | 100.0% (n=1494) | 100.0% (n=1494) | 100.0% (n=1494) |
| DS009-CTU-MCB-249-1 | MAL | 69.6% (n=4000) | 100.0% (n=1238) | 100.0% (n=1238) | 100.0% (n=1238) |
| DS009-CTU-MCB-259-1 | MAL | 100.0% (n=4000) | — | — | — |
| DS009-CTU-MCB-260-1 | MAL | 53.9% (n=4000) | 100.0% (n=887) | 100.0% (n=887) | 99.9% (n=887) |
| DS009-CTU-MCB-264-1 | MAL | 23.8% (n=4000) | — | — | — |
| DS009-CTU-MCB-268-1 | MAL | 19.3% (n=4000) | — | — | — |
| DS011-CTU-Normal-20 | BEN | 0.0% (n=4000) | 0.0% (n=370) | 0.0% (n=370) | 0.0% (n=370) |
| DS011-CTU-Normal-21 | BEN | 34.4% (n=4000) | 100.0% (n=483) | 94.8% (n=483) | 65.8% (n=483) |
| DS011-CTU-Normal-23 | BEN | 0.1% (n=4000) | 0.4% (n=497) | 0.0% (n=497) | 0.0% (n=497) |
| DS011-CTU-Normal-24 | BEN | 0.1% (n=4000) | 0.0% (n=423) | 0.0% (n=423) | 0.0% (n=423) |
| DS011-CTU-Normal-26 | BEN | 0.0% (n=4000) | 0.0% (n=297) | 0.0% (n=297) | 0.0% (n=297) |
| DS011-CTU-Normal-28 | BEN | 0.2% (n=4000) | 0.0% (n=559) | 0.0% (n=559) | 0.0% (n=559) |

### source_identifiability — `source_identifiability-20261016T181509Z`

Seed 42; evaluation population {'per_capture_cap': 4000, 'rows': 38543, 'rows_by_dataset': {'DS-008': 2543, 'DS-009': 36000}, 'positives': 2543, 'negatives': 36000, 'captures': 19}

| Track | Model | Enc. | Status | Pos/Neg | AP [95% CI] (status) | ROC-AUC | Recall @ val-FPR≤1% | Test FPR | ECE | Brier |
|---|---|---|---|---|---|---|---|---|---|---|
| A_FLOW | random_forest | onehot | COMPLETED | 2543/36000 | 0.141 [0.090, 0.298] (FEW_GROUPS) | 0.704 | 4.2% | 0.2% | 0.058 | 0.063 |
| C_JA4 | random_forest | onehot | COMPLETED | 194/8397 | 1.000 [1.000, 1.000] (FEW_GROUPS) | 1.000 | 100.0% | 0.0% | 0.000 | 0.000 |
| E_JA4_FLOW | random_forest | onehot | COMPLETED | 194/8397 | 0.828 [0.581, 1.000] (FEW_GROUPS) | 0.895 | 70.6% | 0.0% | 0.007 | 0.007 |

Per-capture flagged rate at the validation-selected FPR≤1% threshold (primary model random_forest; benign rows = false-positive rate, malicious rows = detection rate):

| Capture | Class | A_FLOW | C_JA4 | E_JA4_FLOW |
|---|---|---|---|---|
| DS008-C001 | MAL | 2.5% (n=1380) | 100.0% (n=45) | 97.8% (n=45) |
| DS008-C002 | MAL | 9.5% (n=74) | 100.0% (n=17) | 88.2% (n=17) |
| DS008-C003 | MAL | 3.5% (n=258) | 100.0% (n=50) | 58.0% (n=50) |
| DS008-C004 | MAL | 33.3% (n=9) | 100.0% (n=2) | 100.0% (n=2) |
| DS008-C005 | MAL | 25.0% (n=20) | 100.0% (n=8) | 100.0% (n=8) |
| DS008-C006 | MAL | 29.6% (n=27) | 100.0% (n=6) | 100.0% (n=6) |
| DS008-C007 | MAL | 2.8% (n=423) | 100.0% (n=10) | 100.0% (n=10) |
| DS008-C008 | MAL | 0.0% (n=16) | 100.0% (n=2) | 100.0% (n=2) |
| DS008-C009 | MAL | 10.3% (n=214) | 100.0% (n=51) | 35.3% (n=51) |
| DS008-C010 | MAL | 4.9% (n=122) | 100.0% (n=3) | 100.0% (n=3) |
| DS009-CTU-MCB-238-1 | BEN | 0.0% (n=4000) | 0.0% (n=1700) | 0.0% (n=1700) |
| DS009-CTU-MCB-240-1 | BEN | 0.4% (n=4000) | 0.0% (n=1725) | 0.0% (n=1725) |
| DS009-CTU-MCB-246-1 | BEN | 0.0% (n=4000) | 0.0% (n=1353) | 0.2% (n=1353) |
| DS009-CTU-MCB-248-1 | BEN | 0.1% (n=4000) | 0.0% (n=1494) | 0.0% (n=1494) |
| DS009-CTU-MCB-249-1 | BEN | 0.1% (n=4000) | 0.0% (n=1238) | 0.0% (n=1238) |
| DS009-CTU-MCB-259-1 | BEN | 0.0% (n=4000) | — | — |
| DS009-CTU-MCB-260-1 | BEN | 0.0% (n=4000) | 0.0% (n=887) | 0.0% (n=887) |
| DS009-CTU-MCB-264-1 | BEN | 1.5% (n=4000) | — | — |
| DS009-CTU-MCB-268-1 | BEN | 0.1% (n=4000) | — | — |

### sequence_capture_cv — `sequence_capture_cv-20261016T185120Z`

Seed 42; evaluation population None


| Model | AP | AP CI | Recall @ val-FPR≤1% | Test FPR | mean fit s | params |
|---|---|---|---|---|---|---|
| tab_trackA_hist_gb | 0.886 | [0.692, 0.983] FEW_GROUPS | 31.7% | 8.4% | 7.4 | None |
| tab_trackA_random_forest | 0.904 | [0.730, 0.984] FEW_GROUPS | 36.2% | 6.3% | 0.8 | None |
| seqagg_logreg | 0.840 | [0.629, 0.954] FEW_GROUPS | 38.3% | 11.4% | 0.1 | None |
| seqagg_hist_gb | 0.909 | [0.759, 0.973] FEW_GROUPS | 41.9% | 4.8% | 1.2 | None |
| cnn | 0.871 | [0.662, 0.979] FEW_GROUPS | 38.9% | 6.9% | 7.0 | 15937 |
| gru | 0.828 | [0.603, 0.972] FEW_GROUPS | 40.8% | 12.0% | 24.1 | 8545 |

Sequence vs tabular contrasts:

| Contrast | Shared rows | AP A | AP B | ΔAP [95% CI] | Holm p | Interpretation |
|---|---|---|---|---|---|---|
| CNN vs information-matched tabular (seqagg_hist_gb→cnn) | 62543 | 0.9094 | 0.8706 | -0.0387 [-0.1181, 0.0296] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |
| GRU vs information-matched tabular (seqagg_hist_gb→gru) | 62543 | 0.9094 | 0.8276 | -0.0818 [-0.1712, 0.0114] | 0.5880 | No evidence of a difference (this is not evidence of equivalence) |
| CNN vs full-flow tabular (tab_trackA_hist_gb→cnn) | 62543 | 0.8860 | 0.8706 | -0.0154 [-0.0597, 0.0292] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |
| GRU vs full-flow tabular (tab_trackA_hist_gb→gru) | 62543 | 0.8860 | 0.8276 | -0.0584 [-0.1045, -0.0060] | 0.0240 | AP lower for B than A (Holm-adjusted); exploratory, source-confounded data |

### sequence_capture_cv_DS009_DS011 — `sequence_capture_cv_DS009_DS011-20261016T190417Z`

Seed 42; evaluation population None


| Model | AP | AP CI | Recall @ val-FPR≤1% | Test FPR | mean fit s | params |
|---|---|---|---|---|---|---|
| tab_trackA_hist_gb | 0.926 | [0.869, 0.972] FEW_GROUPS | 80.7% | 19.6% | 7.9 | None |
| tab_trackA_random_forest | 0.942 | [0.885, 0.978] FEW_GROUPS | 87.7% | 25.2% | 0.7 | None |
| seqagg_logreg | 0.857 | [0.748, 0.940] FEW_GROUPS | 66.0% | 12.3% | 0.1 | None |
| seqagg_hist_gb | 0.896 | [0.806, 0.963] FEW_GROUPS | 64.1% | 8.1% | 1.0 | None |
| cnn | 0.893 | [0.780, 0.971] FEW_GROUPS | 70.5% | 14.2% | 13.9 | 15937 |
| gru | 0.871 | [0.736, 0.964] FEW_GROUPS | 84.9% | 20.3% | 41.7 | 8545 |

Sequence vs tabular contrasts:

| Contrast | Shared rows | AP A | AP B | ΔAP [95% CI] | Holm p | Interpretation |
|---|---|---|---|---|---|---|
| CNN vs information-matched tabular (seqagg_hist_gb→cnn) | 60000 | 0.8961 | 0.8930 | -0.0031 [-0.0684, 0.0640] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |
| GRU vs information-matched tabular (seqagg_hist_gb→gru) | 60000 | 0.8961 | 0.8714 | -0.0247 [-0.1036, 0.0490] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |
| CNN vs full-flow tabular (tab_trackA_hist_gb→cnn) | 60000 | 0.9257 | 0.8930 | -0.0327 [-0.1136, 0.0114] | 1.0000 | No evidence of a difference (this is not evidence of equivalence) |
| GRU vs full-flow tabular (tab_trackA_hist_gb→gru) | 60000 | 0.9257 | 0.8714 | -0.0543 [-0.1630, 0.0141] | 0.9040 | No evidence of a difference (this is not evidence of equivalence) |

## Claim ledger

| ID | Claim | Status | Evidence |
|---|---|---|---|
| C01 | Corpus v3 reproduces the Stage 6.5 DS-008 flow, JA3 and JA4 counts from checksum-verified inputs. | **SUPPORTED** | expected {'flows': 2543, 'ja3': 194, 'ja4': 194} (Stage 6.5 audit minus 6 DS-004 rows), observed {'flows': 2543, 'ja3': 194, 'ja4': 194}; 10/10 DS-008 PCAPs SHA-256 verified. |
| C02 | The admitted benign corpus is sufficient to investigate generalisation (sufficiency level C). | **BLOCKED** | Levels met: {'A_pipeline': True, 'B_preliminary': True, 'C_generalization': False, 'D_publication': False}; failing C checks: ['sources_per_class', 'captures_per_class', 'tls13_in_both_classes', 'environments_per_class'] |
| C03 | JA3 and JA4 values observed in the corpus never occur in both classes. | **SUPPORTED** | JA3 shared 0/90, JA4 shared 0/82. |
| C04 | Adding JA3 to flow features increases average precision on the shared JA3 population (A@JA3POP -> D). | **INSUFFICIENT_EVIDENCE** | pooled: dAP=-0.0023 CI[-0.01517338629370188, 5.510382078866004e-06] (FEW_GROUPS) Holm p=1.0; matched_lab: dAP=0.0000 CI[-2.220446049250313e-16, 2.220446049250313e-16] (FEW_GROUPS) Holm p=1.0 (primary model random_forest, capture-grouped 5-fold, capture bootstrap). Secondary models (sensitivity, not used for the status): pooled logreg: dAP=+0.0004, Holm p within model 0.032, across 12 model x contrast tests 0.096; pooled hist_gb: dAP=+0.0115, Holm p within model 0.984, across 12 model x contrast tests 1.0; matched logreg: dAP=+0.0002, Holm p within model 1.0, across 12 model x contrast tests 1.0; matched hist_gb: dAP=+0.0000, Holm p within model 1.0, across 12 model x contrast tests 1.0 |
| C05 | Adding JA4 to flow features increases average precision on the shared JA4 population (A@JA4POP -> E). | **INSUFFICIENT_EVIDENCE** | pooled: dAP=0.0001 CI[-0.0030099017683952174, 0.0011921853730267658] (FEW_GROUPS) Holm p=1.0; matched_lab: dAP=0.0000 CI[-2.220446049250313e-16, 2.220446049250313e-16] (FEW_GROUPS) Holm p=1.0 (primary model random_forest, capture-grouped 5-fold, capture bootstrap). Secondary models (sensitivity, not used for the status): pooled logreg: dAP=+0.0005, Holm p within model 0.042, across 12 model x contrast tests 0.154; pooled hist_gb: dAP=+0.0115, Holm p within model 0.984, across 12 model x contrast tests 1.0; matched logreg: dAP=+0.0002, Holm p within model 1.0, across 12 model x contrast tests 1.0; matched hist_gb: dAP=+0.0000, Holm p within model 1.0, across 12 model x contrast tests 1.0 |
| C06 | Adding flow features to JA3 increases average precision (B -> D). | **INSUFFICIENT_EVIDENCE** | pooled: dAP=0.0171 CI[-4.9410618678719356e-05, 0.07177036033099671] (FEW_GROUPS) Holm p=0.52; matched_lab: dAP=0.0000 CI[-2.220446049250313e-16, 2.220446049250313e-16] (FEW_GROUPS) Holm p=1.0 (primary model random_forest, capture-grouped 5-fold, capture bootstrap). Secondary models (sensitivity, not used for the status): pooled logreg: dAP=+0.0295, Holm p within model 1.0, across 12 model x contrast tests 1.0; pooled hist_gb: dAP=-0.0044, Holm p within model 0.28, across 12 model x contrast tests 0.7; matched logreg: dAP=-0.0006, Holm p within model 1.0, across 12 model x contrast tests 1.0; matched hist_gb: dAP=-0.0000, Holm p within model 1.0, across 12 model x contrast tests 1.0 |
| C07 | Adding flow features to JA4 increases average precision (C -> E). | **INSUFFICIENT_EVIDENCE** | pooled: dAP=-0.0030 CI[-0.03304864190292077, 0.01409634982502877] (FEW_GROUPS) Holm p=1.0; matched_lab: dAP=0.0000 CI[-2.220446049250313e-16, 2.220446049250313e-16] (FEW_GROUPS) Holm p=1.0 (primary model random_forest, capture-grouped 5-fold, capture bootstrap). Secondary models (sensitivity, not used for the status): pooled logreg: dAP=+0.0010, Holm p within model 1.0, across 12 model x contrast tests 1.0; pooled hist_gb: dAP=-0.0044, Holm p within model 0.28, across 12 model x contrast tests 0.828; matched logreg: dAP=-0.0006, Holm p within model 1.0, across 12 model x contrast tests 1.0; matched hist_gb: dAP=-0.0000, Holm p within model 1.0, across 12 model x contrast tests 1.0 |
| C08A | Flow-only detectors (A_FLOW) transfer to a held-out malicious source at the validation-selected FPR<=1% threshold. | **CONTRADICTED** | Detection rates on the held-out source (random_forest): {'A_FLOW|DS-008': 0.0378, 'A_FLOW|DS-009': 0.1528}. Rule: all >= 0.8 -> PRELIMINARY; all <= 0.5 -> CONTRADICTED; otherwise INSUFFICIENT_EVIDENCE. The benign false-positive rate on a held-out benign source cannot be measured (single benign source). |
| C08B | Fingerprint-only detectors (B_JA3, C_JA4) transfer to a held-out malicious source at the validation-selected FPR<=1% threshold. | **INSUFFICIENT_EVIDENCE** | Detection rates on the held-out source (random_forest): {'B_JA3|DS-008': 0.0, 'B_JA3|DS-009': 1.0, 'C_JA4|DS-008': 0.0, 'C_JA4|DS-009': 1.0}. Rule: all >= 0.8 -> PRELIMINARY; all <= 0.5 -> CONTRADICTED; otherwise INSUFFICIENT_EVIDENCE. The benign false-positive rate on a held-out benign source cannot be measured (single benign source). |
| C08C | Fusion detectors (D_JA3_FLOW, E_JA4_FLOW) transfer to a held-out malicious source at the validation-selected FPR<=1% threshold. | **CONTRADICTED** | Detection rates on the held-out source (random_forest): {'D_JA3_FLOW|DS-008': 0.2887, 'D_JA3_FLOW|DS-009': 0.0343, 'E_JA4_FLOW|DS-008': 0.3505, 'E_JA4_FLOW|DS-009': 0.2622}. Rule: all >= 0.8 -> PRELIMINARY; all <= 0.5 -> CONTRADICTED; otherwise INSUFFICIENT_EVIDENCE. The benign false-positive rate on a held-out benign source cannot be measured (single benign source). |
| C09 | ETTH detection generalises to independent, unseen benign and malicious environments. | **BLOCKED** | Confirmatory evaluation requires an independent benign+malicious source never used in exploration; none is admitted. |
| C10 | Handshake-availability flags alone (no flow statistics, no fingerprints) carry label information beyond prevalence. | **PRELIMINARY** | Probe AP 0.765 CI[0.6281478572865119, 0.8974957040038879] vs prevalence AP 0.6004526946837638; lift 0.164. |
| C11 | Flow features identify which malicious source (DS-008 vs DS-009) a flow came from. | **INSUFFICIENT_EVIDENCE** | Source-identification AP 0.14055969331542695 CI[0.09039419459127196, 0.29780365638455647] (FEW_GROUPS); chance level (prevalence of DS-008 rows) 0.066; rule: CI lower bound > 2x prevalence. |
| C11B | JA4 alone identifies which malicious source (DS-008 vs DS-009) a TLS flow came from. | **PRELIMINARY** | Source-identification AP 1.0 CI[1.0, 1.0]; chance 0.023. |
| C16 | Fingerprint-only models flag most benign flows whose fingerprint was absent from the training fold. | **PRELIMINARY** | Benign unseen-fingerprint share 0.188; flagged at val-FPR<=1%: JA3 unseen 0.9878542510121457, JA3 seen 0.0, JA4 unseen 0.9817813765182186 (logreg, pooled capture-grouped CV). |
| C17 | Flow-only (A_FLOW) ranking quality drops when whole malware families are held out. | **PRELIMINARY** | family-holdout AP 0.7104 CI[0.4561341726113884, 0.9621963561747593] vs capture-grouped AP 0.9308 (random_forest). |
| C12 | The legacy behavioural-hash holdout gives a higher A_FLOW estimate than capture-grouped CV. | **PRELIMINARY** | legacy AP 0.9915 vs capture-grouped AP 0.9308 (random_forest). |
| C13 | Sequence models (CNN/GRU on the first 64 packets) add detection value over information-matched tabular baselines. | **INSUFFICIENT_EVIDENCE** | CNN vs information-matched tabular: dAP=-0.03874886260086374 CI[-0.11807196497400115, 0.02963821398066941] Holm p=1.0; GRU vs information-matched tabular: dAP=-0.08175806216013604 CI[-0.17120298769547032, 0.0114348453216355] Holm p=0.5880000000000001; CNN vs full-flow tabular: dAP=-0.01535365930849275 CI[-0.059678621744575715, 0.029155460987728136] Holm p=1.0; GRU vs full-flow tabular: dAP=-0.058362858867765044 CI[-0.10453033573535651, -0.005980278419421004] Holm p=0.024 |
| C14 | Real-time inference only uses registered, checksum-verified models and never derives a score from ground-truth labels. | **SUPPORTED** | Enforced in backend/inference_engine.py; verified by tests/test_model_registry_inference.py (test_no_model_means_skipped_never_label_echo, test_label_field_never_influences_score, test_incompatible_schema_rejected_without_invention). |
| C15 | The system does not decrypt TLS application payloads. | **SUPPORTED** | Only TLS handshake records (ClientHello/ServerHello) in the first segment are parsed; packet payloads are otherwise reduced to sizes, timings, directions and TCP flags. No key material, interception or decryption code exists (pipeline/tls_fingerprinting.py, backend/event_sources/live_capture.py). The Zeek, Suricata and eBPF adapters read only metadata fields logged by those tools (backend/event_sources/{zeek,suricata,ebpf}_source.py). |
| C18 | The Zeek, Suricata and eBPF adapters normalise records into the canonical flow contract without fabricating fingerprints, endpoints, protocols, durations or rates, and without silently dropping, duplicating or relabelling records. | **SUPPORTED** | pipeline/canonical_flow.py; tests/test_canonical_flow.py, tests/test_sensors_zeek.py, tests/test_sensors_suricata.py, tests/test_sensors_ebpf.py (placeholder fingerprints rejected, negotiated TLS version / selected ALPN kept apart from ETTH features, expiry and overflow emit instead of drop, duplicates and late records counted). |
| C19 | Models trained on ETTH packet features and ETTH JA4 refuse sensor-aggregate statistics and FoxIO JA4 instead of scoring them. | **SUPPORTED** | backend/inference_engine.py provenance and JA4-implementation rules; tests/test_inference_contract.py (FoxIO reference ClientHello: ETTH JA4 t13d1516h2_8daaf6152771_0adf69b4533f vs FoxIO ..._e5627efa2ab1) and tests/test_cross_phase_integration.py (all five tracks on sensor fixtures). |
| C20 | Live capture produces the same flows (boundaries, initiator direction) and the same flow and TLS feature values as the offline PCAP pipeline for the same packets. | **SUPPORTED** | tests/test_live_offline_parity.py: synthetic packets written to a PCAP give identical flows and FLOW features (rel/abs 1e-9) through pipeline.flow_reconstruction and LiveCaptureSource. |
| C21 | ETTH detection models can score flows observed by Zeek, Suricata or eBPF sensors. | **BLOCKED** | No model is trained on sensor-observable features with sensor provenance, and no labelled sensor telemetry is available. Under the current contract only the JA3-only track accepts sensor flows, and those JA3 values are mostly outside the training vocabulary (UNSEEN_CATEGORY). |

## Model registry

- etth-a_flow-random_forest v1 (A_FLOW, random_forest): ACTIVE, RESEARCH_PILOT_SOURCE_CONFOUNDED, calibration PLATT_ON_INNER_CAPTURE_OOF, thresholds {'fpr<=0.01': 0.9728110093782477, 'fpr<=0.05': 0.9052496856533704}
- etth-b_ja3-random_forest v1 (B_JA3, random_forest): ACTIVE, RESEARCH_PILOT_SOURCE_CONFOUNDED, calibration PLATT_ON_INNER_CAPTURE_OOF, thresholds {'fpr<=0.01': 0.3174761120365442, 'fpr<=0.05': 0.3174761120365442}
- etth-c_ja4-random_forest v1 (C_JA4, random_forest): ACTIVE, RESEARCH_PILOT_SOURCE_CONFOUNDED, calibration PLATT_ON_INNER_CAPTURE_OOF, thresholds {'fpr<=0.01': 0.2729353067382673, 'fpr<=0.05': 0.2729353067382673}
- etth-d_ja3_flow-random_forest v1 (D_JA3_FLOW, random_forest): ACTIVE, RESEARCH_PILOT_SOURCE_CONFOUNDED, calibration PLATT_ON_INNER_CAPTURE_OOF, thresholds {'fpr<=0.01': 0.9425702159306136, 'fpr<=0.05': 0.6940088166394474}
- etth-e_ja4_flow-random_forest v1 (E_JA4_FLOW, random_forest): ACTIVE, RESEARCH_PILOT_SOURCE_CONFOUNDED, calibration PLATT_ON_INNER_CAPTURE_OOF, thresholds {'fpr<=0.01': 0.9290371087636209, 'fpr<=0.05': 0.589460196914814}

## Environment

- Python 3.12.0 on Windows-11-10.0.26200-SP0; CPUs 24
- Packages: {'numpy': '2.4.6', 'pandas': '3.0.5', 'sklearn': '1.9.0', 'scipy': '1.18.0', 'pyarrow': '25.0.1', 'torch': '2.13.0+cpu', 'dpkt': '1.9.8'}
- Source revision: c9615c9dc3e63de6d0d07167bc93c71f9c6d4351

## Limitations and negative results

- Every dataset contributes a single class; any classifier can exploit source/environment differences.
- Benign data are 2017 Linux/iceweasel browsing captures; malicious data are Windows hosts (2017 and 2024-2026).
- Labels are capture-level; benign background flows inside malware captures are labelled malicious.
- The ETTH JA4 implementation differs from the FoxIO JA4 specification (e.g. 'n' instead of 'i' for no SNI; TLS version from the presence of supported_versions); values are not comparable with external JA4 databases.
- ClientHellos are parsed from the first TCP segment only (truncation flagged).
- Confidence intervals rest on 6 benign captures per pooled suite and are flagged FEW_GROUPS: they are likely too narrow.

