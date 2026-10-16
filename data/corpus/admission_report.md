# ETTH Corpus Admission Report

Generated: 2026-10-16T16:29:47.369344Z (from `data/corpus/admission_report.json`; all counts computed from data).

## Processing funnel by dataset

| Dataset | Listed | In plan | Present | Verified | PCAP valid | In corpus | Flows | ClientHello | JA3 | JA4 |
|---|---|---|---|---|---|---|---|---|---|---|
| DS-004 | 6 | 6 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| DS-008 | 12 | 10 | 10 | 10 | 10 | 10 | 2543 | 194 | 194 | 194 |
| DS-009 | 9 | 9 | 9 | 9 | 9 | 9 | 447563 | 66612 | 66612 | 66612 |
| DS-011 | 6 | 6 | 6 | 6 | 6 | 6 | 127132 | 13845 | 13845 | 13845 |

## Exclusions

| Capture | Dataset | Stage | Reason |
|---|---|---|---|
| DS004-sample1 | DS-004 | materialize | Raw file not present: data/samples/ds004/sample1.pcap |
| DS004-sample2 | DS-004 | materialize | Raw file not present: data/samples/ds004/sample2.pcap |
| DS004-sample3 | DS-004 | materialize | Raw file not present: data/samples/ds004/sample3.pcap |
| DS004-sample4 | DS-004 | materialize | Raw file not present: data/samples/ds004/sample4.pcap |
| DS004-sample5 | DS-004 | materialize | Raw file not present: data/samples/ds004/sample5.pcap |
| DS004-sample6 | DS-004 | materialize | Raw file not present: data/samples/ds004/sample6.pcap |
| DS008-MTA-C003 | DS-008 | plan | Stage 6.5 decision: Empirical testing failed or no useful TLS/JA4 data |
| DS008-MTA-C039 | DS-008 | plan | Stage 6.5 decision: Only 1 TLS flow; redundant families (XLoader is in baseline, Remcos is in C040) |

## Duplicates (behavioral_hash groups)

- Flows: 577238; behavioural groups: 322014; duplicate groups: 21084
- Flows in duplicate groups: 276308 (rate 0.478673)
- Cross-capture groups: 2312; cross-dataset: 24; cross-label: 24

## Label distribution

- DS-008|MALICIOUS: 2543 flows
- DS-009|MALICIOUS: 447563 flows
- DS-011|BENIGN: 127132 flows

## TLS / fingerprint coverage by binary label

- BENIGN: 127132 flows, ClientHello 13845, JA3 13845 (0.108903), JA4 13845 (0.108903), TLS versions {'nan': 113287, '1.2': 13845}, truncated-ClientHello fingerprints 43
- MALICIOUS: 450106 flows, ClientHello 66806, JA3 66806 (0.148423), JA4 66806 (0.148423), TLS versions {'nan': 383300, '1.2': 66723, '1.3': 83}, truncated-ClientHello fingerprints 14

## Fingerprint overlap between classes

- JA3: {'distinct_values': 90, 'distinct_malicious_only': 46, 'distinct_benign_only': 44, 'distinct_shared': 0, 'flows_with_shared_values': 0}
- JA4: {'distinct_values': 82, 'distinct_malicious_only': 39, 'distinct_benign_only': 43, 'distinct_shared': 0, 'flows_with_shared_values': 0}

## Provenance completeness

Mean fraction of required capture-level fields known: 0.8441

## Known limitations

- Labels are capture-level and propagated to every flow; benign background traffic inside malware captures is labelled MALICIOUS.
- Each dataset contributes exactly one class (DS-008, DS-009 malicious; DS-011, DS-004 benign), so dataset identity and label are perfectly aligned at the source level.
- DS-011 benign traffic is 2017 browser traffic (iceweasel 43 / Firefox-era stacks) to popular sites; it is not representative of enterprise or modern client traffic.
- DS-008 captures are from 2024-2026 while DS-009/DS-011 are from 2017: TLS versions and client stacks differ systematically by year.
- ClientHello parsing uses the first TCP segment only; fingerprints from truncated records are flagged (clienthello_record_truncated).
- DS-004 (CipherSpectrum) is absent from this working copy and is therefore not part of the corpus.
