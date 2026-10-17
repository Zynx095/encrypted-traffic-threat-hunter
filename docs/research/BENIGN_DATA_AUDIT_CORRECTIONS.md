# Corrections to the Independent Benign Dataset Audit

This file reviews `docs/research/INDEPENDENT_BENIGN_DATASET_AUDIT.md`, added in commit 07aba41.

- **Date of check:** 2026-10-17 (Phase 13).
- **Method:** each specific claim was checked against the source pages listed below, or against the repository's own records.
- **Original file:** kept unchanged for provenance, with a banner pointing here. Where the two disagree, this file applies.

**Summary:** no candidate in that audit can currently provide independent benign TLS traffic with complete ClientHellos to this project. The benign-data blocker stands.

## 1. Claims that are wrong or unsupported

| # | Claim in the audit | Finding | Status |
|---|---|---|---|
| 1 | CESNET-TLS22 is at `https://zenodo.org/record/7113110` | That record is unrelated software ("Sige_model_subduction_code", Kaneki & Noda, Kyoto University). The CESNET-TLS22 record is a different one, and sources disagree on which (7730770, 7965515 and 10610895 are all cited). | **WRONG** |
| 2 | CESNET-TLS22 has "full ClientHello extension vectors, cipher suites wire order, and ALPN strings", allowing "100% compliant FoxIO JA4 v2" | The dataset paper and the Liberouter page describe packet-metadata sequences and flow statistics, labelled with 191 *services* derived from the TLS SNI. Neither mentions cipher-suite, extension, signature-algorithm or ALPN fields. Without them neither JA3 nor JA4 can be computed. | **UNSUPPORTED** (contradicted by the documented schema) |
| 3 | CESNET-TLS22 provides "benign" traffic | Its labels are service labels, not maliciousness labels. Backbone traffic is not known to be benign, and project rules forbid treating unlabelled traffic as benign. | **INVALID for this purpose** |
| 4 | CESNET-TLS22 is CC BY-NC 4.0, "68.4 % TLS 1.3", "over 40 million TLS flows" | No source located for these numbers. The dataset is described as about 141 million flow records from two weeks of October 2021. The licence was not confirmed. | **UNVERIFIED** |
| 5 | Stratosphere data is "CC BY 4.0", with CTU-Normal-33..40 from 2020–2023, Windows 10/macOS hosts, "54 % TLS 1.2 / 46 % TLS 1.3" | Stratosphere pages give attribution-based terms ("use these files as long as you reference this project and the authors"), not a CC licence. No source was found for the capture list, the years, the operating systems or the TLS split. | **UNVERIFIED / licence misstated** |
| 6 | DS-011 is "entirely … Iceweasel/Firefox … Debian Linux" and "100.0 % TLS 1.2" | The recorded metadata is mixed: 5 of 6 READMEs say Kali Linux, and 3 file names say "win". The TLS-1.2 statement depends on the historical `tls_version` (offered, from `supported_versions` presence). It was not re-derived here. | **OVERSTATED** |
| 7 | "Models trained on JA3/JA4 alone collapse to near-random performance" under source holdout | Leave-one-source-out folds hold out one class only. The persisted report (`leave_one_source_out-20261016T180916Z`) therefore gives a detection rate or a false-positive rate per held-out source, and AP/ROC-AUC are undefined (INSUFFICIENT_GROUPS). "Near-random" is not a quantity those results measure. | **MISCHARACTERISED** |
| 8 | MAWI truncates payloads to 96 bytes | Plausible (MAWI publishes header traces), but not checked here. | **UNVERIFIED** |
| 9 | "Admission status: APPROVED (Target 1/2)" | No dataset was admitted. `data/corpus/dataset_registry.json` was not changed, and no capture was downloaded or verified. | **WRONG** |

## 2. Current status of benign sources

| Source | What it can provide | Can be used here now? | Blocker |
|---|---|---|---|
| DS-011 Stratosphere CTU-Normal (6 captures, 2017) | Raw PCAP, benign by provider label | Already used in every exploratory suite | It cannot act as an independent confirmatory source. |
| Further Stratosphere CTU-Normal captures (for example CTU-Normal-27, -32 directory listings exist on mcfp.felk.cvut.cz) | Raw PCAP under attribution terms | Not evaluated: not downloaded; TLS content, operating systems and dates unknown | Needs download, checksum recording, README review and a TLS-coverage check before any admission decision. |
| CESNET-TLS22 / TLS-Year22 | Flow and packet metadata with SNI-derived service labels | No | No ClientHello fields (no JA3/JA4); no maliciousness labels. |
| CIC datasets (for example CIRA-CIC-DoHBrw-2020) | Raw PCAP | No | Access form and terms of use. Project rules forbid bypassing them. Known generator artefacts would need checking. |
| DS-004 (UNSW) | — | No | Registration required; historical sample checksums are unverifiable. |
| DS-006 | — | No | Licence unresolved. |

## 3. Effect on claims

- **Incremental value:** every claim about incremental fingerprint value stays BLOCKED or INSUFFICIENT_EVIDENCE, because the only benign source is DS-011.
- **No synthetic substitute:** no synthetic, duplicated or relabelled benign traffic was created to fill the gap.

**Next concrete action:** download one or more additional Stratosphere CTU-Normal captures, then:
1. record their SHA-256 hashes and READMEs;
2. measure their TLS ClientHello coverage with `FlowReconstructor(reassemble_tls=True)`;
3. hold them out unseen as a confirmatory benign source, as `CONFIRMATORY_POLICY` in `ml/benchmark/suites.py` requires.

## Sources

- **CESNET-TLS22:** the [Liberouter page](https://www.liberouter.org/datasets/cesnet-tls22/), the [CTU FIT netmon page](https://netmon.fit.cvut.cz/datasets/cesnet-tls22/) and the [Zenodo record 10610895](https://zenodo.org/records/10610895), retrieved 2026-10-17.
- **CESNET-TLS-Year22 paper:** [PMC11489426](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC11489426/).
- **Unrelated Zenodo record cited by the audit:** [Zenodo record 7113110](https://zenodo.org/records/7113110).
- **Stratosphere datasets:** the [datasets overview](https://www.stratosphereips.org/datasets-overview), the [FAQ](https://stratosphereips.org/datasets-faq) and the [CTU-Normal-32 listing](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-32).
