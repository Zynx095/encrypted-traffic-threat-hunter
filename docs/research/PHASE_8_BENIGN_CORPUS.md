# Phase 8: Benign Corpus Acquisition, Provenance and Admission

**Status:** IMPLEMENTED · TESTED · EXECUTED. Independent benign acquisition is only **partially** resolved: one new benign source was admitted, but generalisation-grade sufficiency (level C) is **NOT MET**.
**Code:** `pipeline/corpus/` · **Artefacts:** `data/corpus/` (versioned), `data/processed/v3/` and `data/raw/` (git-ignored)
**Tests:** `tests/test_corpus_registry.py` (16 tests)

## 1. What exists

| Component | Module | Purpose |
|---|---|---|
| Dataset registry | `pipeline/corpus/registry.py` | Records with 35 fields. Unknown facts stay `UNKNOWN`. Lifecycle changes are guarded and evidence-backed. |
| Seed records | `pipeline/corpus/seed.py` | Initial records built only from repository documents or provider pages checked on 2026-10-16 |
| Capture plan | `pipeline/corpus/capture_plan.py` → `data/corpus/capture_plan.json` | One entry per capture session: label derivation, container, expected SHA-256, provenance |
| Safe extraction | `pipeline/corpus/extract.py` | Extracts PCAP members only from ZipCrypto archives. The archive is opened read-only, extracted bytes are checksum-verified, and nothing is overwritten. |
| Artefact manifest | `pipeline/corpus/artifacts.py` → `data/corpus/artifact_manifest.json` | Tracks RAW / INTERIM / PROCESSED files with dataset, capture, checksum, acquisition, processing and verification for each |
| Validation | `pipeline/corpus/validation.py` | PCAP integrity, duplicate files, behavioural-group duplicates, cross-label conflicts, TLS and fingerprint coverage, fingerprint overlap |
| Builder | `pipeline/corpus/builder.py` | Deterministic, resumable corpus v3 build that reuses the Phase 6 reconstruction and feature code unchanged |
| Admission | `pipeline/corpus/admission.py` | Admission report, four-level sufficiency assessment, registry state updates |
| Replay set | `pipeline/corpus/replay_set.py` | Capture-balanced slice (300 flows per capture) for the real-time replay stream |

### 1.1 Lifecycle

`DISCOVERED → ACCESS_PENDING | LICENSE_VERIFIED → ACQUIRED → CONTENT_VERIFIED → PROCESSED → ADMITTED`, plus `REJECTED` and `BLOCKED`.
The full legal-transition table is in `LEGAL_TRANSITIONS`. Guards:

* `ACQUIRED` requires reviewed terms of use (a non-`UNKNOWN` license field).
* `CONTENT_VERIFIED` requires at least one checksum-verified, parseable artefact.
* `PROCESSED` requires a processing record.
* `ADMITTED` requires a reference to an admission report and an explicit decision.
* `REJECTED` requires a reason.

Every transition appends `{from, to, timestamp, evidence, evidence_refs, actor}` to the record's history.

**Admission means "fit for EXPLORATORY research use with the listed limitations".** It is not a representativeness claim.

## 2. Source research (2026-10-16)

| ID | Source | Category | Outcome |
|---|---|---|---|
| DS-004 | CipherSpectrum (UNSW) | ACADEMIC_ACCESS_REQUIRED | Requires a short registration form (no approval step); license CC BY-NC 4.0. The six Phase 6 samples are **absent** from this working copy and their archive member names were never recorded. The form was **not** completed and the directory link was **not** used. State: `ACCESS_PENDING`. |
| DS-006 | Beyond JA4+ / tls-fingerprinting (Brno) | LICENSE_UNCLEAR | PCAPs of 77 desktop/mobile apps appear in a public GitHub repository, but there is no license file. State: `BLOCKED` until the authors grant permission. |
| DS-007 | Annotated Encrypted Network Traffic (Brno) | ACADEMIC_ACCESS_REQUIRED | Justified request needed (reported earlier; canonical URL not re-verified). State: `ACCESS_PENDING`. |
| CAND-006/007/008 | CIC-IDS-2017, CIC-Bell-DNS-EXF-2021, CIRA-CIC-DoHBrw-2020 | ACADEMIC_ACCESS_REQUIRED | CIC download form (PII and license acceptance). State: `ACCESS_PENDING`. |
| **DS-011** | **Stratosphere CTU-Normal-20…32 (HTTPS "normal" captures)** | VERIFIED_AVAILABLE | Direct download, no registration. The MCFP disclaimer reads "free to use these files as long as you reference this project and the authors". **6 of 13 captures acquired** (CTU-Normal-20, 21, 23, 24, 26, 28; 1.36 GB) to bound download size. **ADMITTED** (exploratory). |
| **DS-009** | **Stratosphere MCFP malware captures (2017)** | VERIFIED_AVAILABLE | Same laboratory, period and terms as DS-011. 9 captures acquired (TrickBot ×2, Dridex ×5, Emotet ×2; 561 MB) as a second, independent **malicious** source. **ADMITTED** (exploratory). |
| DS-008 | Malware-Traffic-Analysis.net | VERIFIED_AVAILABLE | No formal license; research-use statement on the about page. 7 admitted PCAPs were extracted from the repository ZIPs. The 3 missing admitted PCAPs (MTA-C021, C037, C046) were re-downloaded from the URLs in the Stage 6.5 manifest. All 10 match their recorded SHA-256. **ADMITTED**. |

Every download is logged in `data/raw/acquisition_staging/acquisition_log.tsv` (time, URL, HTTP status, bytes, duration) and copied into `capture_plan.json`. No traffic was uploaded anywhere, and no local traffic was captured.

### 2.1 Checklist for the researcher (blocked sources)

1. **DS-004:** complete the CipherSpectrum form at https://cgi.cse.unsw.edu.au/~cspectrum/. Download `mix.zip` and place the six Phase 6 samples in `data/samples/ds004/`. The member names are unknown, so identify them by the recorded sizes and SHA-256 in `data/manifests/dataset_manifest_20260815_092018.csv`. Then run `python -m pipeline.corpus all`.
2. **DS-006:** ask the repository author for written permission or a license (request template: `docs/research/dataset-access-request-drafts.md`).
3. **DS-007 / CIC datasets:** submit the access requests. Before re-running the pipeline, record the terms in the registry `license` field.
4. **Local collection:** none has been performed. A local benign capture needs explicit written authority from the network owner and every user, a retention policy, and minimised PII. ETTH's live mode never stores payloads, but PCAP collection would; that would need a separate, documented authorisation.

## 3. Reconstruction of missing processed data (WP1)

`data/processed/` was missing because the repository moved from `E:\UserBenchmark\…` without its git-ignored data. The Stage 6.5 inputs were restored and the corpus was rebuilt:

* **DS-008: 10/10 admitted PCAPs SHA-256-verified** against the Stage 6.5 manifest. Seven came from the local ZIPs (opened read-only); three were re-downloaded.
* **Deterministic reproduction verified.** Corpus v3 contains exactly **2,543 DS-008 flows, 194 JA3, 196 JA3S, 194 JA4, 111 TLS 1.2 + 83 TLS 1.3**. This equals the Stage 6.5 audit (`data/manifests/v2/phase6_expanded_audit.json`) minus its six DS-004 rows. It is ledger claim C01 (SUPPORTED).
* The six DS-004 flows could not be reproduced (see §2).
* The nine MTA ZIP archives are byte-identical to their state at the start of the task (SHA-256 re-checked at the end; see the final report).

## 4. Corpus v3 (computed from data)

| Dataset | Class | Captures | Flows | ClientHello / JA3 / JA4 flows |
|---|---|---|---|---|
| DS-008 | MALICIOUS | 10 | 2,543 | 194 |
| DS-009 | MALICIOUS | 9 | 447,563 | 66,612 |
| DS-011 | BENIGN | 6 | 127,132 | 13,845 |
| **Total** | | **25** | **577,238** | **80,651** |

Source: `data/corpus/admission_report.json` and `.md`.

* **Duplicates.** 322,014 behavioural groups and 21,084 duplicate groups. 276,308 flows (47.9 %) sit in a duplicate group, mostly beacons and DNS. 2,312 groups span captures, 24 span datasets and 24 span labels. These are kept and grouped, never deleted (see §5).
* **Fingerprint overlap between classes: zero.** 90 distinct JA3 values (46 malicious-only, 44 benign-only) and 82 JA4 values (39 / 43). The fingerprints identify each source's client stack: Windows malware VMs versus Linux/iceweasel browsing.
* **TLS versions.** Benign traffic is 100 % TLS 1.2. Malicious traffic is TLS 1.2 plus 83 TLS 1.3 flows, all from DS-008.
* **Fingerprint integrity.** 57 fingerprints come from ClientHellos truncated in the first TCP segment (43 benign, 14 malicious). They are flagged in `clienthello_record_truncated`.
* **Parser anomaly (documented).** DS009-CTU-MCB-264-1 has 14,060 flows with a TLS ServerHello but no parsable ClientHello. In the inspected prefix, client payloads on port 443 begin with plaintext `GET / HTTP/1.1`.
* **Metadata conflicts recorded, not resolved.** For CTU-Normal-23 and -24 the file name says `win` but the README says Kali Linux/iceweasel. The `os` field records the conflict.

## 5. Duplicate semantics

* **Exact duplicate flow:** identical feature vector *and* packet sequences.
* **Behavioural duplicate:** identical flat feature vector, the frozen Phase 7 `behavioral_hash`, computed with the same algorithm (verified by `test_behavioral_hash_matches_phase7_definition`). Timing sequences may differ.
* **Legitimate repetition:** behavioural duplicates produced by the traffic itself (beaconing, retries, repeated DNS). They are part of the observed population and are never removed. Grouping prevents them from crossing train/test boundaries; capture-level splits purge them from training (Phase 9 §3).

## 6. Sufficiency assessment

Thresholds were fixed in `pipeline/corpus/admission.py::THRESHOLDS` before any Phase 9 result existed.

| Level | Meaning | Result | Failing checks |
|---|---|---|---|
| A | pipeline can execute | **MET** | — |
| B | preliminary evaluation | **MET** | — |
| C | generalisation can be investigated | **NOT MET** | one benign source; fewer than 10 benign captures; no benign TLS 1.3; one benign environment class |
| D | publication claim | **NOT MET** | sources, captures, no independent confirmatory source, no flow-level labels |

## 7. Commands

```bash
python -m pipeline.corpus seed         # registry (keeps existing records)
python -m pipeline.corpus plan         # capture plan from manifests + acquisition log
python -m pipeline.corpus build        # extract, verify, validate, build v3 (resumable; ~13 min measured)
python -m pipeline.corpus admit        # admission report, sufficiency, registry transitions
python -m pipeline.corpus replay-set   # replay table for the live stream
python -m pipeline.corpus status
```

## 8. Limitations

1. Dataset identity equals class at the source level. Every exploratory result is source-confounded.
2. Benign traffic (DS-011) is 2017 scripted or manual browsing of popular sites, mostly from Kali Linux with iceweasel 43. It is not representative of enterprise, mobile, IoT or modern-browser traffic.
3. Labels are capture-level. Malware captures include benign OS background traffic and pre-infection minutes, all labelled malicious.
4. No published checksums exist for DS-009 and DS-011. Their SHA-256 values were recorded at first verification (trust-on-first-download).
5. The license status is informal for DS-008 (research-use statement) and project-level for DS-009 (MCFP disclaimer).
