# JA4 Dependency Inventory and Artifact Status (Phase 13)

This document maps each artifact from packet input to published claim, and states whether it depends on the JA4 implementation. Where it does, the document says what was done about it.

**JA4 implementation identifiers** (defined in `pipeline/canonical_flow.py`):

| Identifier | Version | What it is |
|---|---|---|
| `ETTH_JA4_V1` | `etth_ja4_v1` | The historical ETTH variant. It is **not** FoxIO JA4: signature algorithms are sorted, `n` is used for no SNI, the version comes from the presence of `supported_versions`, the trailing `_` is hashed, the empty cipher list is hashed, and counts are uncapped. |
| `FOXIO_JA4` | `ja4_foxio-c6469a7_etth-2` | `pipeline.tls_fingerprinting.generate_ja4_foxio`. It matches FoxIO's reference output on 139/139 pinned TCP vectors (`data/reference/foxio_ja4/vectors.json`, `tests/test_ja4_foxio_reference.py`). |

## 1. Pipeline stages

| Stage | Code | JA4 dependency |
|---|---|---|
| PCAP ingestion, checksum | `pipeline/corpus/extract.py`, `builder.materialize` | Independent |
| Flow reconstruction (120 s idle, FIN/RST, initiator = forward) | `pipeline/flow_reconstruction.py` | Independent of JA4. Hello acquisition is now a parameter: `reassemble_tls=False` reproduces corpus v3. |
| TLS parsing | `pipeline/tls_fingerprinting.parse_client_hello` | Shared. Phase 13 added raw ALPN bytes and `supported_versions` values, without changing v1 output. |
| JA3 | `generate_ja3` | Independent |
| JA4 v1 (corpus `ja4`) | `generate_ja4_v1` | **Directly**: this is the historical implementation |
| FoxIO JA4 | `generate_ja4_foxio` | **Directly**: the corrected implementation |
| Flow features (74) | `pipeline/feature_extraction.py` | Independent |
| Feature governance, tracks | `ml/features/governance.py` | Tracks C, E and A@JA4POP depend directly, because their population is `ja4` not null. A, B, D and A@JA3POP are independent. |
| Labels, label provenance | `data/corpus/capture_plan.json` | Independent (capture-level labels) |
| Dedup / behavioural hash | `pipeline/corpus/builder.py` | Indirect: the hash includes v1 `ja4`. The behavioural-holdout groups were built from v1. |
| Capture-grouped splits | `ml/evaluation/splits.py` | Independent: grouped by `capture_id` |
| Preprocessing / encoders | `ml/estimators/preprocessing.py` | Indirect for JA4 tracks: the vocabulary is learned from training-fold `ja4` values |
| Models, predictions, calibration, thresholds | `ml/benchmark/runner.py` | Directly for C and E. Indirectly for A@JA4POP, through its population. |
| Model registry | `data/model_registry/registry.json` | The C and E entries require `ETTH_JA4_V1`. Entries created before Phase 13 carry no record; inference applies the legacy default. |
| Real-time inference | `backend/inference_engine.py` | It now refuses JA4 that is undeclared, from another implementation or of another version (`ja4_compatibility_problem`). |
| Live capture | `backend/event_sources/live_capture.py` | It emits both v1 (`ja4`, `ETTH_JA4_V1`) and FoxIO (`ja4_v2`, `FOXIO_JA4`), from complete reassembled Hellos only. |
| Sensor adapters | `backend/event_sources/{zeek,suricata,ebpf}_source.py` | Zeek and Suricata JA4 is tagged `FOXIO_JA4`, with no ETTH version. Every registry model refuses it. |
| Claim ledger, report | `ml/reporting/claims.py`, `report.py` | C03, C04, C05, C07, C10, C11B and C12 use v1 JA4; C24 and C25 use FoxIO JA4. |
| Manuscript | `paper/manuscript/main.md` | Every "JA4" result is ETTH v1 unless it is labelled FoxIO. |

## 2. Historical artifacts and their status

| Artifact | Depends on JA4 | Status |
|---|---|---|
| `data/processed/v3/corpus_flows.parquet` (`ja4` column) | Directly | **Valid only for the historical implementation.** Preserved byte for byte. |
| Corpus v3 flow features and JA3 | No | Still valid. Recompute alignment confirmed JA3 equality on every row. |
| Phase 9 suites (pooled, matched, LOSO, LOFO, legacy holdout, encoding ablation, source identifiability): tracks A, B, D | No | Still valid, with the existing confounding caveats. |
| The same suites: tracks C, E and A@JA4POP | Directly or indirectly | **Valid only for ETTH v1.** FoxIO results are a separate suite (§3). Nothing was overwritten. |
| Phase 10 sequence results | No (packet sequences only) | Still valid (exploratory) |
| Registry models for C_JA4 and E_JA4_FLOW | Directly | Valid only for `ETTH_JA4_V1` input, which inference enforces |
| `data/processed/v3_ja4_v2/` (git-ignored) and suite `ja4_v2_comparison-20261017T050835Z` | — | **Invalidated by a demonstrated defect** (`recompute_ja4_v2.py`). Preserved on disk and in Git, and excluded from reports. |
| Manuscript and ledger text written after a001230 that claims FoxIO re-evaluation results | — | **Invalidated.** Corrected in Phase 13. |

## 3. Rebuilt artifacts

These outputs are new and versioned; nothing was replaced.

| Output | Command | Notes |
|---|---|---|
| `data/processed/v3_ja4_foxio/ja4_foxio.parquet` and `manifest.json` (git-ignored) | `python -m pipeline.corpus.recompute_ja4_foxio --raw-root <repo containing data/raw>` | 25/25 captures aligned with 0 fingerprint mismatches. 80,594 FoxIO values. 57 withheld as truncated (DS-008: 13, DS-009: 1, DS-011: 43). |
| Suite `ja4_foxio_capture_cv-*` | `python -m ml suite ja4_foxio_capture_cv` | New experiment IDs. JA4 tracks record `ja4_implementation`, `ja4_version` and `ja4_table`. |

## 4. Not rebuilt, and why

- **Behavioural-hash holdout with FoxIO JA4.** This legacy protocol is known to leak captures and is kept for continuity only.
- **Corpus v4 with TCP reassembly.** It would change the ClientHello acquisition for 57 flows and redefine the corpus. It needs a new corpus version and a full rebuild, which was not done here.
- **Registry models trained on FoxIO JA4.** Nothing needs them: no detection claim depends on them, and the corpus remains source-confounded.
