# Phases 8–10 — Initial State Audit (Work Package 0)

**Audit date:** 2026-10-16
**Working copy:** `D:\College\SOMESHIT DOWNLOADS\encrypted-traffic-threat-hunter`
**Branch:** `main` (up to date with `origin/main`, HEAD `327bbe3`)

The task specification names the repository path `E:\UserBenchmark\encrypted-traffic-threat-hunter`.
That path is the machine on which Phases 5–7 were executed (it appears inside
`data/verification/results/phase6_step3_pcap_validation.csv`). The repository was
subsequently moved to the D: path above **without** its git-ignored raw and processed data.
This single fact explains most of the "missing data" findings below.

Every statement in this document is labelled **VERIFIED** (checked against the
filesystem, git, or by executing code during this audit) or **REPORTED** (taken from an
earlier document and not re-checked).

---

## 1. Git state (VERIFIED)

| Item | Observation |
|---|---|
| Staged changes | none |
| Unstaged changes | the nine `data/verification/mta_stage65/MTA-C0xx.zip` archives show as modified |
| Cause of the "modified" status | `.gitattributes` routes `*.zip` in that folder through Git LFS, but the committed blobs are raw ZIP bytes. The LFS *clean* filter would turn the working files into 132-byte pointers, so git reports a difference. The working-tree files are the original archives (they open, list correctly and match the checksums below). |
| Action taken | none. The archives were opened **read-only** and were not renormalised, re-added or rewritten. |

SHA-256 of the archives at the start of the task (used for the end-of-task integrity check):

```
d9a1ae02f6098661b5488c830360b1f6d41967b87b66c08137209af2f07e9e63  MTA-C003.zip
54309975b6f9cde0bf5c80771cb2fe48e1c6cfe53c93a64d167d38ffc97204fb  MTA-C006.zip
48e0fbadbfa205572fdef8ff7f02d42912d81ad1362a973907bea157a980459a  MTA-C015.zip
fe6422949c8c3580ffbb762799a93a784a06748c66d0531279b97e3794eed722  MTA-C018.zip
f75dbae7903aef96f6069f59cbe87ae3e9da1f0a38033bdd566d0da519222060  MTA-C022.zip
4f3133298d08eca9bd430aeaee984f4efbdc40516af13c6d5a81cd2b5b1b9ab0  MTA-C039.zip
5bfd0496ca8801f9d513d8cf0aa1225d3e4e0da1e2059cef9dacd9fb948f4c39  MTA-C040.zip
cc40a9268aca8bd7a1215eab3ee82c1cc5a19adb39cb29e76a553e83869f9e25  MTA-C045.zip
37431dfcc6d8a0216276f1aed17dd7e8bc4ce338a3237e724655ecc576c70a03  MTA-C049.zip
```

`MTA-C039.zip` also contains a Windows executable, a TAR and an e-mail (live malware
artefacts). No tool written in this task extracts non-PCAP archive members.

---

## 2. What data physically exists (A, B, C)

| Artefact | Expected by | Physically present | Tracked by git |
|---|---|---|---|
| Nine MTA ZIP archives (`data/verification/mta_stage65/`) | Stage 6.5 | **YES** (89 MB) | yes (raw blobs; LFS attribute mismatch) |
| Two DS-008 baseline PCAPs (`data/verification/pcaps/2024-03-14-AsyncRAT…`, `2025-01-30-XLoader…`) | Stage 6.5 | **NO** | no (`*.pcap` ignored) |
| Admitted DS-008 PCAP `2025-08-20-SmartAgeSG-Netsupport-RAT-with-StealCv2.pcap` (MTA-C021) | Stage 6.5 | **NO**: there is no `MTA-C021.zip` in the repository | no |
| Six DS-004 CipherSpectrum samples (`data/samples/ds004/sample1–6.pcap`) | Phase 6 / Stage 6.5 | **NO** | no (`data/samples/` ignored) |
| `data/raw/`, `data/interim/`, `data/processed/` | Phase 6 / 6.5 / 7 | **NO** (directories absent) | no (ignored) |
| `data/processed/v2/model_safe/model_safe_dataset.parquet` | pilot script, backend inference, replay | **NO** | no |
| Manifests (`data/manifests/*.json`, `*.csv`) | provenance | YES | yes |
| Pilot results (`data/experiments/phase7_step5_pilot/`) | Phase 7 Step 5 | YES | yes |

Expected checksums of all missing inputs are recorded in git
(`data/manifests/dataset_manifest_20260815_092018.csv`,
`data/manifests/ds008_expanded_corpus_manifest.csv`), so any restored file can be verified
byte for byte.

## 3. Dataset states (D)

| ID | Dataset | Prior documented state | Local evidence |
|---|---|---|---|
| DS-008 | Malware-Traffic-Analysis.net | 10 PCAPs admitted (REPORTED) | 7 of 10 admitted PCAPs recoverable from local ZIPs; 3 missing |
| DS-004 | CipherSpectrum | 6 PCAPs, BENIGN_VALIDATION (REPORTED) | 0 of 6 present |
| DS-006 | Beyond JA4+ (Brno) | academic access pending (REPORTED) | none |
| DS-007 | Annotated Encrypted Network Traffic (Brno) | academic access pending (REPORTED) | none |
| CAND-006/007/008 | CIC-IDS-2017 / CIC-Bell-DNS-EXF-2021 / CIRA-CIC-DoHBrw-2020 | rejected for automation, gated by a registration form (REPORTED) | none |

## 4. Experiments actually run (E, G, H)

| Experiment | Artefact | Assessment |
|---|---|---|
| Phase 7 Step 5 pilot (A–E × LR/RF/XGB, 5× GroupShuffleSplit) | `pilot_summary.json`, `pilot_fold_results.csv` | Genuine artefacts, but **source-confounded and uninformative**: 2,543 malicious vs 6 benign; one fold held out zero benign flows; "PR-AUC" was computed with the **malicious** class as positive at ≈99.7 % prevalence, so a constant classifier already scores ≈0.997. Track A included TLS-structural fields (`clienthello_present` etc.) that are 100 % present in DS-004 and ≈4 % present in DS-008, which makes them near-perfect source identifiers. |

No other model evaluation artefact exists. No experiment registry exists.

## 5. Models (F)

No persisted model artefact exists anywhere in the repository (VERIFIED).

`backend/inference_engine.py` **trains five RandomForest pipelines at import time on the
entire available parquet** (no hold-out), fills missing features with `0`, and, if training
fails, falls back to `ETTH-GroundTruthRule`, which returns the **ground-truth label as the
prediction** with a hard-coded confidence of 0.95. Because the parquet is currently
missing, that fallback is the active code path for every replayed flow. On live flows,
which carry the label `UNKNOWN`, the fallback reports `BENIGN` with score 0.08. This
behaviour is incompatible with the research-integrity rules and is replaced in WP5.

## 6. Backend capability findings (I)

| Capability | Status | Notes |
|---|---|---|
| FastAPI app, health, pilot/manifests endpoints | works | |
| Flow/fingerprint endpoints | return 404 | parquet files are missing |
| Replay engine | runs, but the loop spins forever when no dataset is loaded | cause of the one failing baseline test |
| Live capture (`LiveCaptureSource`) | **fabricates TLS fingerprints**: every ClientHello is given the same hard-coded JA3 string, a synthetic JA4 (`t13d150900_<ja3[:12]>_000000000000`) and a hard-coded JA3S; `tls_version` is always 771; `packet_length_std` and `iat_std` are always `0.0`; byte counts use frame length while the offline pipeline uses IP length | fixed in WP5 |
| Target resolver / sessions / WebSocket protocol | work (tests pass) | preserved |

## 7. Frontend API contracts (J)

React 18 + TypeScript + Vite. `frontend/node_modules` is absent, so a build requires
`npm ci`. Research pages read `/api/pilot/*` and `/api/manifests/*`. `DatasetExplorer`
reads a static TypeScript copy of `docs/research/dataset-registry.csv`.
`Experiments.tsx` substitutes hard-coded row counts (`2068`, `160`) when the audit
manifest lacks them. No research-job, model-registry or benchmark API exists.

## 8. Environment (K, VERIFIED)

| Item | Value |
|---|---|
| OS | Windows 11 |
| Python | 3.12.0 |
| Key packages | numpy 2.4.6, pandas 3.0.5, scikit-learn 1.9.0, scipy 1.18.0, imbalanced-learn 0.14.2, xgboost 3.4.1, lightgbm 4.6.0, dpkt 1.9.8, scapy 2.7.0, pyarrow 25.0.1, fastapi 0.136.1, pydantic 2.13.5, **torch 2.13.0+cpu**, safetensors 0.7.0, psutil 7.2.2 |
| Not installed | shap, skops, skl2onnx, captum, statsmodels |
| GPU | NVIDIA RTX 5050 Laptop (8 GB) present, but the installed PyTorch is a CPU build. It was **not** upgraded; deep learning uses the CPU path. |
| Node / npm | 26.7.0 / 11.19.0 |
| Disk | D: 133 GB free; **C: 2.9 GB free** (the scratch directory and caches live on C:, so large artefacts are kept on D:) |
| Network | outbound HTTPS available |

## 9. Baseline test run (VERIFIED)

```
python -m pytest -q -p no:cacheprovider
144 collected — 143 passed, 1 failed (14.95 s)
FAILED tests/test_websocket_stream.py::test_13_replay_completed_transition
```

The failure predates this task. The replay engine has no dataset, because
`data/processed` is missing, so `_stream_loop` sleeps forever and `asyncio.wait_for(…, 2.0)`
times out. The README's claim of "46 tests" is stale; the suite has 144.

## 10. Missing prerequisites (summary)

1. **No benign data of any kind is present locally.** Every supervised detection
   experiment is blocked until benign traffic is restored or acquired.
2. Three admitted DS-008 PCAPs are missing; seven can be recovered from local archives.
3. All processed tiers (`interim`, `processed`, `v2`) are missing and must be regenerated.
4. Real-time inference has no validated model and currently relies on label-echo and
   fingerprint-fabrication code paths.

These findings define Work Packages 1–5.
