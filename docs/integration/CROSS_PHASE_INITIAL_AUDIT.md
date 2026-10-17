# Cross-Phase Initial Audit (Phases 8–12)

Date: 2026-10-17. Scope: the actual Git state before any integration work. Every hash, count and test result below was taken from the repository during this audit. None comes from earlier agent reports.

## 1. Repository and worktrees

Active repository: `D:\College\SOMESHIT DOWNLOADS\encrypted-traffic-threat-hunter`. The older path `E:\UserBenchmark\...` no longer exists. Remote: `origin`. `origin/main` = `main` = `327bbe3`.

| Worktree | Branch | HEAD | Uncommitted changes |
|---|---|---|---|
| `encrypted-traffic-threat-hunter` | `feat/phase-8-9-10-research-platform` | `540a58b` | only the 9 protected MTA ZIPs (see §5) |
| `etth-phase11` | `research/phase-11-sensor-integration` | `b4e1cfb` | only the 9 protected MTA ZIPs |
| `etth-phase12` | `research/phase-12-paper-manuscript` | `7c609af` | only the 9 protected MTA ZIPs |
| `etth-integration` (new, this task) | `integration/phase-8-12-validation` | `540a58b` at creation | none |

No stashes exist. Nothing has been pushed: none of the three research branches has an upstream.

## 2. Branches, merge bases and commit counts

| Branch | HEAD | Merge base with `main` | Commits ahead of `main` | Reported | Match |
|---|---|---|---|---|---|
| `feat/phase-8-9-10-research-platform` | `540a58b` (2026-10-17 00:50 +0530) | `327bbe3` | 119 | 119 | yes |
| `research/phase-11-sensor-integration` | `b4e1cfb` (2026-10-16 21:41 +0530) | `327bbe3` | 12 | 12 | yes |
| `research/phase-12-paper-manuscript` | `7c609af` (2026-10-16) | `327bbe3` | 5 | 5 | yes |

All three branches fork from the same commit, `327bbe3`. Phases 11 and 12 were therefore built **without** any Phase 8–10 code, data or results. No commits were made after the reports on any of the three branches.

Phase 11 commits: `2b6dd8a fdf7c9a f978b9b 2d8eb7c f27dee6 1432664 b4cd087 03e8de7 b3d9bbd fc83ecc 795fbc9 b4e1cfb`.
Phase 12 commits: `91f8e20 0e708bc 3dc1da7 1bf2dca 7c609af`.

## 3. Baseline test results (measured now)

| Tree | Command | Result |
|---|---|---|
| `main` (`327bbe3`), clean export | `python -m pytest -q -p no:cacheprovider` | 143 passed, **1 failed** (`test_websocket_stream::test_13_replay_completed_transition`, pre-existing) |
| Phase 11 (`b4e1cfb`), clean export | same | 156 passed, **1 failed** (the same pre-existing test). The 13 sensor tests pass. |
| Phase 12 (`7c609af`) | documentation only; no code changes relative to `main` | same as `main` |
| Phase 8–10 (`540a58b`), clean checkout without git-ignored data | same | 229 passed, **4 failed**: `test_websocket_stream` tests 5, 12, 13 and 20 need the git-ignored replay parquet |
| Phase 8–10 (`540a58b`), with local `data/processed/v3` and model artifacts | same | **233 passed**, 0 failed. This confirms the reported count. |

The reported "233 passed" holds only when the git-ignored replay data exists. Four lifecycle tests silently depend on local research data.

## 4. What each source branch changes

**Phase 11** (18 files, +1795/−1):
- New: `backend/event_sources/{zeek_source,suricata_source,ebpf_source}.py`, four fixtures under `data/fixtures/sensors/`, five files under `docs/sensors/`, and four `tests/test_sensors_*.py` files.
- Modified: `backend/event_sources/__init__.py` (exports) and `backend/main.py` (adds `GET /api/sensors/status`).

**Phase 12** (5 files, +661):
- `docs/research/{RESEARCH_CLAIM_LEDGER,PAPER_READINESS_AUDIT,REPRODUCIBILITY_GUIDE}.md`.
- Two byte-identical copies of the manuscript: `docs/research/manuscript/main.md` and `paper/manuscript/main.md`.

**Phase 8–10** (375 files): see `docs/research/PHASE_8_9_10_INITIAL_STATE_AUDIT.md`. It overlaps the other branches in these files:

| File | Phase 8–10 | Phase 11 | Phase 12 | Textual conflict |
|---|---|---|---|---|
| `backend/main.py` | research router, data access, honest replay errors | sensor status endpoint | — | none (auto-merges) |
| `docs/research/RESEARCH_CLAIM_LEDGER.md` | generated ledger (C01–C17) | — | hand-written ledger (6 claims) | **add/add** |
| `docs/research/PAPER_READINESS_AUDIT.md` | Phase 8–10 audit | — | venue/score audit | **add/add** |
| `docs/research/REPRODUCIBILITY_GUIDE.md` | Phase 8–10 guide | — | Phase 7 pilot guide | **add/add** |

Phases 11 and 12 do not overlap each other.

## 5. Protected MTA archives

All 9 archives (`data/verification/mta_stage65/MTA-C0{03,06,15,18,22,39,40,45,49}.zip`) show `M` in every worktree.

`git lfs status` reports `Git: <sha> -> File: <same sha>` for each one, and `git archive` reports "should have been pointers, but weren't". The blobs were committed raw while `.gitattributes` routes them through LFS, so the `M` comes from a filter mismatch, not from changed content.

Baseline SHA-256 values are identical in all four worktrees:

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

These files are never staged during this task. They will be re-hashed at the end.

## 6. Semantic incompatibilities found by code reading

These are problems that merge without textual conflicts. Stage 3 verifies each one and fixes the genuine ones.

**Sensor feature semantics**

1. **JA4 implementation mismatch.** `pipeline.tls_fingerprinting.generate_ja4` sorts the signature algorithms. The FoxIO specification keeps them in ClientHello order. On the FoxIO reference vector (`t13d1516h2_8daaf6152771_e5627efa2ab1`), ETTH would produce the suffix `0adf69b4533f`. JA4 values from Zeek (FoxIO package) and Suricata 7+ therefore never match the vocabulary the C/E models were trained on. The fingerprint-only models score unseen fingerprints as malicious (claim C16), so every JA4 that comes from a sensor would be scored as an unseen one.
2. **TLS version semantics.** ETTH `tls_version` is `1.2`/`1.3`, derived from whether the ClientHello has a `supported_versions` extension, i.e. what the client offers. Zeek reports `"TLSv12"` and Suricata reports `"TLS 1.3"`. Both are the *negotiated* version. Phase 11 copies those strings into `tls_version`.
3. **ALPN semantics.** ETTH `alpn_value` is the first ALPN the client *offers*. Zeek `next_protocol` is the ALPN the server *selected*.
4. **Byte semantics.** ETTH counts IP length. Zeek `orig_bytes` counts transport payload (the IP-level count is `orig_ip_bytes`). Suricata counts captured packet length including the link layer. The eBPF meaning depends on the collector.
5. **Missing flow statistics.** Sensors provide no packet-length, IAT or burst statistics. Phase 11 also emits non-registered names (`asymmetry_ratio_*`) with a different formula. When duration is 0 it sets rate = count, which fabricates a rate.

**Fabricated values and lost records**

6. **Fabricated defaults:**
   - endpoints `0.0.0.0` and port `0`;
   - `serverhello_present` defaulting to `True` (Zeek: whenever `established` is missing; Suricata: always);
   - any non-TCP/UDP protocol mapped to `TCP`.
7. **Lost or duplicated records.** Correlator TTL expiry and a full cache silently drop records (Zeek drops pending `conn` records). Duplicate `conn` or `flow` records are emitted twice.
8. **Suricata.** Duration comes from the integer `flow.age`, not from `flow.start`/`flow.end`. A JA3 *string* can land in `ja3_hash`.
9. **eBPF fixture** puts a JA3 string (`771,4865-4866,0-23`) into `ja3_hash`.

**Status, provenance and labels**

10. **Sensor status.** `GET /api/sensors/status` reports Zeek and Suricata as `available: true` because the parsers exist. No sensor process or ingestion path is running, and nothing connects the sensor adapters to the replay/live stream.
11. **Sensor identity** (sensor type and record id) is lost when a flow becomes an `ETTHStreamEvent`.
12. **Suricata alerts** are carried as `sensor_alerts`. They must not become labels or model inputs; Stage 4 verifies this.

**Live capture parity (Phase 8–10 code)**

13. **Direction.** `LiveFlowTracker` assigns "forward" to the lexicographically smaller endpoint. The offline pipeline assigns it to the initiator (the first packet's source), so the `fwd_*`/`rev_*` features can flip between live capture and training.
14. **Flow boundaries.** Live capture uses a 15 s idle timeout and a 60 s maximum duration. Offline uses a 120 s idle timeout and no maximum, so live and offline flow statistics are not defined the same way.

**Tests and documents**

15. **Data-dependent tests.** Four replay lifecycle tests depend on git-ignored data (§3).
16. **Phase 12 documents** were written against the Phase 7 pilot. They state that Phase 10 was never run, and they call the five tracks "mutually exclusive". They claim cross-sensor correlation, which is not implemented. They also give a 15 s offline timeout, "80 features" and a feature-importance narrative (sandbox jitter), none of which match the code or have a supporting artifact. Several citations look wrong (Arp et al. author list, JA4+ attribution, the venue of Anderson & McGrew 2017); Stage 7 checks them.

## 7. Integration sequence

1. Create `integration/phase-8-12-validation` from `540a58b` in a separate worktree (done; the source branches stay untouched).
2. Merge Phase 11 with an ordinary merge commit, preserving its history.
3. Merge Phase 12 with an ordinary merge commit. Resolve the three add/add conflicts by keeping the generated, evidence-backed Phase 8–10 documents and recording what happens to each Phase 12 claim, rather than choosing a side blindly.
4. Stage 3: fix the sensor contracts (items 1–12) and live capture parity (13–14), with regression tests.
5. Stage 5: make the replay lifecycle tests independent of git-ignored data (15) without weakening their assertions.
6. Stage 6–7: re-verify the Phase 9/10 numbers against persisted artifacts, extend the generated claim ledger, and reconcile the manuscript (16).
7. Stage 8–10: full regression (backend, frontend build, lint), integration report, final MTA hash check.

Nothing will be pushed, merged into `main`, rebased or reset.
