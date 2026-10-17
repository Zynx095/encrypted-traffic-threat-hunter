# Final Remediation Report — Phase 13

This report replaces the earlier version written at `61f502a`. The earlier version claimed several things this audit could not confirm:

- 398 passing tests (393 were run here);
- 127 verified records;
- a FoxIO re-evaluation that "proves" invariance to the hashing specification;
- implemented cross-sensor correlation;
- approved benign datasets.

That text remains in Git history.

## 1–5. Repository state

| Item | Value |
|---|---|
| Repository path | `D:\College\SOMESHIT DOWNLOADS\etth-integration` (a worktree of `D:\College\SOMESHIT DOWNLOADS\encrypted-traffic-threat-hunter`) |
| Branch | `integration/phase-8-12-validation` |
| Initial HEAD | `61f502a`. The reference value given was `a001230`; ten further commits, `0a6cf09`…`61f502a`, had been made since then under the same Git identity. They were audited rather than assumed correct (§6). |
| Final HEAD | the commit that adds this report. The ledger in §6 lists everything before it. |
| Uncommitted user changes at start | Only the pre-existing `M` status of the nine MTA zips, caused by an LFS pointer mismatch. Not touched. |

Source branches were recorded at the start and re-checked at the end:

| Branch | Start | End |
|---|---|---|
| `main` | `327bbe3` | `327bbe3` |
| `feat/phase-8-9-10-research-platform` | `540a58b` | `540a58b` |
| `research/phase-11-sensor-integration` | `b4e1cfb` | `b4e1cfb` |
| `research/phase-12-paper-manuscript` | `7c609af` | `7c609af` |

## 6. Audit of the pre-existing Phase 13 commits, and the commit ledger

### Defects found in `0a6cf09`…`61f502a`

| Commit | Defect | Fixed in |
|---|---|---|
| `0a6cf09` | `generate_ja4_foxio` was validated only against a self-built copy of FoxIO's documentation example. It failed FoxIO's non-ASCII ALPN vector, returned `12` for unknown versions instead of `00`, and used the wrong SSL 2.0 code. | `d985e10`, `c0c0485` |
| `a8cd906` | `recompute_ja4_v2.py` "converted" v1 strings into FoxIO JA4: it copied the v1 third component for 41,408 of 80,651 fingerprints and hard-coded one mapping (`0adf69b4533f`→`e5627efa2ab1`). The suite built on it silently fell back to v1 values whenever the file was missing. Its manifest reported 563,310 "changed" rows, a count produced by null≠null comparisons. | `5e58e7c`, `60a46a2`, `f226493` |
| `1b263d7` | The reassembler returned a truncated buffer as "complete" when it hit its size limit, resolved conflicting overlaps silently, and reported no outcomes. | `6046198`, `051c4ac` |
| `87eb96d` | Reassembly was added to the offline reconstructor unconditionally, together with re-parsing of later ClientHellos. This silently changed corpus v3 semantics under the same schema. | `ef9f295` |
| `b97cfff`, `62e29a2` | The manuscript and ledger claimed "cross-sensor correlation implemented & tested". Only per-adapter normalisation tests exist. | `0d2d471` |
| `07aba41` | The benign audit cited an unrelated Zenodo record, gave CESNET-TLS22 ClientHello fields it does not document, misstated licences, and marked datasets "APPROVED". | `2219b7d`, `b622ede` |
| `61f502a` | The report claimed results that were not reproduced (see the introduction). | this report |

### Commits created in Phase 13 (chronological)

| Commit | Purpose |
|---|---|
| `d985e10` | fix(ja4): FoxIO version and ALPN rules |
| `c0c0485` | test(ja4): 139 pinned FoxIO reference vectors |
| `6046198` | feat(capture): bounded Hello reassembly with explicit outcomes and 24 tests |
| `d04dce5` | feat(features): JA4 version and Hello-acquisition identifiers |
| `ef9f295` | fix(pipeline): offline reassembly opt-in; corpus v3 semantics preserved |
| `051c4ac` | fix(capture): live capture uses the shared reassembler |
| `d1661df` | test(parity): Hello acquisition parity with realistic TCP |
| `ec118c0` | fix(models): fail closed on undeclared or mismatched JA4 |
| `4b85175` | feat(models): registry records fingerprint implementations |
| `5ec41ba` | fix(replay): declare historical JA4 on replay rows |
| `79977fa` | feat(sensors): six-state sensor status |
| `2219b7d`, `b622ede` | docs(research): benign-audit corrections |
| `5e58e7c` | feat(corpus): FoxIO JA4 recomputed from raw captures |
| `60a46a2` | fix(benchmark): invalidate `ja4_v2_comparison`; add `ja4_foxio_capture_cv` |
| `f923a9e` | feat(claims): C22–C26 |
| `8db8bf3` | docs(integration): JA4 dependency inventory |
| `8da360f` | data(experiments): FoxIO suite records |
| `7e51cd7` | data(report): regenerated report and ledger |
| `0d2d471` | docs(research): ledger and manuscript reconciliation |
| `3c848ec` | test(capture): unused import |
| `f226493` | fix(benchmark): refuse invalidated suites before loading data (found on a clean export) |
| (following) | docs(readme): test counts and status; docs(integration): this report |

## 7–10. JA4

- **Specification.** FoxIO `technical_details/JA4.md`.
- **Reference.** FoxIO's reference-implementation snapshot outputs, `rust/ja4/src/snapshots/*.snap`, from `github.com/FoxIO-LLC/ja4` at commit `c6469a7b0dbf8fe963810162429fbfd9d1acc4d5` (committed 2026-10-06), retrieved 2026-10-17.
- **Vector set.** 139 TCP `ja4` entries from 13 captures. The captures are pinned by SHA-256 in `data/reference/foxio_ja4/vectors.json` and are not committed, because their licence is not stated separately (JA4 itself is BSD-3). Fetch them with `python -m pipeline.fetch_foxio_ja4_vectors`.
- **Reproduced discrepancy.** On FoxIO's documented ClientHello, ETTH v1 gives `t13d1516h2_8daaf6152771_0adf69b4533f` and FoxIO gives `…_e5627efa2ab1`. The cause is that v1 sorts the signature algorithms; FoxIO keeps wire order. The remaining v1 deviations are listed in `JA4_DEPENDENCY_INVENTORY.md`.
- **Defects found in the earlier v2 code.** Checking it against the reference vectors exposed:
  - **Non-ASCII ALPN.** FoxIO's reference code writes `99`; the earlier code wrote `00`. FoxIO's written spec says hex. ETTH follows both reference implementations (Rust and Python), and the difference is recorded.
  - **Unknown versions** gave `12` instead of `00`.
- **Corrected implementation.** `generate_ja4_foxio`, with the identifier `FOXIO_JA4` / `ja4_foxio-c6469a7_etth-2`.
- **Result.** 139/139 vectors match (`tests/test_ja4_foxio_reference.py`, executed; it skips with a reason when the captures are absent, for example on a clean export).
- **Limitations.** QUIC and DTLS JA4 are not implemented.

## 11–14. Versioning, affected artifacts, rebuilds, preservation

The full map is in `docs/integration/JA4_DEPENDENCY_INVENTORY.md`.

**Versioning**
- Flows carry `ja4_implementation`/`ja4_version` for `ja4`, and `ja4_v2_implementation`/`ja4_v2_version` for FoxIO.
- They also carry `tls_hello_acquisition` (`FIRST_SEGMENT` | `TCP_REASSEMBLY`) and `clienthello_reassembly` outcomes.
- New registry entries record `fingerprint_implementations`. Inference refuses JA4 that is undeclared, `UNKNOWN`, from another implementation or of another version (`tests/test_inference_contract.py`, `tests/test_model_fingerprint_metadata.py`).

**Rebuilt** (new, versioned outputs only)

| Output | Command | Result |
|---|---|---|
| `data/processed/v3_ja4_foxio/` | `python -m pipeline.corpus.recompute_ja4_foxio --raw-root "D:/College/SOMESHIT DOWNLOADS/encrypted-traffic-threat-hunter"` | 25/25 captures: raw SHA-256 verified, alignment proved (v1 JA4 and JA3 identical on every row), 0 mismatches. 80,594 COMPUTED, 57 INCOMPLETE_FIRST_SEGMENT (DS-008: 13, DS-009: 1, DS-011: 43), 496,587 NO_CLIENTHELLO. 35 distinct FoxIO values, 0 shared between classes. |
| suite `ja4_foxio_capture_cv-20261017T063740Z` | `python -m ml suite ja4_foxio_capture_cv` | 28 new experiments |

**Provenance note (independent audit).** The manifest records `git_revision` `b622ede…+dirty`, because the recompute script was still uncommitted when it ran. It was later committed unchanged as `5e58e7c`. Re-running the committed script at `286cfcc` into a scratch directory produced a byte-identical table (output SHA-256 `7bc0e796…16e8`). A second, independent extraction path (`pipeline.ja4_reference`) agreed on all 181 DS-008 first-instance FoxIO values.

**Preserved unchanged**
- Corpus v3 (including its v1 `ja4`).
- All Phase 9 and Phase 10 suites and records.
- The registry models.
- `data/processed/v3_ja4_v2/`, and suite `ja4_v2_comparison-20261017T050835Z`, which is invalidated and excluded from reports.

## 15. TCP ClientHello reassembly

The implementation is `pipeline/tls_reassembly.py` (`HelloReassembler`, `ReassemblyTable`).
- **Outcomes:** COMPLETE, PENDING, INCOMPLETE_TIMEOUT, INCOMPLETE_EVICTED, INCOMPLETE_TERMINATED, MALFORMED, CONFLICTING_OVERLAP, UNSUPPORTED, NO_CLIENTHELLO.
- **Coverage:** `tests/test_tls_reassembly.py` (24 tests) covers all 20 required cases, plus a lost first segment, a Hello spanning several TLS records, and ServerHello completion inside a larger record.
- **Compatibility:** the old `TcpStreamReassembler` is now a wrapper, and its 10 original tests still pass.
- **Limitation:** inputs are synthetic only.

## 16. Live/offline parity

`tests/test_live_offline_parity.py` (11) and `tests/test_hello_acquisition_parity.py` (7) run the same packets through both paths:

| Fields | Equality rule |
|---|---|
| Flows, direction, counts, bytes, duration | exact |
| FLOW features | rel/abs 1e-9 |
| TLS fields, outcomes | exact |

Cases covered:
- split, out-of-order and retransmitted Hellos;
- a missing segment followed by FIN;
- RST;
- a conflicting overlap;
- non-TLS traffic.

**Fixture correction.** The earlier fixtures used `seq=0` on every segment. They now follow real TCP; the assertions are unchanged.

**Known, documented divergences**
- Live capture splits flows at 300 s; such flows are flagged and refused by flow models.
- Corpus v3 uses `FIRST_SEGMENT` acquisition, while live capture uses `TCP_REASSEMBLY`. They differ only for segmented ClientHellos, which are 57 of 80,651 in v3.

All packets are synthetic. No real-capture parity was run.

## 17. Sensors

| Check | Result |
|---|---|
| Zeek, Suricata, tshark installed? | No (`which` on PATH: none) |
| Genuine tool output processed | **None** |
| eBPF program | **None exists**; only a JSON event contract |
| Cross-sensor correlator | **None** (C26 UNTESTED) |
| `/api/sensors/status` | Reports `adapter_implemented`, `configured`, `dependency_installed`, `sensor_running` (null when ETTH cannot know), `sensor_output_observed` and `end_to_end_validated`. The last is false everywhere. |

All sensor tests use hand-authored synthetic fixtures.

## 18. Independent benign data

See `docs/research/BENIGN_DATA_AUDIT_CORRECTIONS.md`. No candidate is currently usable:
- **CESNET-TLS22** has no ClientHello fields and carries service labels, not benign labels.
- **CIC** datasets require a request form.
- **DS-004** requires registration.
- **DS-006** has an unresolved licence.
- **Further Stratosphere CTU-Normal captures** are not yet evaluated.

Nothing was downloaded, relabelled or synthesised. The blocker stands.

## 19–20. Experimental tracks (exploratory, `ja4_foxio_capture_cv`)

- **Protocol:** capture-grouped 5-fold CV, seed 42, per-capture cap 4,000.
- **Population:** 62,543 rows (38,543 malicious, 24,000 benign) from 25 captures. B, D and A@JA3POP use 8,591/2,629 flows; C, E and A@JA4POP use 8,578/2,621, because the 57 truncated ClientHellos get no FoxIO value.
- **Uncertainty:** capture bootstrap; every interval is FEW_GROUPS.

Primary model random_forest, AP [95 % CI]:

| Track | AP | Track | AP |
|---|---|---|---|
| A_FLOW | 0.931 [0.797, 0.986] | A@JA3POP | 0.990 [0.946, 1.000] |
| B_JA3 | 0.971 [0.868, 1.000] | A@JA4POP | 0.995 [0.969, 1.000] |
| C_JA4 (FoxIO) | 0.999 [0.989, 1.000] | D_JA3_FLOW | 0.988 [0.931, 1.000] |
| E_JA4_FLOW (FoxIO) | 0.994 [0.968, 1.000] | | |

**Contrasts (Holm-corrected)**
- **C24, A@JA4POP→E:** ΔAP −0.0007 [−0.0043, 0.0003], p = 1.0. Status: INSUFFICIENT_EVIDENCE.
- **C25, C→E:** ΔAP −0.0049 [−0.0267, 0.00004], p = 1.0. Status: INSUFFICIENT_EVIDENCE.

**Test FPR at the validation threshold (FPR ≤ 1 %).** C_JA4 18.4 %, B_JA3 18.6 %.

**What this does and does not show.** These numbers are bounded by source confounding: one benign source, and dataset identity equals class. They are not evidence of either a fingerprint benefit or its absence.

## 21–22. Claim ledger and manuscript

**Claim ledger** (generated at 2026-10-17T09:09:38Z)

| Claim | Status |
|---|---|
| C22, FoxIO conformance | SUPPORTED (engineering) |
| C23, reassembly | SUPPORTED (synthetic) |
| C24, C25 | INSUFFICIENT_EVIDENCE |
| C26, cross-sensor identity | UNTESTED |
| Earlier claims (C01–C21) | unchanged |

**Ledger reconciliation table.** Rows 4 (JA4 vs JA3) and 6 (cross-sensor identity) were corrected.

**Manuscript corrections** (`paper/manuscript/main.md`)
- the two JA4 implementations are named, and each result says which one it uses;
- C22 and the FoxIO recompute are described;
- the FoxIO results are added;
- the "v2" result is withdrawn;
- the 43 truncated DS-011 ClientHellos are reported;
- the sensors section is restored to engineering-only;
- the limitations and future work are corrected.

No citation was added.

## 23–26. Checks

| Check | Result |
|---|---|
| Backend tests, with local data | **459 passed**. Re-run at `286cfcc` during the independent audit: 459 passed. |
| Backend tests, clean `git archive` export | At `286cfcc`: **458 passed, 1 skipped** (FoxIO reference captures absent; skip reason printed). Before `f226493` the same run gave 457 passed, 1 skipped, 1 failed; `f226493` fixed that failure. |
| Frontend `npm run build` | passes (chunk-size warning only) |
| `npm run lint` | **not executable**: `eslint` is not installed (pre-existing) |
| pyflakes | 68 findings, all unused imports or variables; no undefined names. The one new finding in Phase 13 code was fixed; the re-export in `tcp_reassembly.py` is intentional. |
| `python -m ml verify` | **152/152 VERIFIED** (124 earlier records + 28 FoxIO), no claim-status differences. Invalidated v2 records are excluded. |

## 27. Protected MTA archives

Baseline taken at the start of this session and re-hashed at the end; `diff` showed no differences.

| File | SHA-256 (before = after) |
|---|---|
| MTA-C003.zip | d9a1ae02f6098661b5488c830360b1f6d41967b87b66c08137209af2f07e9e63 |
| MTA-C006.zip | 54309975b6f9cde0bf5c80771cb2fe48e1c6cfe53c93a64d167d38ffc97204fb |
| MTA-C015.zip | 48e0fbadbfa205572fdef8ff7f02d42912d81ad1362a973907bea157a980459a |
| MTA-C018.zip | fe6422949c8c3580ffbb762799a93a784a06748c66d0531279b97e3794eed722 |
| MTA-C022.zip | f75dbae7903aef96f6069f59cbe87ae3e9da1f0a38033bdd566d0da519222060 |
| MTA-C039.zip | 4f3133298d08eca9bd430aeaee984f4efbdc40516af13c6d5a81cd2b5b1b9ab0 |
| MTA-C040.zip | 5bfd0496ca8801f9d513d8cf0aa1225d3e4e0da1e2059cef9dacd9fb948f4c39 |
| MTA-C045.zip | cc40a9268aca8bd7a1215eab3ee82c1cc5a19adb39cb29e76a553e83869f9e25 |
| MTA-C049.zip | 37431dfcc6d8a0216276f1aed17dd7e8bc4ce338a3237e724655ecc576c70a03 |

They were never staged. No LFS configuration was changed.

## 28–29. Remaining blockers and next steps (ranked)

1. **Independent benign data.**
   - Download additional Stratosphere CTU-Normal captures.
   - Record their SHA-256 hashes and READMEs.
   - Measure ClientHello coverage with `FlowReconstructor(reassemble_tls=True)`.
   - Reserve one never-used benign source and one never-used malicious source for a frozen confirmatory run.
2. **Corpus v4.**
   - Rebuild with `reassemble_tls=True`, with FoxIO JA4 as the primary `ja4`, under a new corpus and schema version.
   - Retrain any deployable JA4 models; they will record `FOXIO_JA4`.
3. **Genuine sensor validation.**
   - Install Zeek and Suricata on an authorised host and run them on the corpus PCAPs.
   - Validate the adapters against that output.
   - Implement a cross-sensor correlator (C26).
4. **Real-interface live capture.** Validate on a host with a capture driver.
5. **Statistics.** Add more seeds and benign captures, an equivalence margin, and an IOC baseline.
6. **Lint.** Install and configure ESLint.

## 30. Confirmation

- Nothing was pushed.
- Nothing was merged into `main`.
- No history was rewritten.
- No `git add .` or `-A`, reset, clean or LFS operation was run.
- All four source branches are unchanged (§1–5).

## Acceptance checklist

- [x] Integration worktree and branch verified.
- [x] Source branches untouched.
- [x] No push and no merge into main.
- [x] Protected hashes identical.
- [x] JA4 discrepancy reproduced from an identifiable input.
- [x] Authoritative JA4 specification and reference identified.
- [x] Corrected JA4 validated against reference vectors (139/139).
- [x] Fingerprint implementation version recorded in metadata.
- [x] Incompatible fingerprint/model combinations fail closed.
- [x] Historical artifacts preserved.
- [x] Explicit dependency inventory.
- [x] Reassembly edge cases covered (synthetic).
- [x] Incomplete and malformed Hellos produce no fingerprint.
- [x] Live/offline parity tested (synthetic).
- [x] Changes versioned. Corpus v3 semantics were preserved rather than redefined; a corpus v4 was not built.
- [x] Sensor capabilities reported truthfully.
- [x] Genuine sensor validation distinguished from synthetic tests (none was genuine).
- [x] Benign-data limitations documented.
- [x] Recomputed tracks evaluated under comparable conditions.
- [x] Claims updated according to evidence.
- [x] Backend and frontend checks reported (lint not executable).
- [x] Granular commits.
- [x] This report.
- [ ] **Independent benign data acquired.** BLOCKED, because no admissible source is available.
- [ ] **Genuine Zeek, Suricata or eBPF validation.** BLOCKED, because none of the tools is installed and no eBPF program exists.
