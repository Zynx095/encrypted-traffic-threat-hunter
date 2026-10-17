# Cross-Phase Integration Report (Phases 8–12)

Date: 2026-10-17. Worktree: `D:\College\SOMESHIT DOWNLOADS\etth-integration`. Branch: `integration/phase-8-12-validation`.

Every count, hash and result below was measured during this task. Engineering status and scientific status are kept separate throughout:

| Status level | Reached? | Notes |
|---|---|---|
| Implemented | yes | |
| Tested | yes | |
| Executed | yes | the exploratory Phase 9/10 runs |
| Scientifically validated | **no** | |
| Publication-ready | **no** | |

## A. Git structure

| Branch | HEAD | Base | Role | Modified by this task |
|---|---|---|---|---|
| `main` | `327bbe3` (= `origin/main`) | — | baseline | no |
| `feat/phase-8-9-10-research-platform` | `540a58b` | `327bbe3`, 119 commits | Phases 8–10 | no |
| `research/phase-11-sensor-integration` | `b4e1cfb` | `327bbe3`, 12 commits | Phase 11 | no |
| `research/phase-12-paper-manuscript` | `7c609af` | `327bbe3`, 5 commits | Phase 12 | no |
| `integration/phase-8-12-validation` | `daf6b9b`, plus the commit adding this report | `540a58b` | this integration | yes |

**Strategy.**
- A new worktree was created from the Phase 8–10 HEAD.
- Phase 11 was merged with an ordinary `--no-ff` merge (`c980769`): no textual conflicts.
- Phase 12 was merged with an ordinary `--no-ff` merge (`6611f2b`): three add/add documentation conflicts, resolved by hand (§B).
- No rebase, reset, force or history rewrite. No source branch was modified or deleted. Nothing was merged into `main`.

**Commits added.**
- 28 first-parent commits, including this report: 26 regular commits and 2 merge commits.
- The merges bring the 17 source commits (12 + 5) into the branch with their history intact.

**Push.** Nothing was pushed. No branch has an upstream except `main`.

**Local, git-ignored copies in the integration worktree** (copied read-only from the Phase 8–10 worktree, never staged):
- `data/processed/v3` (160 MB);
- `data/model_registry/artifacts` (1.7 MB);
- 124 `predictions.parquet` files (37 MB);
- `frontend/node_modules`, from `npm ci`.

## B. Integration work

### Merge resolutions (Phase 12)

| File | Decision | Why |
|---|---|---|
| `docs/research/RESEARCH_CLAIM_LEDGER.md` | Kept the generated ledger and added a disposition table for the six Phase 12 claims | The generated ledger is computed from persisted artefacts. The Phase 12 claims predated Phase 8–10 and were kept, corrected, superseded, marked untested, or withdrawn. "Cross-sensor identity resolution" was withdrawn: it is not implemented |
| `docs/research/PAPER_READINESS_AUDIT.md` | Kept the evidence-based verdict and reconciled the Phase 12 items | The rubric scores (e.g. 52/100, novelty 8.5/10) have no defined procedure. Venues were kept as orientation only. The IOC baseline was adopted as future work |
| `docs/research/REPRODUCIBILITY_GUIDE.md` | Kept the Phase 8–10 guide; added the Phase 12 sensor and Phase 7 pilot sections | Preserves Phase 12's useful content |

### Contracts reconciled

`docs/integration/CROSS_PHASE_CONTRACTS.md` is the reference; `pipeline/canonical_flow.py` holds the code.

| Problem found (and confirmed) | Fix | Commit |
|---|---|---|
| **ETTH JA4 ≠ FoxIO JA4.** Sorted signature algorithms plus five other deviations. On the FoxIO reference vector, ETTH gives `…_0adf69b4533f`, FoxIO `…_e5627efa2ab1`. Sensor JA4 would always be "unseen", and fingerprint-only models flag unseen fingerprints | Tagged `ja4_implementation`. ETTH-JA4 models refuse other implementations. `generate_ja4` is **not** changed (that would silently redefine the corpus feature) | `acb92ac` |
| Sensor counters fed into features with different meanings: negotiated vs offered TLS version, selected vs offered ALPN, payload vs IP bytes | Kept apart (`tls_version_observed`, `alpn_negotiated`, `byte_count_semantics`). Flow-feature models refuse `SENSOR_AGGREGATE` provenance | `3c45c67`, `4ab0e22`, `d8e7180`, `acb92ac` |
| Fabricated values in the Phase 11 adapters: `0.0.0.0`, port 0, duration 0, rate = count, `serverhello_present` defaulting to True, non-TCP/UDP relabelled as TCP, JA3 strings in hash fields | Not produced any more; values are absent/`None` or rejected with a reason | same |
| Zeek: TTL expiry and full cache silently dropped `conn` records; duplicates re-emitted | Expired or overflowing records are emitted without TLS; duplicate and late records are counted | `3c45c67` |
| Suricata: duration from integer `flow.age`; alerts at risk of being read as labels | Duration is `flow.end − flow.start`. Alerts are context only, with a test showing they cannot change scores | `4ab0e22` |
| Sensor identity lost in events; missing values shown as 0 | `ProvenanceDetails.sensor` and `FlowDetails.unobserved_fields` (additive); the UI shows "not observed" | `eb6c154` |
| `/api/sensors/status` reported Zeek/Suricata `available: true` although nothing was running | Reports `adapter_available`, `ingestion_active`, `connected_to_live_stream` | `9dfec3e` |
| Live capture claimed `available` without a capture driver ("wpcap.dll missing" on this host) | Detects Scapy's placeholder socket | `9dfec3e` |
| **Live capture vs offline parity.** "Forward" was the lexicographically smaller endpoint; IP length included Ethernet padding; boundaries were 15 s / 60 s instead of 120 s / FIN; non-TCP/UDP packets created flows | Live now matches offline on identical synthetic packets (tolerance 1e-9). Splits at 300 s are flagged and refused | `722524c` |
| Attribution fell back to the initiator endpoint; IPv6 endpoints were parsed at the first `:` | Responder-only destination, `rsplit` parsing | `d0198be` |
| Absolute filesystem paths in model-load errors and job logs | `backend/redaction.py` | `d1fdd0b` |
| **Phase 10 re-runs always failed** after training (`'dict' object is not callable`): shadowing introduced by refactor `310e94c` after the recorded runs | Renamed the local dict; added an end-to-end regression test | `0a372ef` |
| Four replay lifecycle tests depended on git-ignored data | A synthetic replay table, with the assertions unchanged | `37227e6` |

### Integrated components

- All three branches' code.
- The sensor adapters, connected to the detection pipeline through the canonical contract. They are exercised by tests and tooling; the running server does not wire them in.
- Real-time inference with provenance gates.
- Research API and Workbench (paths redacted; job status reflects real exit codes).
- Reporting with a new `ml verify` command.
- The reconciled manuscript (one canonical copy) and the corrected sensor and research documentation.

### Still incompatible or incomplete

- **Sensors.** No runtime path from Zeek/Suricata/eBPF to the live stream. No cross-sensor correlation. No eBPF program. Sensor flows can be scored only by B_JA3, and detection on sensor telemetry is BLOCKED (C21).
- **JA4.** ETTH JA4 is non-conformant. ClientHellos are parsed from the first segment only.
- **Lint.** `npm run lint` cannot run: ESLint is referenced in `package.json` but is neither installed nor configured. This was already the case before the integration.

## C. Test results

**Backend.** Command: `python -m pytest -q -p no:cacheprovider`, Python 3.12.0, run from the integration worktree.

| Tree | Result |
|---|---|
| `main` `327bbe3` (clean export) | 143 passed, 1 failed (`test_13_replay_completed_transition`, pre-existing) |
| Phase 11 `b4e1cfb` (clean export) | 156 passed, 1 failed (same pre-existing test) |
| Phase 8–10 `540a58b`, clean checkout without ignored data | 229 passed, **4 failed** (data-dependent lifecycle tests) |
| Phase 8–10 `540a58b`, with local data | 233 passed |
| After the Phase 11 merge `c980769` (local data) | 246 passed |
| **Integration HEAD, with local data** | **362 passed, 0 failed** |
| **Integration HEAD, clean `git archive` export** (no `data/processed`, no model artefacts) | **362 passed, 0 failed** |

The single pre-existing failure on `main` and Phase 11, and the four data-dependent failures on Phase 8–10, no longer occur. No test was deleted, and no assertion was weakened.

The Phase 11 sensor tests used placeholder fingerprints such as `"abc123ja3hash"` and `"t13d1516h2_suricata"`. These inputs were replaced by syntactically valid synthetic values, because the contract now rejects placeholders. The tests' assertions that values are preserved are unchanged, and new tests check the rejection.

**Frontend.** `cd frontend && npm ci && npm run build` (`tsc -b && vite build`) passes. The chunk-size and dynamic-import warnings are pre-existing.

**Static checks.**
- `python -m pyflakes backend pipeline ml tests` reports 62 findings, the same count as Phase 8–10. All are unused imports or variables.
- No undefined names. The one redefinition, the Phase 10 bug, was fixed.
- No mypy or ruff configuration exists.

**Persisted research results.** `python -m ml verify` reports 124/124 experiment records VERIFIED:
- prediction checksums match;
- pooled AP, test FPR, recall and class counts recomputed from predictions match within 1e-9;
- re-derived claim statuses equal the committed ledger.

On the clean export, `verify` reports 124 MISSING: the predictions are git-ignored.

**Not run.**
- Native live capture: no Npcap/libpcap on this host.
- Native eBPF: Windows host, and no probe exists.
- Real Zeek or Suricata processes: not installed.
- Browser end-to-end UI tests: none exist.

## D. Sensor status

| Sensor | Validated | Not validated |
|---|---|---|
| Zeek | synthetic `conn`/`ssl` fixtures and unit tests: correlation in either order, duplicates, late records, expiry/overflow emission, nested `id`, semantics, rejection of placeholder fingerprints; pipeline and WebSocket integration | real Zeek logs; ja3/ja4 package output |
| Suricata | synthetic EVE fixture and unit tests: flow/tls/alert correlation, timestamp duration, ALPN lists, JA3 string to MD5, alerts not used as labels; pipeline and WebSocket integration | real Suricata output; byte-counter semantics (undocumented) |
| eBPF | JSON adapter and capability probe (Windows reports unavailable, with a reason); collector contract | any kernel attachment. **ETTH contains no eBPF program, loader or collector** |
| Live capture | parity with the offline pipeline on synthetic packets (6 flows, all FLOW features within 1e-9, TLS fields, direction, padding, boundaries); honest capability detection | packet capture on a real interface. This host has no capture driver |

## E. Research integrity

**Tracks.** All five tracks are executed in the Phase 9 suites. Exploratory results for the pre-declared primary model (random forest, capture-grouped CV):

| Track | AP |
|---|---|
| A | 0.931 [0.797, 0.986] |
| B | 0.971 |
| C | 0.994 |
| D | 0.988 |
| E | 0.991 |

All intervals are FEW_GROUPS, because there are only 6 benign captures.

**Verified vs exploratory.**
- Verified:
  - every persisted number reproduces from its predictions;
  - the engineering properties C01, C03, C14, C15 and C18–C20.
- Not verified:
  - no detection-performance claim is SUPPORTED;
  - every Phase 9/10 result is exploratory.

**Data and labels.**
- One benign source (DS-011, 2017 lab browsing). The READMEs of 5 of its 6 captures state Kali Linux/iceweasel; the file names of three say "win".
- Two malicious sources (Windows hosts).
- No benign TLS 1.3.
- Capture-level labels only.
- Sufficiency level C is NOT MET.

**Incremental JA3/JA4 benefit.** No result supports one.
- Random forest contrasts: Holm p ≥ 0.52.
- Logistic regression shows ΔAP +0.0004 / +0.0005 at AP ≈ 0.9994. This is significant within that model (Holm p 0.032 / 0.042), but not across all 12 model × contrast tests (p 0.096 / 0.154). It was disclosed in PHASE_9 §11 and is now also in the ledger evidence.
- Fingerprint "value" behaves like client-stack memorisation:
  - zero JA3/JA4 overlap between the classes;
  - 98% of unseen-stack benign flows flagged;
  - 0% or 100% detection of a held-out malicious source;
  - JA4 identifies the source with AP 1.000.

**Corrections made during the audit.**
- The benign environment had been described as "Linux". The recorded metadata is mixed.
- The logistic-regression sensitivity result was missing from the ledger.
- The Phase 10 re-run bug.

**Needed for confirmatory validation.**
1. Independent benign environments comparable to the malicious hosts, each held out once.
2. A frozen configuration evaluated a single time.
3. Flow-level labels or documented background filtering.
4. FoxIO-conformant JA4 with a corpus rebuild.
5. Multiple seeds and more benign captures.
6. A pre-registered equivalence margin, if "no benefit" is to be claimed.

## F. Manuscript status

`paper/manuscript/main.md` is the single canonical copy; `docs/research/manuscript/main.md` now points to it.

**Claims.**
- Every result was replaced with the persisted Phase 8–10 values.
- Unsupported content was removed:
  - the pilot metrics presented as results;
  - the sandbox-jitter feature-importance narrative;
  - "80 features", the "15 s timeout" and "mutually exclusive tracks";
  - the "Phase 10 not executed" statement.
- Engineering, exploratory findings and future work are now separated.
- The benign-data limitation, the failure to show a fingerprint benefit, JA4 non-conformance and the synthetic-only sensor validation are all disclosed.

**References.** Checked against publisher, venue or canonical sources:
- Anderson & McGrew, AISec 2016, pp. 35–46;
- Anderson & McGrew, KDD 2017, pp. 1723–1732;
- Arp et al., USENIX Security 2022, pp. 3971–3988;
- Sommer & Paxson, S&P 2010 (DOI);
- RFC 9849 (March 2026);
- JA3, JA4 and FoxIO sources;
- García et al. 2014;
- Paxson 1999;
- Suricata, MTA and Stratosphere pages.

Three errors were removed:
- a non-existent IEEE TNSM entry;
- JA4+ attributed to Brotherston;
- a wrong co-author in Arp et al.

**Provisional.** The whole draft: abstract, results, discussion and author list.

**Required before submission.** The experiments listed in §E, plus an IOC baseline.

## G. Protected data

The SHA-256 of all nine `data/verification/mta_stage65/MTA-C0{03,06,15,18,22,39,40,45,49}.zip` were taken at the start of the task and again at the end, in all four worktrees (Phase 8–10, Phase 11, Phase 12, integration). They are identical (baseline in `CROSS_PHASE_INITIAL_AUDIT.md` §5):
- start: 9/9 recorded;
- end: 9/9 OK in each worktree.

`git log 540a58b..HEAD --name-only` contains no MTA path, and none was ever staged. Their `M` status is the pre-existing LFS pointer mismatch (the content is identical), and it was left untouched. No `git lfs migrate` and no renormalisation were run.

## H. Commit ledger (`integration/phase-8-12-validation`, oldest first)

"pass" = the named tests passed when the commit was made.

| # | Commit | Message | Scope | Test evidence |
|---|---|---|---|---|
| 1 | `820d71f` | docs(integration): add cross-phase initial audit | Stage 1 audit | docs |
| 2 | `c980769` | merge: integrate Phase 11 sensor ingestion | merge of `b4e1cfb` | full suite: 246 pass |
| 3 | `6611f2b` | merge: integrate Phase 12 manuscript drafts | merge of `7c609af`; 3 conflict resolutions | docs only |
| 4 | `81952aa` | feat(integration): add canonical flow contract helpers | `pipeline/canonical_flow.py` | 20 pass |
| 5 | `3c45c67` | fix(sensors): adapt Zeek events to the canonical flow schema | Zeek adapter | 19 pass |
| 6 | `4ab0e22` | fix(sensors): adapt Suricata EVE events to the canonical flow schema | Suricata adapter | 13 pass |
| 7 | `d8e7180` | fix(sensors): enforce the canonical contract in the eBPF adapter | eBPF adapter | 11 pass |
| 8 | `acb92ac` | fix(inference): reject sensor aggregates and FoxIO JA4 for ETTH-trained models | inference gate, JA4 vector | 24 pass |
| 9 | `eb6c154` | fix(pipeline): carry sensor provenance and unobserved fields through events | schemas, pipeline, frontend types/UI, end-to-end tests | full: 313 pass; frontend build passes |
| 10 | `9dfec3e` | fix(api): report sensor adapters and capture capability honestly | status endpoint, capture capability | 2 + 58 pass |
| 11 | `722524c` | fix(live): align live capture flows and features with the offline pipeline | live capture parity | full: 320 pass |
| 12 | `d0198be` | fix(attribution): derive the destination only from the responder endpoint | target resolver | 59 pass |
| 13 | `37227e6` | test(integration): make replay lifecycle tests independent of ignored data | WebSocket lifecycle tests | clean export: 323 pass |
| 14 | `d1fdd0b` | fix(research): keep local paths out of model-load errors and job logs | redaction | 3 pass, plus API/registry tests |
| 15 | `6e45f94` | docs(integration): document cross-phase flow, inference and event contracts | contracts doc | docs |
| 16 | `346200b` | docs(sensors): correct Phase 11 sensor documentation to the integrated contract | `docs/sensors/*` | docs |
| 17 | `d3ec6ef` | feat(reporting): add `python -m ml verify` to re-check persisted results | verify module and CLI | 3 pass; 124/124 VERIFIED |
| 18 | `c9615c9` | feat(reporting): add sensor claims and secondary-model sensitivity to the ledger | `claims.py` | 3 pass (see note) |
| 19 | `2eccf57` | docs(research): regenerate report and claim ledger on the integration branch | generated report and ledger snapshot | verify: no differences |
| 20 | `682e1d6` | docs(paper): reconcile the manuscript with executed Phase 8-10 results | manuscript, pointer file | references web-checked |
| 21 | `e50ea6c` | docs(research): describe the benign environment as recorded, not as "Linux" | confounder wording | 3 pass |
| 22 | `e2c2be7` | docs(research): regenerate report after the benign-environment correction | generated report | verify: no differences |
| 23 | `ec524ea` | docs(research): update reproducibility guide and readiness audit for integration | docs | docs |
| 24 | `0a372ef` | fix(sequence): stop shadowing the contrast reading rule in the Phase 10 suite | Phase 10 runner | 9 pass, including the new end-to-end test |
| 25 | `e0ba255` | test(integration): run a Phase 9 suite end to end in a temporary registry | suite roots, end-to-end test | 15 pass |
| 26 | `6b48423` | test(integration): smoke-test every parameterless GET route for server errors | API smoke | full: 362 pass (local and clean) |
| 27 | `daf6b9b` | docs(readme): reflect Phases 11-12 integration status and current test count | README | docs |
| 28 | (this commit) | docs(integration): add final cross-phase integration report | this report | full: 362 pass; frontend build passes |

**Note on commit 18.** The commit message of `c9615c9` gives 0.168 for the cross-model Holm p of the logistic-regression JA4 contrast. The generated value is 0.154. The correction is recorded in `2eccf57`, and history was not rewritten.

## I. Remaining work, ranked

| Rank | Task | Type |
|---|---|---|
| 1 | Independent benign data comparable to the malicious environments, plus a never-used held-out source per class for a single frozen confirmatory run. This unblocks C02, C09 and any answer to RQ1/RQ2. Access must follow the dataset terms: registration, requests (DS-007, CIC), or authorised and consented collection | **research-data blocker** |
| 2 | Flow-level labels, or a documented and sensitivity-tested filter for background traffic in malware captures | research-data / protocol |
| 3 | FoxIO-conformant JA4 (as a separate function), corpus rebuild and suite re-run. Required for literature comparability and for using sensor JA4 at all | engineering → research |
| 4 | ClientHello reassembly across TCP segments (offline and live) | engineering |
| 5 | Multiple seeds, more benign captures, a pre-registered equivalence margin, and an IOC (hash-lookup) baseline | research protocol |
| 6 | Labelled, authorised sensor telemetry and a sensor-aware model (C21) | **research-data blocker** |
| 7 | A runtime sensor ingestion path (authenticated log tailing or push API with back-pressure), cross-sensor correlation, validation against real Zeek/Suricata on a shared authorised PCAP, and a real eBPF collector if host telemetry is wanted | engineering |
| 8 | Native live-capture validation on a host with Npcap/libpcap | engineering (environment) |
| 9 | ESLint installation and configuration; clean up pre-existing unused imports and `datetime.utcnow` deprecations | engineering hygiene |
| 10 | Review, push and pull-request decisions for `integration/phase-8-12-validation`. Nothing has been pushed or merged | user decision |
