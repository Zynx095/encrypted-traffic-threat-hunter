# Paper-Readiness Audit (after Phases 8-10)

**Verdict: NOT PUBLICATION-READY.** The system is implemented, tested and executed, and it produces honest exploratory evidence. The data cannot yet support the central generalisation claim, so the research question remains **open**. A publishable contribution may still come from an honest negative or methodological result (see §3).

| Criterion | Assessment | Evidence |
|---|---|---|
| Research novelty evidence | **Weak.** Combining JA3/JA4 with flow features has precedent (see `docs/research/literature/`). Novelty would have to come from a rigorous source-aware evaluation, not from the fusion itself. | literature matrix |
| Related-work requirements | Partial: an annotated bibliography exists. A systematic comparison with prior fingerprint+flow results on shared data is missing. | `docs/research/literature/` |
| Dataset representativeness | **Insufficient.** 1 benign source (2017 Stratosphere lab browsing, 6 captures; mostly Kali Linux/iceweasel 43 per the READMEs, with recorded OS-metadata conflicts) against 2 malicious sources (Windows malware VMs, 19 captures). No benign TLS 1.3. | `data/corpus/sufficiency_assessment.json` (levels C and D NOT MET) |
| Provenance completeness | Good for raw captures: SHA-256 for every file, acquisition log and capture-level metadata (mean field completeness 0.84). Weak for labels: capture-level only. | `data/corpus/artifact_manifest.json`, `capture_plan.json` |
| Leakage controls | Strong. Allow-list feature governance; capture-level splits with duplicate purging; training-only preprocessing, selection, calibration and thresholds. Each is tested. | Phase 9 §§1-4; `tests/test_feature_governance_and_splits.py`, `tests/test_benchmark_metrics.py` |
| Evaluation rigour | Good protocol (nested, capture-grouped, pre-declared contrasts, Holm). It is limited by the data: dataset identity equals class, so no protocol can separate behaviour from source. | Phase 9 §§3-6 |
| Baseline strength | Adequate: prevalence floor, L2-LR, RF and HGB with nested selection; information-matched and full-flow baselines for Phase 10. No external SOTA re-implementation. | suites |
| Uncertainty | Capture-level bootstrap. With only 6 benign captures every interval is FEW_GROUPS and likely too narrow. | suite summaries |
| Statistical methodology | Paired capture bootstrap and Holm over 4 contrasts; no equivalence claims. One seed per configuration. | `ml/evaluation/uncertainty.py` |
| Reproducibility | Strong: deterministic rebuild verified (C01); immutable registry; seeds; environment snapshots; reproduction commands. Raw data must be re-acquired (URLs and checksums recorded). | `REPRODUCIBILITY_GUIDE.md` |
| External validity | **Not established.** Confirmatory evaluation is BLOCKED; no independent benign source. | ledger C09 |
| Ethics and privacy | No decryption, interception or local capture. Public datasets are used under their stated terms. CTU-Normal captures contain the collector's own browsing (published by the lab). Raw PCAPs stay local and git-ignored; the model matrix excludes SNI strings and endpoints. | Phase 8 §2 |

## 1. What would make the work publishable

1. **Independent benign data from the same kinds of environment as the malicious data.** Examples: Windows hosts with modern browsers and enterprise software (CIC datasets after registration, DS-007 by request, or an authorised and consented local collection).
2. **At least one held-out source per class** that was never used during exploration, evaluated once with a frozen configuration (the confirmatory policy).
3. **Flow-level labels**, or at least removal of benign background traffic from malware captures. Example: allow-listing well-known OS telemetry by SNI or destination, documented as a labelling rule and evaluated for sensitivity.
4. **JA4 conformance:** replace or annotate the ETTH JA4 implementation to match the FoxIO specification, so results can be compared with the literature.
5. **ClientHello reassembly across TCP segments.** Modern post-quantum key shares exceed one segment.
6. **Multiple seeds and more benign captures**, so intervals stop being FEW_GROUPS.

## 2. What the current evidence can support

See `RESEARCH_CLAIM_LEDGER.md`. In short: engineering and reproducibility claims are SUPPORTED. Every detection-performance claim is at most PRELIMINARY. The central generalisation claim is BLOCKED.

## 3. Candidate honest contributions

* A **methodological negative result**, supported by the exploratory evidence in PHASE_9 §11:
  * Under the legacy behaviour-hash split, every track looks near-perfect (fingerprint tracks AP 1.000 at 0.4 % FPR).
  * Under capture-grouped evaluation, fingerprint-only models flag about 98 % of benign flows whose client stack was not in training, for an 18 % test FPR.
  * Held-out malicious sources are detected at 0 % or 100 % depending only on how unseen fingerprints are scored.
  * JA4 identifies the collection source perfectly (AP 1.000 for DS-008 vs DS-009).
  * Flow-only AP drops from 0.93 to 0.71 when families are held out.
  * The availability probe alone reaches AP 0.77 against a 0.60 prevalence.
  * In this corpus fingerprint "value" is client-stack memorisation, and the legacy protocol hides it.
* An **open, reproducible, leakage-audited benchmark harness** for fingerprint+flow fusion. It enforces feature governance and source-aware splits, and the claim ledger states exactly what is not yet known.

## 4. Reconciliation with the Phase 12 draft audit

The Phase 12 branch (`7c609af`) contained a separate audit, *ETTH Academic Paper Readiness & Peer-Review Audit*. It was written against the Phase 7 pilot. The verdicts above are kept. The Phase 12 audit's items were handled as follows.

| Phase 12 item | Disposition |
|---|---|
| "Readiness score 52/100" and rubric scores (novelty 8.5/10, rigour 9.0/10, reproducibility 8.5/10) | **Not adopted.** No defined scoring procedure supports these numbers, and they contradict the evidence-based assessment above (novelty *weak*; external validity *not established*). |
| Engineering described as "production-grade and scientifically rigorous" | **Not adopted.** The platform is a tested research prototype. Its models are research pilots with status `RESEARCH_PILOT_SOURCE_CONFOUNDED`. |
| Dataset deficiency (424:1 pilot ratio, 6 benign flows) | **Superseded.** Corpus v3 has 577,238 flows from 25 captures, including 6 benign CTU-Normal captures. The structural blocker remains: each dataset contributes only one class, and there is a single benign source. |
| Missing neural baselines | **Done in Phase 10.** The CNN and GRU were run with information-matched tabular baselines; see C13. |
| Missing hash-lookup (IOC) baseline | **Adopted as future work.** A JA3/JA4 blocklist baseline would show how much of B/C is plain memorisation. With a JA3/JA4 class overlap of 0 (C03), it would be expected to be near-perfect in-sample and to fail on unseen fingerprints (C16). |
| SHAP/LIME attributions | **Partly addressed.** `python -m ml explain` reports permutation importance on held-out folds. Feature importance is associative and is never presented as causal. |
| "143/144 tests passing" | **Outdated.** See `docs/integration/CROSS_PHASE_INTEGRATION_REPORT.md` for current results. |
| Target venues (RAID, ACSAC, CoNEXT/WiSec, S&P/USENIX Security) | **Kept as orientation only.** No deadlines were verified. Choosing a venue is premature until a confirmatory evaluation exists. An honest negative or methodological result (§3) fits venues that accept measurement and evaluation-methodology papers. |
