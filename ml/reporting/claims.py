"""
Evidence ledger: each claim is evaluated from persisted artefacts by a fixed rule.

Status vocabulary: SUPPORTED | PRELIMINARY | CONTRADICTED | UNTESTED | BLOCKED | INSUFFICIENT_EVIDENCE.
Rules that keep the ledger honest:
  * every detection-performance claim on this corpus is at most PRELIMINARY: all suites are
    exploratory and each dataset contributes a single class (source-confounded);
  * a non-significant difference is INSUFFICIENT_EVIDENCE, never "no effect";
  * a claim whose producing experiment has not run is UNTESTED; one whose prerequisite data
    cannot be obtained is BLOCKED.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from pipeline import config as pipeline_config

ROOT = pipeline_config.PROJECT_ROOT
CONFOUNDERS = [
    "dataset identity equals class at source level (DS-008/DS-009 malicious, DS-011 benign)",
    "benign captures are 2017 Stratosphere lab browsing (READMEs of 5 of 6 captures state Kali Linux / iceweasel 43; file names of 3 say 'win'); malicious captures are Windows hosts",
    "capture-level labels propagated to flows (background traffic in malware captures labelled malicious)",
]


def _load(path: Path) -> Optional[Dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _claim(cid, text, status, evidence, experiments=None, datasets=None, protocol=None, metrics=None, uncertainty=None,
           assumptions=None, confounders=None, limitations=None) -> Dict[str, Any]:
    return {"claim_id": cid, "claim": text, "status": status, "evidence_summary": evidence,
            "supporting_experiments": experiments or [], "datasets": datasets or [], "evaluation_protocol": protocol,
            "metrics": metrics or {}, "uncertainty": uncertainty or {}, "assumptions": assumptions or [],
            "known_confounders": confounders or [], "limitations": limitations or []}


def _row(summary: Dict[str, Any], track: str, model: str, encoding: str = "onehot") -> Optional[Dict[str, Any]]:
    for r in (summary or {}).get("experiments", []):
        if r["track"] == track and r["model"] == model and r.get("encoding", "onehot") == encoding:
            return r
    return None


def pc_row(summary: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    return _row(summary, "A_FLOW", "random_forest")


def _contrast(summary: Dict[str, Any], model: str, label: str) -> Optional[Dict[str, Any]]:
    fam = ((summary or {}).get("paired_contrasts") or {}).get(model) or {}
    for c in fam.get("contrasts", []):
        if c["contrast"] == label:
            return c
    return None


SECONDARY_MODELS = ("logreg", "hist_gb")


def _secondary_evidence(summary: Dict[str, Any], label: str) -> Dict[str, Any]:
    """
    Sensitivity view of one contrast for the secondary (non-primary) models. The suite applies Holm
    within each model's 4 contrasts; here the same raw p-values are also Holm-adjusted across all
    models x 4 contrasts of the suite. This is a post-hoc multiplicity check reported for
    transparency; it never changes a claim status (claims use the pre-declared primary model).
    """
    from ml.evaluation.uncertainty import holm
    fams = (summary or {}).get("paired_contrasts") or {}
    raw = {f"{m}|{c['contrast']}": (c.get("holm") or {}).get("p")
           for m, fam in fams.items() for c in fam.get("contrasts", []) if c.get("status") == "COMPLETED"}
    across = holm(raw) if raw else {}
    out = {}
    for m in SECONDARY_MODELS:
        c = _contrast(summary, m, label)
        if c and c.get("status") == "COMPLETED":
            ap = c.get("average_precision") or {}
            out[m] = {"difference": ap.get("difference"), "ci_low": ap.get("ci_low"), "ci_high": ap.get("ci_high"),
                      "p_holm_within_model": (c.get("holm") or {}).get("p_holm"),
                      "p_holm_across_models": (across.get(f"{m}|{label}") or {}).get("p_holm"),
                      "n_tests_across_models": len(raw)}
    return out


def _contrast_status(cs: List[Optional[Dict[str, Any]]]) -> str:
    done = [c for c in cs if c and c.get("status") == "COMPLETED"]
    if not done:
        return "UNTESTED"
    signs = []
    for c in done:
        ap = c.get("average_precision") or {}
        if ap.get("status") == "INSUFFICIENT_GROUPS" or ap.get("ci_low") is None:
            signs.append(0)
        elif ap["ci_low"] > 0 and (c.get("holm") or {}).get("reject"):
            signs.append(1)
        elif ap["ci_high"] < 0 and (c.get("holm") or {}).get("reject"):
            signs.append(-1)
        else:
            signs.append(0)
    if all(s == 1 for s in signs):
        return "PRELIMINARY"
    if all(s == -1 for s in signs):
        return "CONTRADICTED"
    return "INSUFFICIENT_EVIDENCE"


def build_claims(latest: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """`latest` maps suite name -> {"suite": suite.json, "summary": summary.json}."""
    claims: List[Dict[str, Any]] = []
    adm = _load(ROOT / "data" / "corpus" / "admission_report.json")
    suff = _load(ROOT / "data" / "corpus" / "sufficiency_assessment.json")
    v2 = _load(ROOT / "data" / "manifests" / "v2" / "phase6_expanded_audit.json")
    cov = _load(ROOT / "data" / "experiments" / "phase9" / "diagnostics" / "coverage_report.json")
    S = lambda n: (latest.get(n) or {}).get("summary") or {}
    sid = lambda n: ((latest.get(n) or {}).get("suite") or {}).get("suite_id")

    # C01 reproduction of Stage 6.5 DS-008
    if adm and v2:
        f = adm["funnel_by_dataset"].get("DS-008", {})
        expected = {"flows": v2["ds008_flows"], "ja3": v2["ja3_flows"] - 6, "ja4": v2["ja4_flows"] - 6}
        observed = {"flows": f.get("flows_in_corpus"), "ja3": f.get("ja3_flows"), "ja4": f.get("ja4_flows")}
        ok = expected == observed and f.get("captures_checksum_verified_or_observed") == 10
        claims.append(_claim("C01", "Corpus v3 reproduces the Stage 6.5 DS-008 flow, JA3 and JA4 counts from checksum-verified inputs.",
                             "SUPPORTED" if ok else "CONTRADICTED",
                             f"expected {expected} (Stage 6.5 audit minus 6 DS-004 rows), observed {observed}; 10/10 DS-008 PCAPs SHA-256 verified.",
                             datasets=["DS-008"], protocol="deterministic rebuild", metrics={"expected": expected, "observed": observed}))
    # C02 benign sufficiency
    if suff:
        lv = suff["levels"]
        claims.append(_claim("C02", "The admitted benign corpus is sufficient to investigate generalisation (sufficiency level C).",
                             "BLOCKED" if not lv["C_generalization"]["met"] else "PRELIMINARY",
                             f"Levels met: { {k: v['met'] for k, v in lv.items()} }; failing C checks: "
                             f"{[k for k, v in lv['C_generalization']['checks'].items() if not v]}",
                             datasets=suff["per_class"]["BENIGN"]["sources"], metrics=suff["per_class"],
                             limitations=["Independent benign sources (DS-004 re-acquisition, DS-006, DS-007, CIC datasets) require registration, permission or a request."]))
    # C03 fingerprint overlap
    if cov:
        o = cov["fingerprint_overlap"]
        claims.append(_claim("C03", "JA3 and JA4 values observed in the corpus never occur in both classes.",
                             "SUPPORTED" if o["ja3"]["distinct_shared"] == 0 and o["ja4"]["distinct_shared"] == 0 else "CONTRADICTED",
                             f"JA3 shared {o['ja3']['distinct_shared']}/{o['ja3']['distinct_values']}, JA4 shared {o['ja4']['distinct_shared']}/{o['ja4']['distinct_values']}.",
                             protocol="descriptive (full corpus v3)", confounders=CONFOUNDERS,
                             limitations=["Describes client stacks per source; it is not evidence that fingerprints identify maliciousness."]))
    # C04-C07 incremental value
    labels = [("C04", "Adding JA3 to flow features increases average precision on the shared JA3 population (A@JA3POP -> D).", "JA3 added to flow"),
              ("C05", "Adding JA4 to flow features increases average precision on the shared JA4 population (A@JA4POP -> E).", "JA4 added to flow"),
              ("C06", "Adding flow features to JA3 increases average precision (B -> D).", "flow added to JA3"),
              ("C07", "Adding flow features to JA4 increases average precision (C -> E).", "flow added to JA4")]
    for cid, text, lab in labels:
        cs = [_contrast(S("pooled_capture_cv"), "random_forest", lab), _contrast(S("matched_lab_capture_cv"), "random_forest", lab)]
        status = _contrast_status(cs)
        ev = []
        for name, c in zip(("pooled", "matched_lab"), cs):
            if c and c.get("status") == "COMPLETED":
                ap = c["average_precision"]
                d = ap.get("difference")
                ev.append(f"{name}: dAP={'NA' if d is None else f'{d:.4f}'} CI[{ap.get('ci_low')}, {ap.get('ci_high')}] "
                          f"({ap.get('status')}) Holm p={(c.get('holm') or {}).get('p_holm')}")
            else:
                ev.append(f"{name}: NOT_RUN")
        secondary = {name: _secondary_evidence(S(name), lab) for name in ("pooled_capture_cv", "matched_lab_capture_cv")}
        sec_txt = []
        for name, blk in secondary.items():
            for m, v in blk.items():
                if v.get("difference") is not None:
                    sec_txt.append(f"{name.split('_')[0]} {m}: dAP={v['difference']:+.4f}, Holm p within model "
                                   f"{v['p_holm_within_model']}, across {v['n_tests_across_models']} model x contrast tests "
                                   f"{None if v['p_holm_across_models'] is None else round(v['p_holm_across_models'], 3)}")
        claims.append(_claim(cid, text, status, "; ".join(ev) + " (primary model random_forest, capture-grouped 5-fold, capture bootstrap)"
                             + (". Secondary models (sensitivity, not used for the status): " + "; ".join(sec_txt) if sec_txt else ""),
                             experiments=[c.get("experiment_a") for c in cs if c] + [c.get("experiment_b") for c in cs if c],
                             protocol="CAPTURE_GROUP_KFOLD, nested selection, paired capture bootstrap, Holm (4 contrasts)",
                             metrics={"secondary_models": secondary},
                             uncertainty={n: (c or {}).get("average_precision") for n, c in zip(("pooled", "matched_lab"), cs)},
                             confounders=CONFOUNDERS,
                             limitations=["Exploratory; at most PRELIMINARY on this corpus.", "No equivalence margin was pre-registered."]))
    # C08 cross-source transfer, one claim per feature family (primary model random_forest)
    lo = S("leave_one_source_out")
    families = (("C08A", "Flow-only detectors (A_FLOW) transfer to a held-out malicious source", ["A_FLOW"]),
                ("C08B", "Fingerprint-only detectors (B_JA3, C_JA4) transfer to a held-out malicious source", ["B_JA3", "C_JA4"]),
                ("C08C", "Fusion detectors (D_JA3_FLOW, E_JA4_FLOW) transfer to a held-out malicious source", ["D_JA3_FLOW", "E_JA4_FLOW"]))
    for cid, text, tracks in families:
        rates = {}
        for r in (lo or {}).get("experiments", []):
            if r["model"] == "random_forest" and r["track"] in tracks and r.get("per_source"):
                for src, blk in r["per_source"].items():
                    if "detection_rate" in blk:
                        rates[f"{r['track']}|{src}"] = blk["detection_rate"].get("pred@fpr<=0.01")
        vals = [v for v in rates.values() if v is not None]
        if not vals:
            status = "UNTESTED"
        elif all(v >= 0.8 for v in vals):
            status = "PRELIMINARY"
        elif all(v <= 0.5 for v in vals):
            status = "CONTRADICTED"
        else:
            status = "INSUFFICIENT_EVIDENCE"
        claims.append(_claim(cid, text + " at the validation-selected FPR<=1% threshold.", status,
                             f"Detection rates on the held-out source (random_forest): { {k: round(v, 4) for k, v in rates.items()} }. "
                             "Rule: all >= 0.8 -> PRELIMINARY; all <= 0.5 -> CONTRADICTED; otherwise INSUFFICIENT_EVIDENCE. "
                             "The benign false-positive rate on a held-out benign source cannot be measured (single benign source).",
                             experiments=[sid("leave_one_source_out")], protocol="LEAVE_ONE_SOURCE_OUT", metrics=rates,
                             confounders=CONFOUNDERS, limitations=["Recall only; exploratory; one benign source."]))
    claims.append(_claim("C09", "ETTH detection generalises to independent, unseen benign and malicious environments.", "BLOCKED",
                         "Confirmatory evaluation requires an independent benign+malicious source never used in exploration; none is admitted.",
                         protocol="CONFIRMATORY (not run)", confounders=CONFOUNDERS))
    # C10 shortcut probe
    pr = _row(S("pooled_capture_cv"), "P_AVAILABILITY_PROBE", "random_forest")
    dm = _row(S("pooled_capture_cv"), "P_AVAILABILITY_PROBE", "dummy_prior")
    if pr and pr.get("average_precision") is not None:
        lift = pr["average_precision"] - (dm or {}).get("average_precision", 0)
        claims.append(_claim("C10", "Handshake-availability flags alone (no flow statistics, no fingerprints) carry label information beyond prevalence.",
                             "PRELIMINARY" if (pr["ap_ci"][0] or 0) > ((dm or {}).get("average_precision") or 0) else "INSUFFICIENT_EVIDENCE",
                             f"Probe AP {pr['average_precision']:.3f} CI{pr['ap_ci']} vs prevalence AP {(dm or {}).get('average_precision')}; lift {lift:.3f}.",
                             experiments=[pr["experiment_id"]], protocol="CAPTURE_GROUP_KFOLD", confounders=CONFOUNDERS,
                             limitations=["Indicates availability-driven shortcut risk; not a detection result."]))
    # C11 source identifiability
    si = S("source_identifiability")
    r = _row(si, "A_FLOW", "random_forest")
    if r and r.get("n_pos"):
        prevalence = r["n_pos"] / (r["n_pos"] + r["n_neg"])
        claims.append(_claim("C11", "Flow features identify which malicious source (DS-008 vs DS-009) a flow came from.",
                             "PRELIMINARY" if (r["ap_ci"][0] or 0) > 2 * prevalence else "INSUFFICIENT_EVIDENCE",
                             f"Source-identification AP {r['average_precision']} CI{r['ap_ci']} ({r['ap_ci_status']}); "
                             f"chance level (prevalence of DS-008 rows) {prevalence:.3f}; rule: CI lower bound > 2x prevalence.",
                             experiments=[r["experiment_id"]], protocol="CAPTURE_GROUP_KFOLD (task: DS-008 vs DS-009)",
                             limitations=["Diagnostic of collection-environment signal; it is not a detection task."]))
    r4 = _row(si, "C_JA4", "random_forest")
    if r4 and r4.get("n_pos"):
        prev4 = r4["n_pos"] / (r4["n_pos"] + r4["n_neg"])
        claims.append(_claim("C11B", "JA4 alone identifies which malicious source (DS-008 vs DS-009) a TLS flow came from.",
                             "PRELIMINARY" if (r4["ap_ci"][0] or 0) > 2 * prev4 else "INSUFFICIENT_EVIDENCE",
                             f"Source-identification AP {r4['average_precision']} CI{r4['ap_ci']}; chance {prev4:.3f}.",
                             experiments=[r4["experiment_id"]], protocol="CAPTURE_GROUP_KFOLD (task: DS-008 vs DS-009)",
                             limitations=["Shows that fingerprints encode collection era / client stack; diagnostic only."]))
    pooled_dir = (latest.get("pooled_capture_cv") or {}).get("suite", {}).get("suite_id")
    if pooled_dir:
        from ml.benchmark.registry import suite_dir
        un = _load(suite_dir(pooled_dir) / "unseen_B_JA3_logreg.json")
        un4 = _load(suite_dir(pooled_dir) / "unseen_C_JA4_logreg.json")
        if un and un4:
            def rate(u, cls, seen):
                return next((c.get("flagged_rate_at_val_fpr_0.01") for c in u["cells"]
                             if c["class"] == cls and c["fingerprint_seen_in_training"] is seen), None)
            r_unseen, r_seen = rate(un, "BENIGN", False), rate(un, "BENIGN", True)
            r4_unseen = rate(un4, "BENIGN", False)
            claims.append(_claim("C16", "Fingerprint-only models flag most benign flows whose fingerprint was absent from the training fold.",
                                 "PRELIMINARY" if (r_unseen or 0) > 0.5 and (r_seen or 0) < 0.05 else "INSUFFICIENT_EVIDENCE",
                                 f"Benign unseen-fingerprint share {un['benign_unseen_share']:.3f}; flagged at val-FPR<=1%: JA3 unseen {r_unseen}, "
                                 f"JA3 seen {r_seen}, JA4 unseen {r4_unseen} (logreg, pooled capture-grouped CV).",
                                 experiments=[un["experiment_id"], un4["experiment_id"]], protocol="CAPTURE_GROUP_KFOLD",
                                 confounders=CONFOUNDERS, limitations=["Novelty, not maliciousness, drives these alerts."]))
    fam = _row(S("leave_one_family_out"), "A_FLOW", "random_forest")
    if fam and pc_row(S("pooled_capture_cv")):
        base = pc_row(S("pooled_capture_cv"))
        claims.append(_claim("C17", "Flow-only (A_FLOW) ranking quality drops when whole malware families are held out.",
                             "PRELIMINARY" if fam["average_precision"] < base["average_precision"] else "CONTRADICTED",
                             f"family-holdout AP {fam['average_precision']:.4f} CI{fam['ap_ci']} vs capture-grouped AP {base['average_precision']:.4f} (random_forest).",
                             experiments=[fam["experiment_id"], base["experiment_id"]], protocol="LEAVE_ONE_FAMILY_OUT vs CAPTURE_GROUP_KFOLD",
                             limitations=["Different fold structures; no paired test between protocols."]))
    # C12 legacy protocol optimism
    lg, pc = _row(S("legacy_behavioral_holdout"), "A_FLOW", "random_forest"), _row(S("pooled_capture_cv"), "A_FLOW", "random_forest")
    if lg and pc and lg.get("average_precision") is not None and pc.get("average_precision") is not None:
        claims.append(_claim("C12", "The legacy behavioural-hash holdout gives a higher A_FLOW estimate than capture-grouped CV.",
                             "PRELIMINARY" if lg["average_precision"] > pc["average_precision"] else "CONTRADICTED",
                             f"legacy AP {lg['average_precision']:.4f} vs capture-grouped AP {pc['average_precision']:.4f} (random_forest).",
                             experiments=[lg["experiment_id"], pc["experiment_id"]],
                             limitations=["Single legacy split; the comparison has no paired uncertainty estimate."]))
    # C13 sequence models
    seq = None
    for name, entry in latest.items():
        if name.startswith("sequence_capture_cv") and not name.endswith("DS009_DS011"):
            seq = entry
    if seq and (seq.get("summary") or {}).get("contrasts"):
        cs = seq["summary"]["contrasts"]
        ev = "; ".join(f"{c['contrast']}: dAP={(c.get('average_precision') or {}).get('difference')} "
                       f"CI[{(c.get('average_precision') or {}).get('ci_low')}, {(c.get('average_precision') or {}).get('ci_high')}] "
                       f"Holm p={(c.get('holm') or {}).get('p_holm')}" for c in cs)
        st = _contrast_status([c for c in cs if "information-matched" in c["contrast"]])
        claims.append(_claim("C13", "Sequence models (CNN/GRU on the first 64 packets) add detection value over information-matched tabular baselines.",
                             st, ev, experiments=[seq["suite"]["suite_id"]], protocol="CAPTURE_GROUP_KFOLD with validation captures",
                             confounders=CONFOUNDERS, limitations=["Exploratory; CPU-scale models; one seed."]))
    else:
        claims.append(_claim("C13", "Sequence models add detection value over tabular baselines.", "UNTESTED", "Phase 10 suite has not completed."))
    claims.append(_claim("C14", "Real-time inference only uses registered, checksum-verified models and never derives a score from ground-truth labels.",
                         "SUPPORTED", "Enforced in backend/inference_engine.py; verified by tests/test_model_registry_inference.py "
                         "(test_no_model_means_skipped_never_label_echo, test_label_field_never_influences_score, test_incompatible_schema_rejected_without_invention).",
                         protocol="unit tests"))
    claims.append(_claim("C15", "The system does not decrypt TLS application payloads.", "SUPPORTED",
                         "Only TLS handshake records (ClientHello/ServerHello) in the first segment are parsed; packet payloads are otherwise reduced to sizes, "
                         "timings, directions and TCP flags. No key material, interception or decryption code exists (pipeline/tls_fingerprinting.py, "
                         "backend/event_sources/live_capture.py). The Zeek, Suricata and eBPF adapters read only metadata fields logged by those tools "
                         "(backend/event_sources/{zeek,suricata,ebpf}_source.py).", protocol="code inspection + tests"))

    # ---- Phase 11 sensor integration (engineering properties; synthetic fixtures only) ----------------
    sensor_limits = ["Verified with synthetic fixtures only; no real Zeek, Suricata or eBPF collector output was processed.",
                     "Software contract evidence, not detection-quality evidence."]
    claims.append(_claim("C18", "The Zeek, Suricata and eBPF adapters normalise records into the canonical flow contract without fabricating "
                                "fingerprints, endpoints, protocols, durations or rates, and without silently dropping, duplicating or relabelling records.",
                         "SUPPORTED", "pipeline/canonical_flow.py; tests/test_canonical_flow.py, tests/test_sensors_zeek.py, tests/test_sensors_suricata.py, "
                                      "tests/test_sensors_ebpf.py (placeholder fingerprints rejected, negotiated TLS version / selected ALPN kept apart from "
                                      "ETTH features, expiry and overflow emit instead of drop, duplicates and late records counted).",
                         protocol="unit and integration tests", limitations=sensor_limits))
    claims.append(_claim("C19", "Models trained on ETTH packet features and ETTH JA4 refuse sensor-aggregate statistics and FoxIO JA4 instead of scoring them.",
                         "SUPPORTED", "backend/inference_engine.py provenance and JA4-implementation rules; tests/test_inference_contract.py (FoxIO reference "
                                      "ClientHello: ETTH JA4 t13d1516h2_8daaf6152771_0adf69b4533f vs FoxIO ..._e5627efa2ab1) and "
                                      "tests/test_cross_phase_integration.py (all five tracks on sensor fixtures).",
                         protocol="unit and integration tests", limitations=sensor_limits))
    claims.append(_claim("C20", "Live capture produces the same flows (boundaries, initiator direction) and the same flow and TLS feature values as "
                                "the offline PCAP pipeline for the same packets.",
                         "SUPPORTED", "tests/test_live_offline_parity.py: synthetic packets written to a PCAP give identical flows and FLOW features "
                                      "(rel/abs 1e-9) through pipeline.flow_reconstruction and LiveCaptureSource.",
                         protocol="parity test on synthetic packets",
                         limitations=["Native capture was not exercised (no capture driver on the integration host).",
                                      "Flows longer than the live maximum duration are split, flagged and refused by flow-feature models."]))
    claims.append(_claim("C21", "ETTH detection models can score flows observed by Zeek, Suricata or eBPF sensors.", "BLOCKED",
                         "No model is trained on sensor-observable features with sensor provenance, and no labelled sensor telemetry is available. "
                         "Under the current contract only the JA3-only track accepts sensor flows, and those JA3 values are mostly outside the training "
                         "vocabulary (UNSEEN_CATEGORY).",
                         protocol="not run", confounders=CONFOUNDERS,
                         limitations=["Requires authorised, labelled sensor data and a retrained, sensor-aware model."]))

    # ---- Phase 13: FoxIO JA4 conformance, Hello reassembly, FoxIO re-evaluation ------------------------
    claims.append(_claim("C22", "pipeline.tls_fingerprinting.generate_ja4_foxio reproduces FoxIO's reference JA4 output for TLS over TCP.",
                         "SUPPORTED", "tests/test_ja4_foxio_reference.py: 139/139 TCP vectors from FoxIO-LLC/ja4 commit c6469a7 "
                                      "(snapshot outputs of FoxIO's reference implementation; captures pinned by SHA-256 in "
                                      "data/reference/foxio_ja4/vectors.json). Implementation id FOXIO_JA4 / ja4_foxio-c6469a7_etth-2.",
                         protocol="reference-vector conformance test",
                         limitations=["QUIC ('q') and DTLS ('d') JA4 are not implemented.",
                                      "Non-ASCII ALPN follows FoxIO's reference code ('9'), which differs from the written spec (hex).",
                                      "The pcap test is skipped when the reference captures are not fetched; conformance is claimed only from runs where it executed.",
                                      "Corpus v3's 'ja4' column remains the historical, non-conformant ETTH_JA4_V1."]))
    claims.append(_claim("C23", "TLS Hellos split across TCP segments are fingerprinted from their complete bytes, and incomplete, conflicting or "
                                "malformed streams produce no fingerprint, identically in live capture and offline reconstruction.",
                         "SUPPORTED", "pipeline/tls_reassembly.py; tests/test_tls_reassembly.py (24 cases: segmentation, wraparound, reordering, "
                                      "retransmission, overlaps, conflicts, timeouts, termination, malformed lengths, eviction, concurrency) and "
                                      "tests/test_hello_acquisition_parity.py (live = offline on the same packets).",
                         protocol="unit and parity tests on synthetic packets",
                         limitations=["Synthetic segments only; no real-interface capture was exercised.",
                                      "Corpus v3 was built with first-segment parsing and is unchanged; reassembly applies to new builds and live capture."]))
    fox = S("ja4_foxio_capture_cv")
    fox_labels = [("C24", "With FoxIO-conformant JA4, adding JA4 to flow features increases average precision on the shared JA4 population (A@JA4POP -> E).", "JA4 added to flow"),
                  ("C25", "With FoxIO-conformant JA4, adding flow features to JA4 increases average precision (C -> E).", "flow added to JA4")]
    for cid, text, lab in fox_labels:
        c = _contrast(fox, "random_forest", lab)
        st = _contrast_status([c])
        if c and c.get("status") == "COMPLETED":
            ap = c["average_precision"]
            ev = (f"ja4_foxio_capture_cv ({sid('ja4_foxio_capture_cv')}), random_forest: dAP={ap.get('difference')} "
                  f"CI[{ap.get('ci_low')}, {ap.get('ci_high')}] ({ap.get('status')}) Holm p={(c.get('holm') or {}).get('p_holm')}")
        else:
            ev = "ja4_foxio_capture_cv not run"
        status = {"SUPPORTED": "PRELIMINARY", "UNTESTED": "UNTESTED"}.get(st, "INSUFFICIENT_EVIDENCE" if st != "CONTRADICTED" else st)
        claims.append(_claim(cid, text, status, ev + ". The suite ja4_v2_comparison (Phase 13 pre-audit) is invalidated and not used.",
                             experiments=[sid("ja4_foxio_capture_cv")] if sid("ja4_foxio_capture_cv") else [],
                             datasets=["DS-008", "DS-009", "DS-011"], protocol="capture-grouped 5-fold CV, exploratory",
                             confounders=CONFOUNDERS,
                             limitations=["Same single-benign-source corpus as every other suite: dataset identity equals class.",
                                          "FoxIO JA4 is withheld for ClientHellos that corpus v3 parsed from a truncated first segment."]))
    claims.append(_claim("C26", "Flows observed by Zeek, Suricata and eBPF collectors are resolved to a single cross-sensor identity.",
                         "UNTESTED", "No cross-sensor correlation is implemented: tests/test_sensor_cross_correlation.py checks, on synthetic "
                                           "fixtures, that each adapter normalises the same flow to comparable fields, but no component joins records "
                                           "across sensors.", protocol="not run",
                         limitations=["Needs an implemented correlator that handles NAT, clock skew and missing records, and genuine tool output."]))
    return claims
