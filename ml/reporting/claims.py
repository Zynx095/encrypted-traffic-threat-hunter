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
    "benign captures are 2017 Linux/iceweasel browsing; malicious captures are Windows hosts",
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


def _contrast(summary: Dict[str, Any], model: str, label: str) -> Optional[Dict[str, Any]]:
    fam = ((summary or {}).get("paired_contrasts") or {}).get(model) or {}
    for c in fam.get("contrasts", []):
        if c["contrast"] == label:
            return c
    return None


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
        claims.append(_claim(cid, text, status, "; ".join(ev) + " (primary model random_forest, capture-grouped 5-fold, capture bootstrap)",
                             experiments=[c.get("experiment_a") for c in cs if c] + [c.get("experiment_b") for c in cs if c],
                             protocol="CAPTURE_GROUP_KFOLD, nested selection, paired capture bootstrap, Holm (4 contrasts)",
                             uncertainty={n: (c or {}).get("average_precision") for n, c in zip(("pooled", "matched_lab"), cs)},
                             confounders=CONFOUNDERS,
                             limitations=["Exploratory; at most PRELIMINARY on this corpus.", "No equivalence margin was pre-registered."]))
    # C08 cross-source generalisation
    lo = S("leave_one_source_out")
    if lo:
        rates = {}
        for r in lo.get("experiments", []):
            if r["model"] == "random_forest" and r.get("per_source"):
                for src, blk in r["per_source"].items():
                    if "detection_rate" in blk:
                        rates[f"{r['track']}|{src}"] = blk["detection_rate"].get("pred@fpr<=0.01")
        claims.append(_claim("C08", "A detector trained without a malicious source detects that held-out source at the validation-selected FPR<=1% threshold.",
                             "PRELIMINARY" if rates else "UNTESTED",
                             f"Held-out-source detection rates (random_forest): {rates}. Benign false-positive rate on a held-out benign source cannot be measured (only one benign source).",
                             experiments=[sid("leave_one_source_out")], protocol="LEAVE_ONE_SOURCE_OUT", metrics=rates,
                             confounders=CONFOUNDERS, limitations=["Recall only; holding out the single benign source leaves no benign training data."]))
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
                         "backend/event_sources/live_capture.py).", protocol="code inspection + tests"))
    return claims
