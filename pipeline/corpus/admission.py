"""
Dataset admission report and benign-corpus sufficiency assessment.

Admission means "fit to enter the ETTH corpus for EXPLORATORY research use with the listed
limitations". It does not mean the data is representative, and it never by itself licenses a
generalisation claim. Sufficiency is assessed separately against four explicitly different
evidence levels (A: pipeline executes, B: preliminary evaluation, C: generalisation study,
D: publication claim).
"""
from __future__ import annotations

import datetime as _dt
import json
from typing import Any, Dict, List

import numpy as np
import pandas as pd

from pipeline.corpus import paths
from pipeline.corpus.artifacts import ArtifactManifest
from pipeline.corpus.builder import USABLE_RAW_STATUS, load_corpus
from pipeline.corpus.capture_plan import load_plan
from pipeline.corpus.registry import UNKNOWN, DatasetRegistry, transition
from pipeline.corpus.validation import (duplicate_diagnostics, fingerprint_overlap, label_conflicts,
                                         missingness_table, tls_coverage)

KEY_FEATURES = ["flow_duration", "packet_length_mean", "iat_mean", "iat_std", "fwd_iat_mean", "rev_iat_mean",
                "ja3_hash", "ja4", "ja3s_hash", "tls_version", "alpn_value"]
PROVENANCE_FIELDS = ["collection_date", "environment", "os", "malware_family", "source_url", "expected_sha256"]

# Sufficiency thresholds. They are design choices, stated in advance and documented in
# PHASE_8_BENIGN_CORPUS.md; changing them requires a documented justification.
THRESHOLDS = {
    "A_pipeline": {"min_captures_per_class": 1, "min_flows_per_class": 1},
    "B_preliminary": {"min_captures_per_class": 5, "min_flows_per_class": 200, "min_fingerprinted_flows_per_class": 30,
                      "min_behavioral_groups_per_class": 100},
    "C_generalization": {"min_sources_per_class": 2, "min_captures_per_class": 10,
                         "require_temporal_overlap_between_classes": True,
                         "require_tls13_in_both_classes": True, "min_environments_per_class": 2},
    "D_publication": {"min_sources_per_class": 3, "min_captures_per_class": 20,
                      "require_independent_confirmatory_source": True, "require_flow_level_labels": True},
}


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _binary(label: Any) -> str:
    return "MALICIOUS" if "MALICIOUS" in str(label).upper() else "BENIGN"


def _provenance_completeness(caps: List[Dict[str, Any]]) -> Dict[str, Any]:
    per = {}
    for c in caps:
        known = [f for f in PROVENANCE_FIELDS if c.get(f) not in (None, "", UNKNOWN) and not str(c.get(f)).startswith(UNKNOWN)]
        per[c["capture_id"]] = round(len(known) / len(PROVENANCE_FIELDS), 4)
    return {"fields": PROVENANCE_FIELDS, "per_capture": per,
            "mean": round(float(np.mean(list(per.values()))), 4) if per else None}


def build_admission_report() -> Dict[str, Any]:
    plan = load_plan()
    manifest = ArtifactManifest()
    validation = json.loads(paths.VALIDATION_REPORT_PATH.read_text(encoding="utf-8")) if paths.VALIDATION_REPORT_PATH.exists() else {"checks": []}
    flows, prov = load_corpus()
    df = flows.merge(prov.drop(columns=["label"]), on="corpus_index", how="left")
    df["binary_label"] = df["label"].map(_binary)

    datasets = sorted({c["dataset_id"] for c in plan["captures"]})
    funnel: Dict[str, Any] = {}
    exclusions: List[Dict[str, Any]] = []
    pcap_checks = {c["capture_id"]: c for c in validation.get("checks", []) if c.get("stage") == "pcap"}
    raw = {e["capture_id"]: e for e in manifest.by_tier("RAW")}

    for ds in datasets:
        caps = [c for c in plan["captures"] if c["dataset_id"] == ds]
        inc = [c for c in caps if c["planned_use"] == "INCLUDE"]
        present = [c for c in inc if raw.get(c["capture_id"], {}).get("verification", {}).get("status") not in (None, "MISSING")]
        verified = [c for c in inc if raw.get(c["capture_id"], {}).get("verification", {}).get("status") in USABLE_RAW_STATUS]
        valid = [c for c in verified if pcap_checks.get(c["capture_id"], {}).get("status") == "VALID"]
        part = df[df["dataset_id"] == ds]
        funnel[ds] = {
            "captures_listed": len(caps),
            "captures_included_in_plan": len(inc),
            "captures_present": len(present),
            "captures_checksum_verified_or_observed": len(verified),
            "captures_pcap_valid": len(valid),
            "captures_in_corpus": int(part["capture_id"].nunique()),
            "flows_in_corpus": int(len(part)),
            "tls_clienthello_flows": int(part["clienthello_present"].fillna(False).astype(bool).sum()) if len(part) else 0,
            "ja3_flows": int(part["ja3_hash"].notna().sum()) if len(part) else 0,
            "ja4_flows": int(part["ja4"].notna().sum()) if len(part) else 0,
        }
        for c in caps:
            if c["planned_use"] != "INCLUDE":
                exclusions.append({"capture_id": c["capture_id"], "dataset_id": ds, "stage": "plan", "reason": c["exclusion_reason"]})
            elif c not in verified:
                exclusions.append({"capture_id": c["capture_id"], "dataset_id": ds, "stage": "materialize",
                                   "reason": raw.get(c["capture_id"], {}).get("verification", {}).get("detail") or "raw capture missing"})
            elif c not in valid:
                exclusions.append({"capture_id": c["capture_id"], "dataset_id": ds, "stage": "pcap_validation",
                                   "reason": "; ".join(pcap_checks.get(c["capture_id"], {}).get("issues", []))})

    integrity_issues = {cid: chk["issues"] for cid, chk in pcap_checks.items() if chk.get("issues")}
    report = {
        "generated_at": _now(),
        "corpus_rows": int(len(df)),
        "funnel_by_dataset": funnel,
        "exclusions": exclusions,
        "pcap_integrity_notes": integrity_issues,
        "label_distribution": {
            "by_label": {k: int(v) for k, v in df["label"].value_counts().items()},
            "by_dataset_label": {f"{d}|{l}": int(v) for (d, l), v in df.groupby(["dataset_id", "label"]).size().items()},
            "captures_by_binary_label": {k: int(v) for k, v in df.groupby("binary_label")["capture_id"].nunique().items()},
        },
        "flows_per_capture": {k: int(v) for k, v in df.groupby("capture_id").size().items()},
        "missingness_by_dataset": missingness_table(df, KEY_FEATURES, by="dataset_id"),
        "duplicates": duplicate_diagnostics(df),
        "duplicates_by_dataset": {d: duplicate_diagnostics(p) for d, p in df.groupby("dataset_id")},
        "label_conflicting_behavioral_groups": len(label_conflicts(df)),
        "tls_coverage_overall": tls_coverage(df),
        "tls_coverage_by_dataset": tls_coverage(df, by="dataset_id"),
        "tls_coverage_by_binary_label": tls_coverage(df, by="binary_label"),
        "fingerprint_overlap_between_classes": {"ja3": fingerprint_overlap(df, "ja3_hash"), "ja4": fingerprint_overlap(df, "ja4")},
        "provenance_completeness": _provenance_completeness([c for c in plan["captures"] if c["planned_use"] == "INCLUDE"]),
        "known_limitations": [
            "Labels are capture-level and propagated to every flow; benign background traffic inside malware captures is labelled MALICIOUS.",
            "Each dataset contributes exactly one class (DS-008, DS-009 malicious; DS-011, DS-004 benign), so dataset identity and label are perfectly aligned at the source level.",
            "DS-011 benign traffic is 2017 browser traffic (iceweasel 43 / Firefox-era stacks) to popular sites; it is not representative of enterprise or modern client traffic.",
            "DS-008 captures are from 2024-2026 while DS-009/DS-011 are from 2017: TLS versions and client stacks differ systematically by year.",
            "ClientHello parsing uses the first TCP segment only; fingerprints from truncated records are flagged (clienthello_record_truncated).",
            "DS-004 (CipherSpectrum) is absent from this working copy and is therefore not part of the corpus.",
        ],
    }
    paths.ADMISSION_REPORT_JSON.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    paths.ADMISSION_REPORT_MD.write_text(render_admission_markdown(report), encoding="utf-8")
    return report


def render_admission_markdown(r: Dict[str, Any]) -> str:
    lines = ["# ETTH Corpus Admission Report", "", f"Generated: {r['generated_at']} (from `data/corpus/admission_report.json`; all counts computed from data).", "",
             "## Processing funnel by dataset", "",
             "| Dataset | Listed | In plan | Present | Verified | PCAP valid | In corpus | Flows | ClientHello | JA3 | JA4 |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for ds, f in r["funnel_by_dataset"].items():
        lines.append(f"| {ds} | {f['captures_listed']} | {f['captures_included_in_plan']} | {f['captures_present']} | "
                     f"{f['captures_checksum_verified_or_observed']} | {f['captures_pcap_valid']} | {f['captures_in_corpus']} | "
                     f"{f['flows_in_corpus']} | {f['tls_clienthello_flows']} | {f['ja3_flows']} | {f['ja4_flows']} |")
    lines += ["", "## Exclusions", "", "| Capture | Dataset | Stage | Reason |", "|---|---|---|---|"]
    for e in r["exclusions"]:
        lines.append(f"| {e['capture_id']} | {e['dataset_id']} | {e['stage']} | {str(e['reason']).replace('|', '/')} |")
    d = r["duplicates"]
    lines += ["", "## Duplicates (behavioral_hash groups)", "",
              f"- Flows: {d['flows']}; behavioural groups: {d['behavioral_groups']}; duplicate groups: {d['duplicate_groups']}",
              f"- Flows in duplicate groups: {d['flows_in_duplicate_groups']} (rate {d['behavioral_duplicate_rate']})",
              f"- Cross-capture groups: {d['cross_capture_groups']}; cross-dataset: {d['cross_dataset_groups']}; cross-label: {d['cross_label_groups']}",
              "", "## Label distribution", ""]
    for k, v in r["label_distribution"]["by_dataset_label"].items():
        lines.append(f"- {k}: {v} flows")
    lines += ["", "## TLS / fingerprint coverage by binary label", ""]
    for lab, c in r["tls_coverage_by_binary_label"].items():
        lines.append(f"- {lab}: {c['flows']} flows, ClientHello {c['clienthello_flows']}, JA3 {c['ja3_available']} ({c['ja3_coverage']}), "
                     f"JA4 {c['ja4_available']} ({c['ja4_coverage']}), TLS versions {c['tls_version_counts']}, "
                     f"truncated-ClientHello fingerprints {c.get('fingerprints_from_truncated_clienthello')}")
    o = r["fingerprint_overlap_between_classes"]
    lines += ["", "## Fingerprint overlap between classes", "",
              f"- JA3: {o['ja3']}", f"- JA4: {o['ja4']}", "",
              f"## Provenance completeness", "", f"Mean fraction of required capture-level fields known: {r['provenance_completeness']['mean']}", "",
              "## Known limitations", ""]
    lines += [f"- {x}" for x in r["known_limitations"]]
    return "\n".join(lines) + "\n"


def assess_sufficiency() -> Dict[str, Any]:
    flows, prov = load_corpus()
    df = flows.merge(prov.drop(columns=["label"]), on="corpus_index", how="left")
    df["binary_label"] = df["label"].map(_binary)
    out: Dict[str, Any] = {"generated_at": _now(), "thresholds": THRESHOLDS, "levels": {}}
    per_class = {}
    for lab, part in df.groupby("binary_label"):
        years = pd.to_datetime(part["collection_date"], errors="coerce").dt.year.dropna().astype(int)
        per_class[lab] = {
            "sources": sorted(part["dataset_id"].unique().tolist()),
            "captures": int(part["capture_id"].nunique()),
            "flows": int(len(part)),
            "fingerprinted_flows": int(part["ja4"].notna().sum()),
            "behavioral_groups": int(part["behavioral_hash"].nunique()),
            # environment class = annotation before the first ';' (per-capture host details are not new environments)
            "environments": int(part["environment"].astype(str).str.split(";").str[0].str.strip().nunique()),
            "environment_classes": sorted(part["environment"].astype(str).str.split(";").str[0].str.strip().unique().tolist()),
            "collection_years": sorted(set(years.tolist())),
            "tls13_flows": int((part["tls_version"] == 1.3).sum()),
        }
    out["per_class"] = per_class
    b, m = per_class.get("BENIGN"), per_class.get("MALICIOUS")

    def level(name: str, checks: Dict[str, bool]) -> None:
        out["levels"][name] = {"met": all(checks.values()), "checks": checks}

    if not b or not m:
        for name in THRESHOLDS:
            level(name, {"both_classes_present": False})
        return out
    t = THRESHOLDS
    level("A_pipeline", {"captures_per_class": min(b["captures"], m["captures"]) >= t["A_pipeline"]["min_captures_per_class"],
                         "flows_per_class": min(b["flows"], m["flows"]) >= t["A_pipeline"]["min_flows_per_class"]})
    level("B_preliminary", {
        "captures_per_class": min(b["captures"], m["captures"]) >= t["B_preliminary"]["min_captures_per_class"],
        "flows_per_class": min(b["flows"], m["flows"]) >= t["B_preliminary"]["min_flows_per_class"],
        "fingerprinted_flows_per_class": min(b["fingerprinted_flows"], m["fingerprinted_flows"]) >= t["B_preliminary"]["min_fingerprinted_flows_per_class"],
        "behavioral_groups_per_class": min(b["behavioral_groups"], m["behavioral_groups"]) >= t["B_preliminary"]["min_behavioral_groups_per_class"],
    })
    m_years_by_source = {}
    for src, part in df[df["binary_label"] == "MALICIOUS"].groupby("dataset_id"):
        m_years_by_source[src] = sorted(set(pd.to_datetime(part["collection_date"], errors="coerce").dt.year.dropna().astype(int)))
    overlap = bool(set(b["collection_years"]) & set(m["collection_years"]))
    level("C_generalization", {
        "sources_per_class": min(len(b["sources"]), len(m["sources"])) >= t["C_generalization"]["min_sources_per_class"],
        "captures_per_class": min(b["captures"], m["captures"]) >= t["C_generalization"]["min_captures_per_class"],
        "temporal_overlap_between_classes": overlap,
        "tls13_in_both_classes": b["tls13_flows"] > 0 and m["tls13_flows"] > 0,
        "environments_per_class": min(b["environments"], m["environments"]) >= t["C_generalization"]["min_environments_per_class"],
    })
    level("D_publication", {
        "sources_per_class": min(len(b["sources"]), len(m["sources"])) >= t["D_publication"]["min_sources_per_class"],
        "captures_per_class": min(b["captures"], m["captures"]) >= t["D_publication"]["min_captures_per_class"],
        "independent_confirmatory_source": False,
        "flow_level_labels": False,
    })
    out["malicious_years_by_source"] = m_years_by_source
    out["interpretation"] = (
        "Levels are cumulative requirements for increasingly strong claims. Meeting A or B permits executing and "
        "reporting preliminary, explicitly confounded results; it does not support generalisation claims (C) or "
        "publication claims (D)."
    )
    paths.SUFFICIENCY_REPORT_JSON.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    return out


def update_registry_states(report: Dict[str, Any]) -> DatasetRegistry:
    """Advance dataset lifecycle states from recorded evidence only."""
    reg = DatasetRegistry(paths.REGISTRY_PATH)
    refs = [paths.rel(paths.ADMISSION_REPORT_JSON), paths.rel(paths.ARTIFACT_MANIFEST_PATH), paths.rel(paths.CORPUS_MANIFEST_PATH)]
    for ds, f in report["funnel_by_dataset"].items():
        rec = reg.get(ds)
        if rec is None:
            continue
        if f["captures_checksum_verified_or_observed"] == 0:
            continue
        if rec["state"] == "DISCOVERED" and rec.get("license") not in (None, UNKNOWN):
            rec = transition(rec, "LICENSE_VERIFIED", "Terms of use reviewed and recorded in the license field.", refs)
        if rec["state"] == "LICENSE_VERIFIED":
            rec = transition(rec, "ACQUIRED", f"{f['captures_present']} capture file(s) present locally; acquisition log / archive provenance recorded.", refs)
        if rec["state"] == "ACQUIRED":
            rec = transition(rec, "CONTENT_VERIFIED",
                             f"{f['captures_checksum_verified_or_observed']} capture(s) checksum-verified or hashed at acquisition; "
                             f"{f['captures_pcap_valid']} parse as valid PCAP.", refs,
                             context={"verified_artifacts": f["captures_pcap_valid"]})
        if rec["state"] == "CONTENT_VERIFIED" and f["flows_in_corpus"] > 0:
            rec = transition(rec, "PROCESSED", f"{f['flows_in_corpus']} flows from {f['captures_in_corpus']} capture(s) in corpus v3.",
                             refs, context={"processing_record": paths.rel(paths.CORPUS_MANIFEST_PATH)})
        if rec["state"] == "PROCESSED":
            rec = transition(rec, "ADMITTED",
                             "Admitted for EXPLORATORY research use only, subject to the known limitations in the admission report.",
                             refs, context={"admission_decision": "ADMIT_EXPLORATORY"})
        rec["flow_count"] = f["flows_in_corpus"]
        rec["processing_status"] = f"{f['captures_in_corpus']} capture(s) processed into corpus v3"
        rec["checksums"] = {e["capture_id"]: e["sha256"] for e in ArtifactManifest().by_tier("RAW")
                            if e["dataset_id"] == ds and e.get("sha256")}
        rec["duplicate_statistics"] = report["duplicates_by_dataset"].get(ds, UNKNOWN)
        rec["missingness_statistics"] = report["missingness_by_dataset"].get(ds, UNKNOWN)
        rec["fingerprint_availability"] = report["tls_coverage_by_dataset"].get(ds, UNKNOWN)
        rec["behavioral_group_count"] = (report["duplicates_by_dataset"].get(ds) or {}).get("behavioral_groups", UNKNOWN)
        reg.upsert(rec)
    reg.save()
    return reg
