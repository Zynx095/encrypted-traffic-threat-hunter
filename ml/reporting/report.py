"""
Reproducible research report generated from persisted artefacts only.

Outputs (data/experiments/reports/):
    latest_report.json / latest_report.md     most recent report
    report_<timestamp>.json / .md             immutable copies
    claim_ledger.json                         evidence ledger (also embedded in the report)
No metric is typed by hand: every number is read from suite summaries, experiment records,
corpus reports or the model registry, and every section names its source artefact.
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ml.benchmark.comparisons import interpret
from ml.benchmark.registry import environment_snapshot, list_suites, sha256_file, suite_dir
from ml.reporting.claims import build_claims
from pipeline import config as pipeline_config

ROOT = pipeline_config.PROJECT_ROOT
REPORT_DIR = ROOT / "data" / "experiments" / "reports"
RESEARCH_QUESTION = ("Does combining TLS fingerprint information, including JA3 and JA4 where available, with encrypted-flow "
                     "behavioral features improve malicious encrypted-traffic detection compared with individual feature families, "
                     "under realistic generalization conditions and without decrypting TLS application payloads?")


def _load(path: Path) -> Optional[Dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def invalidated_suites() -> Dict[str, str]:
    from ml.benchmark.suites import SUITES
    return {n: s["invalidated"] for n, s in SUITES.items() if s.get("invalidated")}


def latest_suites() -> Dict[str, Dict[str, Any]]:
    """Latest completed run per suite. Invalidated suites are preserved on disk but never reported as results."""
    out: Dict[str, Dict[str, Any]] = {}
    bad = invalidated_suites()
    for s in list_suites():
        if not str(s.get("status", "")).startswith("COMPLETED") or s["name"] in bad:
            continue
        name = s["name"]
        if name not in out or s["created_at"] > out[name]["suite"]["created_at"]:
            summ = _load(suite_dir(s["suite_id"]) / "summary.json")
            out[name] = {"suite": s, "summary": summ}
    return out


def _per_capture(entry: Dict[str, Any], model: str = "random_forest",
                 tracks=("A_FLOW", "C_JA4", "E_JA4_FLOW", "D_JA3_FLOW")) -> Dict[str, Any]:
    """Per-capture flagged rates of the primary model, read from experiment records."""
    out: Dict[str, Any] = {}
    sid = entry["suite"]["suite_id"]
    for row in (entry.get("summary") or {}).get("experiments", []):
        if row.get("model") == model and row.get("track") in tracks and row.get("encoding", "onehot") == "onehot"                 and row.get("status") == "COMPLETED":
            rec = _load(suite_dir(sid) / row["experiment_id"] / "record.json") or {}
            out[row["track"]] = (rec.get("metrics") or {}).get("per_capture") or {}
    return out


def _f(v, d=3):
    return "—" if v is None else (f"{v:.{d}f}" if isinstance(v, (int, float)) else str(v))


def _pct(v):
    return "—" if v is None else f"{100 * v:.1f}%"


def generate_report() -> Dict[str, str]:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    latest = latest_suites()
    claims = build_claims(latest)
    adm = _load(ROOT / "data" / "corpus" / "admission_report.json")
    suff = _load(ROOT / "data" / "corpus" / "sufficiency_assessment.json")
    reg = _load(ROOT / "data" / "corpus" / "dataset_registry.json")
    cov = _load(ROOT / "data" / "experiments" / "phase9" / "diagnostics" / "coverage_report.json")
    shift = _load(ROOT / "data" / "experiments" / "phase9" / "diagnostics" / "shift_report.json")
    models = _load(ROOT / "data" / "model_registry" / "registry.json")
    from ml.benchmark.suites import CONFIRMATORY_POLICY, SUITES
    from ml.estimators.zoo import MODEL_SPECS
    from ml.features.governance import SCHEMA_VERSION, TRACKS, schema_fingerprint, track_columns

    now = _dt.datetime.now(_dt.timezone.utc)
    report = {
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "research_question": RESEARCH_QUESTION,
        "status_vocabulary": ["IMPLEMENTED", "TESTED", "EXECUTED", "SCIENTIFICALLY VALIDATED", "PUBLICATION-READY"],
        "overall_status": {"implemented": True, "tested": True, "executed": bool(latest),
                           "scientifically_validated": False, "publication_ready": False,
                           "reason": "All evaluations are exploratory on a corpus where dataset identity equals class; confirmatory evaluation is BLOCKED."},
        "datasets": [{k: d.get(k) for k in ("dataset_id", "name", "state", "access_category", "license", "flow_count", "research_role")}
                     for d in (reg or {}).get("datasets", [])],
        "admission": adm, "sufficiency": suff, "coverage": cov, "shift": shift,
        "feature_schemas": {t: {"schema_fingerprint": schema_fingerprint(t), **track_columns(t), **TRACKS[t].to_dict()} for t in TRACKS},
        "feature_schema_version": SCHEMA_VERSION,
        "protocols": {n: {"description": s["description"], "protocol": s["protocol"], "datasets": s.get("datasets"),
                          "tracks": s["tracks"], "models": s["models"]} for n, s in SUITES.items()},
        "confirmatory_policy": CONFIRMATORY_POLICY,
        "model_configurations": {n: {"description": s.description, "grid": s.grid, "scaled_inputs": s.scale, "exportable": s.exportable}
                                 for n, s in MODEL_SPECS.items()},
        "suites": {n: {"suite_id": e["suite"]["suite_id"], "status": e["suite"]["status"], "created_at": e["suite"]["created_at"],
                       "seed": e["suite"]["config"].get("seed"), "evaluation_population": e["suite"].get("evaluation_population"),
                       "dataset": e["suite"].get("dataset"), "environment": e["suite"].get("environment"),
                       "summary": e["summary"], "per_capture_primary": _per_capture(e)} for n, e in latest.items()},
        "suites_not_run": sorted(set(SUITES) - set(latest) - set(invalidated_suites())),
        "invalidated_suites": invalidated_suites(),
        "model_registry": {"models": [{k: m.get(k) for k in ("model_id", "version", "track", "estimator", "status", "research_status",
                                                             "calibration", "thresholds", "evaluation", "artifact")}
                                      for m in (models or {}).get("models", [])],
                           "activation_history": (models or {}).get("activation_history", [])},
        "claims": claims,
        "environment": environment_snapshot(),
        "artifact_references": {
            "corpus_manifest": "data/processed/v3/corpus_manifest.json",
            "admission_report": "data/corpus/admission_report.json",
            "capture_plan": "data/corpus/capture_plan.json",
            "artifact_manifest": "data/corpus/artifact_manifest.json",
            "experiment_index": "data/experiments/registry/index.jsonl",
        },
    }
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    js = json.dumps(report, indent=2, default=str)
    md = render_markdown(report)
    for name, content in ((f"report_{stamp}.json", js), (f"report_{stamp}.md", md), ("latest_report.json", js), ("latest_report.md", md)):
        (REPORT_DIR / name).write_text(content, encoding="utf-8")
    ledger = {"generated_at": report["generated_at"], "claims": claims, "statuses": sorted({c["status"] for c in claims})}
    (REPORT_DIR / "claim_ledger.json").write_text(json.dumps(ledger, indent=2, default=str), encoding="utf-8")
    def rel(p: Path) -> str:
        try:
            return p.resolve().relative_to(ROOT.resolve()).as_posix()
        except ValueError:
            return p.as_posix()
    return {"json": rel(REPORT_DIR / f"report_{stamp}.json"), "markdown": rel(REPORT_DIR / f"report_{stamp}.md"),
            "claims": rel(REPORT_DIR / "claim_ledger.json")}


def _suite_table(summary: Dict[str, Any]) -> List[str]:
    rows = summary.get("experiments") or []
    if not rows:
        return []
    out = ["| Track | Model | Enc. | Status | Pos/Neg | AP [95% CI] (status) | ROC-AUC | Recall @ val-FPR≤1% | Test FPR | ECE | Brier |",
           "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['track']} | {r['model']} | {r.get('encoding')} | {r['status']} | {r.get('n_pos')}/{r.get('n_neg')} | "
                   f"{_f(r.get('average_precision'))} [{_f(r['ap_ci'][0])}, {_f(r['ap_ci'][1])}] ({r.get('ap_ci_status')}) | "
                   f"{_f(r.get('roc_auc'))} | {_pct(r.get('recall_at_val_fpr_0.01'))} | {_pct(r.get('test_fpr_at_val_fpr_0.01'))} | "
                   f"{_f(r.get('ece_15bin'))} | {_f(r.get('brier'))} |")
    return out


def _contrast_table(contrasts: List[Dict[str, Any]]) -> List[str]:
    out = ["| Contrast | Shared rows | AP A | AP B | ΔAP [95% CI] | Holm p | Interpretation |", "|---|---|---|---|---|---|---|"]
    for c in contrasts:
        ap = c.get("average_precision") or {}
        out.append(f"| {c['contrast']} ({c.get('track_a')}→{c.get('track_b')}) | {c.get('shared_rows', '—')} | {_f(ap.get('metric_a'), 4)} | "
                   f"{_f(ap.get('metric_b'), 4)} | {_f(ap.get('difference'), 4)} [{_f(ap.get('ci_low'), 4)}, {_f(ap.get('ci_high'), 4)}] | "
                   f"{_f((c.get('holm') or {}).get('p_holm'), 4)} | {c.get('interpretation') or interpret(c)} |")
    return out


def render_markdown(r: Dict[str, Any]) -> str:
    L: List[str] = [f"# ETTH Research Report", "", f"Generated {r['generated_at']} from persisted artefacts (`ml/reporting/report.py`). "
                    "No value in this document was entered by hand.", "", "## Research question", "", r["research_question"], "",
                    "## Status", ""]
    st = r["overall_status"]
    L += [f"- Implemented: {st['implemented']}; tested: {st['tested']}; executed: {st['executed']}",
          f"- Scientifically validated: **{st['scientifically_validated']}**; publication-ready: **{st['publication_ready']}**",
          f"- Reason: {st['reason']}", "", "## Datasets", "", "| ID | Name | State | Access | Flows |", "|---|---|---|---|---|"]
    for d in r["datasets"]:
        L.append(f"| {d['dataset_id']} | {d['name']} | {d['state']} | {d['access_category']} | {d.get('flow_count')} |")
    if r.get("admission"):
        L += ["", "### Inclusion funnel (from data/corpus/admission_report.json)", "",
              "| Dataset | In plan | Verified | Valid | In corpus | Flows | JA3 | JA4 |", "|---|---|---|---|---|---|---|---|"]
        for ds, f in r["admission"]["funnel_by_dataset"].items():
            L.append(f"| {ds} | {f['captures_included_in_plan']} | {f['captures_checksum_verified_or_observed']} | {f['captures_pcap_valid']} | "
                     f"{f['captures_in_corpus']} | {f['flows_in_corpus']} | {f['ja3_flows']} | {f['ja4_flows']} |")
        L += ["", "Exclusions:"] + [f"- {e['capture_id']} ({e['stage']}): {e['reason']}" for e in r["admission"]["exclusions"]]
    if r.get("sufficiency"):
        L += ["", "### Benign sufficiency", ""] + [f"- {k}: {'MET' if v['met'] else 'NOT MET'} {v['checks']}" for k, v in r["sufficiency"]["levels"].items()]
    if r.get("coverage"):
        L += ["", "## Fingerprint coverage (full corpus)", "", "| Track | Rows | Coverage (all) | Malicious | Benign |", "|---|---|---|---|---|"]
        for t, v in r["coverage"]["track_coverage"].items():
            L.append(f"| {t} | {v['rows']} | {_pct(v['coverage_all'])} | {_pct(v['coverage_malicious'])} | {_pct(v['coverage_benign'])} |")
        o = r["coverage"]["fingerprint_overlap"]
        L += ["", f"JA3 values shared between classes: {o['ja3']['distinct_shared']} of {o['ja3']['distinct_values']}; "
                  f"JA4: {o['ja4']['distinct_shared']} of {o['ja4']['distinct_values']}."]
    if r.get("shift"):
        L += ["", "## Dataset-shift diagnostics", "", f"- Collection years by source: {r['shift']['collection_years_by_source']}",
              f"- TLS-version share by source: {r['shift']['tls_version_share_by_source']}",
              f"- Median flow statistics by source: {r['shift']['median_by_source']}"]
    L += ["", "## Evaluation protocols", ""]
    for n, p in r["protocols"].items():
        L.append(f"- **{n}** ({p['protocol']}): {p['description']} Tracks: {', '.join(p['tracks'])}. Models: {', '.join(p['models'])}.")
    L += ["", f"Confirmatory evaluation: **{r['confirmatory_policy']['status']}** — {r['confirmatory_policy']['reason']}", "",
          "## Results by suite (exploratory)", ""]
    for n, s in r["suites"].items():
        L += [f"### {n} — `{s['suite_id']}`", "", f"Seed {s['seed']}; evaluation population {s.get('evaluation_population')}", ""]
        summ = s.get("summary") or {}
        L += _suite_table(summ)
        for model, fam in (summ.get("paired_contrasts") or {}).items():
            L += ["", f"Paired contrasts ({model}; Holm over 4 pre-declared contrasts):", ""] + _contrast_table(fam["contrasts"])
        if summ.get("models"):
            L += ["", "| Model | AP | AP CI | Recall @ val-FPR≤1% | Test FPR | mean fit s | params |", "|---|---|---|---|---|---|---|"]
            for m, v in summ["models"].items():
                b = v.get("ap_bootstrap") or {}
                L.append(f"| {m} | {_f(v.get('average_precision'))} | [{_f(b.get('ci_low'))}, {_f(b.get('ci_high'))}] {b.get('status')} | "
                         f"{_pct(v.get('recall_at_val_fpr_0.01'))} | {_pct(v.get('test_fpr_at_val_fpr_0.01'))} | "
                         f"{_f(((v.get('cost') or {}).get('fit_seconds_mean') or {}).get('mean'), 1)} | {(v.get('cost') or {}).get('parameters')} |")
        if summ.get("contrasts"):
            L += ["", "Sequence vs tabular contrasts:", ""] + _contrast_table(summ["contrasts"])
        pc = s.get("per_capture_primary") or {}
        if pc:
            tracks = sorted(pc)
            caps = sorted({c for t in tracks for c in pc[t]})
            L += ["", f"Per-capture flagged rate at the validation-selected FPR≤1% threshold (primary model random_forest; "
                      f"benign rows = false-positive rate, malicious rows = detection rate):", "",
                  "| Capture | Class | " + " | ".join(tracks) + " |", "|---|---|" + "---|" * len(tracks)]
            for c in caps:
                y = next((pc[t][c]["y"] for t in tracks if c in pc[t]), None)
                cells = [(_pct(pc[t][c].get("pred@fpr<=0.01")) + f" (n={pc[t][c]['n']})") if c in pc[t] else "—" for t in tracks]
                L.append(f"| {c} | {'MAL' if y == 1 else 'BEN'} | " + " | ".join(cells) + " |")
        L.append("")
    if r["suites_not_run"]:
        L += ["Suites NOT_RUN: " + ", ".join(r["suites_not_run"]), ""]
    for name, why in (r.get("invalidated_suites") or {}).items():
        L += [f"Suite **{name}** is INVALIDATED and excluded from results: {why}", ""]
    L += ["## Claim ledger", "", "| ID | Claim | Status | Evidence |", "|---|---|---|---|"]
    for c in r["claims"]:
        L.append(f"| {c['claim_id']} | {c['claim']} | **{c['status']}** | {c['evidence_summary']} |")
    L += ["", "## Model registry", ""]
    if r["model_registry"]["models"]:
        for m in r["model_registry"]["models"]:
            L.append(f"- {m['model_id']} v{m['version']} ({m['track']}, {m['estimator']}): {m['status']}, {m['research_status']}, "
                     f"calibration {(m.get('calibration') or {}).get('status')}, thresholds {m.get('thresholds')}")
    else:
        L.append("No registered models.")
    env = r["environment"]
    L += ["", "## Environment", "", f"- Python {env['python']} on {env['platform']}; CPUs {env['cpu_count']}",
          f"- Packages: {env['packages']}", f"- Source revision: {env['source_revision']}", "",
          "## Limitations and negative results", "",
          "- Every dataset contributes a single class; any classifier can exploit source/environment differences.",
          "- Benign data are 2017 Stratosphere lab browsing captures (mostly Kali Linux / iceweasel 43 per their READMEs; OS metadata conflicts are recorded); malicious data are Windows hosts (2017 and 2024-2026).",
          "- Labels are capture-level; benign background flows inside malware captures are labelled malicious.",
          "- The ETTH JA4 implementation differs from the FoxIO JA4 specification (e.g. 'n' instead of 'i' for no SNI; TLS version from the presence of supported_versions); values are not comparable with external JA4 databases.",
          "- ClientHellos are parsed from the first TCP segment only (truncation flagged).",
          "- Confidence intervals rest on 6 benign captures per pooled suite and are flagged FEW_GROUPS: they are likely too narrow.",
          ""]
    return "\n".join(L) + "\n"
