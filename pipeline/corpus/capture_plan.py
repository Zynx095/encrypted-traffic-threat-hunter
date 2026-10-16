"""
Declarative capture plan for the ETTH research corpus.

Every capture (one PCAP = one independent capture session) is described once, with its
label derivation, provenance, container and expected checksum. The plan is generated from
the repository's own manifests and the acquisition log, so it never invents a checksum: a
checksum that was never published or recorded stays "UNKNOWN" and is replaced only by the
value observed at acquisition (trust-on-first-download, recorded as such).
"""
from __future__ import annotations

import csv
import datetime as _dt
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from pipeline.corpus import paths
from pipeline.corpus.registry import UNKNOWN

# Family groups merge captures that share any malware family, so a family-holdout split can
# never place the same family on both sides (e.g. XWorm appears in DS008-C002 and DS008-C004).
FAMILY_GROUPS = {
    "XLoader": "XLoader",
    "AsyncRAT / XWorm": "AsyncRAT_XWorm",
    "XWorm": "AsyncRAT_XWorm",
    "Lumma Stealer / SectopRAT / ArechClient2": "Lumma",
    "Lumma Stealer / Ghostsocks": "Lumma",
    "Lumma Stealer / SectopRAT": "Lumma",
    "SmartApeSG / NetSupport RAT / StealC v2": "NetSupport_StealC",
    "GuLoader / Remcos RAT": "Remcos",
    "Remcos RAT": "Remcos",
    "Remcos RAT / XLoader": "Remcos",
    "Pikabot / Meduza Stealer": "Pikabot",
    "DarkGate": "DarkGate",
}

MTA_LABEL_DERIVATION = (
    "Capture-level label MALICIOUS taken from the Malware-Traffic-Analysis.net post that "
    "publishes the capture as infection traffic, propagated to every reconstructed flow. "
    "Flows in such captures can include benign background traffic of the infected host, "
    "so flow-level label noise is expected and unquantified."
)
CTU_LABEL_DERIVATION = (
    "Capture-level label BENIGN taken from the Stratosphere Laboratory 'normal capture' "
    "description (no malware executed), propagated to every reconstructed flow."
)
DS004_LABEL_DERIVATION = (
    "Capture-level label BENIGN_VALIDATION from the CipherSpectrum dataset (customised "
    "Chromium visiting listed websites), as used in Phase 6."
)


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _acquisition_log() -> Dict[str, Dict[str, str]]:
    """Map repository-relative output path -> acquisition record."""
    out: Dict[str, Dict[str, str]] = {}
    if not paths.ACQUISITION_LOG.exists():
        return out
    for line in paths.ACQUISITION_LOG.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        ts, url, out_rel, code, size, seconds = parts[:6]
        out[paths.rel(paths.ACQUISITION_STAGING_DIR / out_rel)] = {
            "acquired_at": ts, "url": url, "http_status": code,
            "bytes_downloaded": size, "seconds": seconds,
        }
    return out


def _mta_rows() -> List[Dict[str, str]]:
    return _read_csv(paths.PROJECT_ROOT / "data" / "manifests" / "ds008_expanded_corpus_manifest.csv")


def _phase6_manifest() -> Dict[str, Dict[str, str]]:
    rows = _read_csv(paths.PROJECT_ROOT / "data" / "manifests" / "dataset_manifest_20260815_092018.csv")
    return {r["source_file"]: r for r in rows}


def _ctu_readme_facts(readme: Path, fname: str) -> Dict[str, str]:
    """
    Read the source README next to a CTU capture. Filename and README sometimes disagree
    (e.g. a '*_win-normal.pcap' whose README says 'Using a Kali linux'); disagreements are
    recorded as such instead of being resolved by guessing.
    """
    text = readme.read_text(encoding="utf-8", errors="replace") if readme.exists() else ""
    lower = text.lower()
    readme_os = "Kali Linux" if "kali" in lower else None
    file_os = "Windows" if "win" in fname.lower() else ("Kali Linux" if "kali" in fname.lower() else None)
    if readme_os and file_os and readme_os != file_os:
        os_value = f"{UNKNOWN} (CONFLICT: filename says {file_os}, README says {readme_os})"
    elif readme_os or file_os:
        os_value = f"{readme_os or file_os} ({'README' if readme_os else 'filename only'})"
    else:
        os_value = UNKNOWN
    browser = UNKNOWN
    for line in text.splitlines():
        if line.strip().lower().startswith("- browser:"):
            browser = line.split(":", 1)[1].strip()
    proxy = "no intermediate proxy (README)" if "did not use an intermediate proxy" in lower else UNKNOWN
    return {"os": os_value, "browser": browser, "proxy": proxy,
            "readme_path": paths.rel(readme) if readme.exists() else UNKNOWN}


def _mta_container(row: Dict[str, str]) -> Dict[str, Any]:
    cand = row["mta_candidate_id"]
    local = paths.PROJECT_ROOT / "data" / "verification" / "mta_stage65" / f"{cand}.zip"
    staged = paths.ACQUISITION_STAGING_DIR / "mta" / f"{cand}.pcap.zip"
    archive = local if local.exists() else staged
    return {
        "type": "zip",
        "path": paths.rel(archive),
        "member": row["pcap_filename"],
        "password_scheme": "MTA_INFECTED_POST_DATE",
        "post_date": row["mta_date"],
        "origin": "repository_archive" if archive == local else "acquisition_staging",
    }


def build_default_plan() -> Dict[str, Any]:
    acq = _acquisition_log()
    p6 = _phase6_manifest()
    captures: List[Dict[str, Any]] = []

    # ---- DS-008: Malware-Traffic-Analysis.net (malicious) -------------------------------
    for row in _mta_rows():
        status = row["admission_status"]
        include = status in ("ADMITTED", "CURRENT VERIFIED BASELINE")
        cand = row["mta_candidate_id"]
        capture_id = row["corpus_sample_id"] or f"DS008-{cand}"
        expected = row["pcap_sha256"] or (p6.get(row["pcap_filename"], {}).get("sha256") or UNKNOWN)
        size = row["pcap_size_bytes"] or (p6.get(row["pcap_filename"], {}).get("file_size_bytes") or UNKNOWN)
        container = _mta_container(row)
        acq_rec = acq.get(container["path"])
        captures.append({
            "capture_id": capture_id,
            "dataset_id": "DS-008",
            "source_candidate_id": cand,
            "label": "MALICIOUS",
            "label_derivation": MTA_LABEL_DERIVATION,
            "label_granularity": "CAPTURE_PROPAGATED_TO_FLOWS",
            "flow_label_confidence": "MEDIUM",
            "malware_family": row["malware_family"],
            "family_group": FAMILY_GROUPS.get(row["malware_family"], UNKNOWN),
            "collection_date": row["mta_date"],
            "environment": "MALWARE_LAB_WINDOWS_HOST (source narrative; not independently verified)",
            "os": "Windows (source narrative)",
            "source_url": row["source_url"],
            "container": container,
            "acquisition": acq_rec or {"acquired_at": UNKNOWN, "url": row["source_url"],
                                       "note": "Archive present in repository before Phase 8; original acquisition time not recorded."},
            "expected_sha256": expected.lower() if expected != UNKNOWN else UNKNOWN,
            "expected_sha256_source": "data/manifests/ds008_expanded_corpus_manifest.csv" if row["pcap_sha256"]
                                      else "data/manifests/dataset_manifest_20260815_092018.csv",
            "expected_size_bytes": int(size) if str(size).isdigit() else UNKNOWN,
            "raw_path": paths.rel(paths.EXTRACTED_DIR / "DS-008" / capture_id / row["pcap_filename"]),
            "planned_use": "INCLUDE" if include else "EXCLUDED",
            "exclusion_reason": None if include else f"Stage 6.5 decision: {row['admission_reason']}",
            "prior_admission_status": status,
        })

    # ---- DS-004: CipherSpectrum samples (benign validation; currently not present) -------
    for name, rec in sorted(p6.items()):
        if rec["dataset_id"] != "DS-004":
            continue
        path = paths.PROJECT_ROOT / "data" / "samples" / "ds004" / name
        captures.append({
            "capture_id": f"DS004-{Path(name).stem}",
            "dataset_id": "DS-004",
            "source_candidate_id": UNKNOWN,
            "label": "BENIGN_VALIDATION",
            "label_derivation": DS004_LABEL_DERIVATION,
            "label_granularity": "CAPTURE_PROPAGATED_TO_FLOWS",
            "flow_label_confidence": "HIGH",
            "malware_family": "BENIGN",
            "family_group": "BENIGN",
            "collection_date": UNKNOWN,
            "environment": "CIPHERSPECTRUM_CUSTOM_CHROMIUM",
            "os": UNKNOWN,
            "source_url": "https://cspectrum.web.cse.unsw.edu.au/ (mix.zip member name not recorded in Phase 5)",
            "container": {"type": "file", "path": paths.rel(path), "origin": "phase6_sample"},
            "acquisition": {"acquired_at": UNKNOWN, "note": "Acquired on the original E: workstation; not present in this working copy."},
            "expected_sha256": rec["sha256"].lower(),
            "expected_sha256_source": "data/manifests/dataset_manifest_20260815_092018.csv",
            "expected_size_bytes": int(rec["file_size_bytes"]),
            "raw_path": paths.rel(path),
            "planned_use": "INCLUDE",
            "exclusion_reason": None,
            "prior_admission_status": "BENIGN_VALIDATION",
        })

    # ---- DS-011: Stratosphere CTU-Normal HTTPS captures (benign) --------------------------
    for out_rel, rec in sorted(acq.items()):
        if "/ctu_normal/" not in out_rel or not out_rel.endswith(".pcap"):
            continue
        cap_dir = Path(out_rel).parent.name            # e.g. CTU-Normal-20
        fname = Path(out_rel).name
        date = fname[:10].replace("_", "-")
        facts = _ctu_readme_facts(paths.resolve(out_rel).parent / "README.md", fname)
        captures.append({
            "capture_id": f"DS011-{cap_dir}",
            "dataset_id": "DS-011",
            "source_candidate_id": cap_dir,
            "label": "BENIGN",
            "label_derivation": CTU_LABEL_DERIVATION,
            "label_granularity": "CAPTURE_PROPAGATED_TO_FLOWS",
            "flow_label_confidence": "HIGH",
            "malware_family": "BENIGN",
            "family_group": "BENIGN",
            "collection_date": date,
            "environment": f"STRATOSPHERE_LAB_CAPTURE; browser={facts['browser']}; {facts['proxy']}",
            "os": facts["os"],
            "source_readme": facts["readme_path"],
            "source_url": rec["url"],
            "container": {"type": "file", "path": out_rel, "origin": "acquisition_staging"},
            "acquisition": rec,
            "expected_sha256": UNKNOWN,
            "expected_sha256_source": "No checksum is published by the source; SHA-256 observed at acquisition is recorded in the artifact manifest.",
            "expected_size_bytes": int(rec["bytes_downloaded"]) if rec["bytes_downloaded"].isdigit() else UNKNOWN,
            "raw_path": out_rel,
            "planned_use": "INCLUDE" if rec.get("http_status") == "200" else "EXCLUDED",
            "exclusion_reason": None if rec.get("http_status") == "200" else f"Download failed (HTTP {rec.get('http_status')})",
            "prior_admission_status": "NEW_IN_PHASE_8",
        })

    # ---- DS-009: Stratosphere MCFP malware captures (malicious, same lab as DS-011) -------
    for out_rel, rec in sorted(acq.items()):
        if "/stratosphere_malware/" not in out_rel or not out_rel.endswith(".pcap"):
            continue
        cap_dir = Path(out_rel).parent.name            # e.g. CTU-Malware-Capture-Botnet-246-1
        fname = Path(out_rel).name
        facts = _mcfp_readme_facts(paths.resolve(out_rel).parent / "README.md")
        family = facts["family"]
        captures.append({
            "capture_id": f"DS009-{cap_dir.replace('CTU-Malware-Capture-Botnet-', 'CTU-MCB-')}",
            "dataset_id": "DS-009",
            "source_candidate_id": cap_dir,
            "label": "MALICIOUS",
            "label_derivation": MCFP_LABEL_DERIVATION,
            "label_granularity": "CAPTURE_PROPAGATED_TO_FLOWS",
            "flow_label_confidence": "MEDIUM",
            "malware_family": family,
            "family_group": _mcfp_family_group(family),
            "collection_date": facts["start_date"] if facts["start_date"] != UNKNOWN else fname.split("_")[0],
            "environment": f"STRATOSPHERE_LAB_CAPTURE; infected host {facts['host']}; {facts['proxy']}",
            "os": "Windows (filename 'winN')" if "_win" in fname else UNKNOWN,
            "source_readme": facts["readme_path"],
            "malware_sample_sha256": facts["sample_sha256"],
            "source_url": rec["url"],
            "container": {"type": "file", "path": out_rel, "origin": "acquisition_staging"},
            "acquisition": rec,
            "expected_sha256": UNKNOWN,
            "expected_sha256_source": "No PCAP checksum is published by the source (README lists only the malware sample hash); SHA-256 observed at acquisition is recorded.",
            "expected_size_bytes": int(rec["bytes_downloaded"]) if rec["bytes_downloaded"].isdigit() else UNKNOWN,
            "raw_path": out_rel,
            "planned_use": "INCLUDE" if rec.get("http_status") == "200" else "EXCLUDED",
            "exclusion_reason": None if rec.get("http_status") == "200" else f"Download failed (HTTP {rec.get('http_status')})",
            "prior_admission_status": "NEW_IN_PHASE_8",
        })

    return {
        "schema_version": "1.0",
        "description": "ETTH research corpus capture plan (one entry per capture session).",
        "captures": captures,
    }


MCFP_LABEL_DERIVATION = (
    "Capture-level label MALICIOUS: Stratosphere Malware Capture Facility Project recording of "
    "a Windows VM executing the sample named in the README ('Probable Name'). Every flow of the "
    "VM is labelled MALICIOUS, including the minutes before infection and benign background "
    "Windows traffic, so flow-level label noise is expected and unquantified."
)


MCFP_KNOWN_FAMILIES = ("Emotet", "Dridex", "TrickBot")


def _mcfp_family_group(family: str) -> str:
    """Map a README family string (e.g. 'Trojan Bank Emotet (probable, per README)') to a family group."""
    for known in MCFP_KNOWN_FAMILIES:
        if known.lower() in family.lower():
            return known.capitalize()
    return UNKNOWN if family == UNKNOWN else re.split(r"[ .]", family)[0].lower().capitalize()


def _parse_readme_date(text: str) -> str:
    """'Wed Mar 15 19:16:25 CET 2017' -> '2017-03-15' (time-zone token dropped; date only)."""
    tokens = text.split()
    if len(tokens) == 6:
        tokens = tokens[:4] + tokens[5:]
    try:
        return _dt.datetime.strptime(" ".join(tokens), "%a %b %d %H:%M:%S %Y").date().isoformat()
    except ValueError:
        return UNKNOWN


def _mcfp_readme_facts(readme: Path) -> Dict[str, str]:
    text = readme.read_text(encoding="utf-8", errors="replace") if readme.exists() else ""
    facts = {"family": UNKNOWN, "sample_sha256": UNKNOWN, "host": UNKNOWN, "proxy": "proxy usage not stated",
             "start_date": UNKNOWN, "readme_path": paths.rel(readme) if readme.exists() else UNKNOWN}
    lines = text.splitlines()
    for i, line in enumerate(lines):
        s = line.strip()
        low = s.lower()
        if low.startswith("- probable name:"):
            facts["family"] = s.split(":", 1)[1].strip() + " (probable, per README)"
        elif low.startswith("- sha256:"):
            facts["sample_sha256"] = s.split(":", 1)[1].strip()
        elif low.startswith("- infected host:"):
            facts["host"] = s.split(":", 1)[1].strip()
        elif "proxy usage" in low:
            facts["proxy"] = s.split(":", 1)[1].strip() if ":" in s else s
        elif low.startswith("## ") and facts["start_date"] == UNKNOWN and any(m in s for m in
                ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")):
            facts["start_date"] = _parse_readme_date(s[3:].strip())
    if "mitm.out" in text.lower() and facts["proxy"] == "proxy usage not stated":
        facts["proxy"] = "README lists a MITM proxy interception log; interception point not stated (JA3S may reflect a proxy)"
    return facts


def load_plan(path: Path = paths.CAPTURE_PLAN_PATH) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save_plan(plan: Dict[str, Any], path: Path = paths.CAPTURE_PLAN_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def included(plan: Dict[str, Any], dataset_id: Optional[str] = None) -> List[Dict[str, Any]]:
    return [c for c in plan["captures"]
            if c["planned_use"] == "INCLUDE" and (dataset_id is None or c["dataset_id"] == dataset_id)]
