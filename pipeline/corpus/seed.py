"""
Initial registry records, populated only with facts that are documented in the repository
or were verified on the provider's site during Phase 8 (2026-10-16). Anything not documented
stays UNKNOWN.
"""
from __future__ import annotations

import csv
from typing import Dict, List

from pipeline.corpus import paths
from pipeline.corpus.registry import UNKNOWN, DatasetRegistry, new_record, transition

VERIFIED_ON = "2026-10-16"


def _documented_records() -> List[Dict]:
    recs = []

    r = new_record(
        "DS-008", "Malware-Traffic-Analysis.net (selected infection-traffic captures)",
        version="Stage 6.5 selection (10 admitted captures)",
        publisher="Brad Duncan (malware-traffic-analysis.net)",
        canonical_source="https://www.malware-traffic-analysis.net/",
        access_method="Public download of password-protected ZIP archives (password scheme infected_YYYYMMDD).",
        access_category="VERIFIED_AVAILABLE",
        license=("No formal license. About page (reviewed " + VERIFIED_ON + "): files are shared 'as a resource for "
                 "threat researchers and other security professionals'; 'use this website at your own risk'."),
        usage_restrictions="Formal license UNKNOWN; used here for non-commercial security research only.",
        collection_period="2024-01-30 to 2026-04-16 (admitted captures)",
        raw_capture_available="YES", pcap_available="YES",
        labeling_methodology="Capture-level: each capture is published as infection traffic of a named family.",
        label_confidence="Capture level HIGH; flow level MEDIUM (background host traffic is not separated).",
        composition="MALICIOUS only",
        network_environment="Infected Windows lab hosts as described in each post (not independently verified).",
        os_environment="Windows (source narrative)",
        protocol_coverage="TCP/UDP incl. DNS, HTTP, TLS",
        research_role="Primary malicious source (Stage 6.5).",
    )
    recs.append(r)

    r = new_record(
        "DS-004", "CipherSpectrum",
        version="Phase 5/6 sample of 6 PCAPs from mix.zip",
        publisher="Wickramasinghe et al., UNSW (IEEE S&P 2025)",
        canonical_source="https://cspectrum.web.cse.unsw.edu.au/",
        access_method="Short registration form (no approval step); ZIP links shown on the confirmation page.",
        access_category="ACADEMIC_ACCESS_REQUIRED",
        license="CC BY-NC 4.0 (verified on provider site " + VERIFIED_ON + "); citation of DOI 10.1109/SP61157.2025.00165 requested.",
        usage_restrictions="Academic and non-commercial research only; commercial use requires permission.",
        collection_period=UNKNOWN,
        raw_capture_available="YES (after form)", pcap_available="YES (after form)",
        labeling_methodology="Website-level labels from a customised Chromium crawler (benign web traffic).",
        label_confidence="HIGH (benign) but single application (browser)",
        composition="BENIGN (used as BENIGN_VALIDATION)",
        network_environment="Controlled crawler", os_environment=UNKNOWN,
        tls_version_coverage="TLS 1.3 (4 samples) and TLS 1.0 record version (2 samples) per Phase 6 validation",
        research_role="Benign validation baseline (Phase 6).",
        notes=("Six samples (sha256 recorded in data/manifests/dataset_manifest_20260815_092018.csv) were acquired on the "
               "original workstation. They are absent from this working copy. The original archive member names were not "
               "recorded. Re-acquisition requires the researcher to complete the provider's form; this automation does not."),
    )
    r = transition(r, "LICENSE_VERIFIED", "CC BY-NC 4.0 stated on provider site.", ["https://cgi.cse.unsw.edu.au/~cspectrum/"])
    r = transition(r, "ACCESS_PENDING", "Local copies absent; access requires the provider's registration form (PII), which must be completed by a human.",
                   ["docs/research/PHASE_8_9_10_INITIAL_STATE_AUDIT.md"])
    recs.append(r)

    r = new_record(
        "DS-006", "Beyond JA4+ / TLS fingerprinting datasets (Brno University of Technology)",
        publisher="NES group, Brno University of Technology (P. Matoušek et al.)",
        canonical_source="https://github.com/matousp/tls-fingerprinting",
        access_method="Public GitHub repository (datasets/desktop, datasets/mobile with PCAP and CSV).",
        access_category="LICENSE_UNCLEAR",
        license=UNKNOWN,
        usage_restrictions="No license file; only '(c) Petr Matousek, 2024'. Default copyright applies until clarified.",
        labeling_methodology="Application labels (77 desktop/mobile applications); not benign/malicious labels.",
        composition="Application-labelled (presumed benign) traffic", research_role="Candidate benign application corpus.",
        notes="Reviewed " + VERIFIED_ON + ". Action: request written permission or a license from the authors before acquisition.",
    )
    r = transition(r, "BLOCKED", "Repository has no license; acquisition deferred until the authors grant permission.",
                   ["https://github.com/matousp/tls-fingerprinting"])
    recs.append(r)

    r = new_record(
        "DS-007", "Annotated Encrypted Network Traffic (Brno University of Technology)",
        publisher="Brno University of Technology (REPORTED in docs/research/dataset-registry.csv)",
        access_method="Raw PCAPs reportedly require a justified request (REPORTED).",
        access_category="ACADEMIC_ACCESS_REQUIRED",
        research_role="Candidate unified benign+malicious corpus.",
        notes="Canonical URL not verified in Phase 8. Prepared request text: docs/research/dataset-access-request-drafts.md.",
    )
    r = transition(r, "ACCESS_PENDING", "Access requires a justified request that must be sent by the researcher.",
                   ["docs/research/dataset-access-request-drafts.md"])
    recs.append(r)

    r = new_record(
        "DS-009", "Stratosphere Malware Capture Facility Project (MCFP), selected 2017 Windows malware captures",
        publisher="Stratosphere Laboratory, Czech Technical University in Prague",
        canonical_source="https://www.stratosphereips.org/datasets-malware",
        access_method="Direct HTTPS download from https://mcfp.felk.cvut.cz/publicDatasets/ (no registration).",
        access_category="VERIFIED_AVAILABLE",
        license=("MCFP disclaimer (verified " + VERIFIED_ON + " in the project's README.html): 'You are free to use these files "
                 "as long as you reference this project and the authors' (Garcia, Sebastian. Malware Capture Facility Project). "
                 "The disclaimer is published with the project's captures; it is not repeated inside every malware directory."),
        usage_restrictions="Attribution required.",
        collection_period="2017 (per capture README timelines and file names)",
        raw_capture_available="YES", pcap_available="YES",
        labeling_methodology="Capture-level: VM infected with the sample named in the README ('Probable Name').",
        label_confidence="Capture level MEDIUM-HIGH ('probable' family names); flow level MEDIUM (pre-infection and background traffic included).",
        composition="MALICIOUS only",
        network_environment="Stratosphere lab Windows VMs", os_environment="Windows (file names 'winN')",
        research_role="Second, independent malicious source, captured in the same laboratory and period as DS-011.",
    )
    r = transition(r, "LICENSE_VERIFIED", "Project-level attribution terms reviewed.", ["https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-20/README.html"])
    recs.append(r)

    r = new_record(
        "DS-011", "Stratosphere CTU-Normal HTTPS captures (CTU-Normal-20 to -32)",
        publisher="Stratosphere Laboratory, Czech Technical University in Prague (captures by F. Strasak)",
        canonical_source="https://www.stratosphereips.org/datasets-normal",
        access_method="Direct HTTPS download from https://mcfp.felk.cvut.cz/publicDatasets/ (no registration).",
        access_category="VERIFIED_AVAILABLE",
        license=("MCFP disclaimer (verified " + VERIFIED_ON + " in CTU-Normal-20/README.html): 'You are free to use these files as long "
                 "as you reference this project and the authors'."),
        usage_restrictions="Attribution required.",
        collection_period="2017-04-18 to 2017-05-02 (file names)",
        raw_capture_available="YES", pcap_available="YES",
        labeling_methodology="Capture-level: 'normal connections to various HTTPS sites in Alexa top 1,000', no malware executed.",
        label_confidence="HIGH (benign) — single activity type (scripted/manual browsing of popular sites).",
        composition="BENIGN only",
        network_environment="Stratosphere lab hosts; READMEs state no intermediate proxy.",
        os_environment="Kali Linux / iceweasel 43.0.4 per most READMEs; some file names say 'win' (recorded as conflicts).",
        research_role="Independent benign source; same laboratory and period as DS-009.",
        notes="6 of 13 captures acquired in Phase 8 (CTU-Normal-20, 21, 23, 24, 26, 28) to bound download size.",
    )
    r = transition(r, "LICENSE_VERIFIED", "Attribution terms reviewed.", ["https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-20/README.html"])
    recs.append(r)

    for cid, name, url in (
        ("CAND-006", "CIC-IDS-2017", "https://www.unb.ca/cic/datasets/ids-2017.html"),
        ("CAND-007", "CIC-Bell-DNS-EXF-2021", "https://www.unb.ca/cic/datasets/dns-exf-2021.html"),
        ("CAND-008", "CIRA-CIC-DoHBrw-2020", "https://www.unb.ca/cic/datasets/dohbrw-2020.html"),
    ):
        r = new_record(cid, name, publisher="Canadian Institute for Cybersecurity, University of New Brunswick",
                       canonical_source=url, access_method="CIC dataset download form (PII + license acceptance) (REPORTED in Phase 7 Step 4).",
                       access_category="ACADEMIC_ACCESS_REQUIRED", research_role="Candidate benign source.")
        r = transition(r, "ACCESS_PENDING", "Registration form must be completed by the researcher.",
                       ["docs/research/phase-7-step-4-benign-dataset-verification.md"])
        recs.append(r)
    return recs


def _imported_registry_rows(existing: set) -> List[Dict]:
    """Remaining rows of docs/research/dataset-registry.csv, imported without re-evaluation."""
    out = []
    path = paths.PROJECT_ROOT / "docs" / "research" / "dataset-registry.csv"
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            did = row.get("dataset_id")
            if not did or did in existing:
                continue
            out.append(new_record(did, row.get("dataset_name") or UNKNOWN,
                                  canonical_source=row.get("official_url") or UNKNOWN,
                                  publisher=row.get("source") or UNKNOWN,
                                  access_category="INSUFFICIENT_EVIDENCE",
                                  notes="Imported from docs/research/dataset-registry.csv; not re-evaluated in Phase 8."))
    return out


def seed_registry(path=paths.REGISTRY_PATH, overwrite: bool = False) -> DatasetRegistry:
    reg = DatasetRegistry(path)
    for rec in _documented_records():
        if overwrite or reg.get(rec["dataset_id"]) is None:
            reg.upsert(rec)
    for rec in _imported_registry_rows(set(reg.records)):
        reg.upsert(rec)
    reg.save()
    return reg
