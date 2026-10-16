"""Evidence ledger rules and artefact-only report generation."""
import json

import pytest

import ml.reporting.report as rep
from ml.reporting.claims import _contrast_status, build_claims


def _c(diff, lo, hi, reject, status="FEW_GROUPS"):
    return {"status": "COMPLETED", "average_precision": {"difference": diff, "ci_low": lo, "ci_high": hi, "status": status},
            "holm": {"reject": reject}}


def test_contrast_status_never_upgrades_beyond_preliminary():
    assert _contrast_status([_c(0.05, 0.01, 0.09, True), _c(0.04, 0.01, 0.07, True)]) == "PRELIMINARY"
    assert _contrast_status([_c(-0.05, -0.09, -0.01, True)]) == "CONTRADICTED"
    assert _contrast_status([_c(0.05, -0.01, 0.09, False)]) == "INSUFFICIENT_EVIDENCE"
    assert _contrast_status([_c(0.05, 0.01, 0.09, True), _c(0.0, -0.02, 0.02, False)]) == "INSUFFICIENT_EVIDENCE"
    assert _contrast_status([_c(0.05, None, None, False, status="INSUFFICIENT_GROUPS")]) == "INSUFFICIENT_EVIDENCE"
    assert _contrast_status([None, {"status": "NOT_RUN"}]) == "UNTESTED"


def test_claims_without_experiments_are_untested_or_blocked():
    claims = {c["claim_id"]: c for c in build_claims({})}
    assert claims["C04"]["status"] == "UNTESTED"
    assert claims["C09"]["status"] == "BLOCKED"
    assert claims["C13"]["status"] == "UNTESTED"
    allowed = {"SUPPORTED", "PRELIMINARY", "CONTRADICTED", "UNTESTED", "BLOCKED", "INSUFFICIENT_EVIDENCE"}
    assert {c["status"] for c in claims.values()} <= allowed


def test_report_is_generated_from_artifacts_only(tmp_path, monkeypatch):
    monkeypatch.setattr(rep, "REPORT_DIR", tmp_path)
    monkeypatch.setattr(rep, "latest_suites", lambda: {})
    paths = rep.generate_report()
    data = json.loads((tmp_path / "latest_report.json").read_text(encoding="utf-8"))
    assert data["overall_status"]["publication_ready"] is False
    assert data["overall_status"]["scientifically_validated"] is False
    assert data["suites"] == {} and "pooled_capture_cv" in data["suites_not_run"]
    md = (tmp_path / "latest_report.md").read_text(encoding="utf-8")
    assert "No value in this document was entered by hand" in md and "Suites NOT_RUN" in md
    assert (tmp_path / "claim_ledger.json").exists() and paths["claims"].endswith("claim_ledger.json")
