"""Phase 8: registry lifecycle, provenance manifest, extraction safety and validation."""
import hashlib
import struct
import zipfile

import numpy as np
import pandas as pd
import pytest

from pipeline.corpus.artifacts import ArtifactManifest
from pipeline.corpus.extract import extract_member, mta_password
from pipeline.corpus.registry import (LEGAL_TRANSITIONS, STATES, UNKNOWN, DatasetRegistry, RegistryError, new_record,
                                      transition)
from pipeline.corpus.validation import (behavioral_hash_series, duplicate_diagnostics, fingerprint_overlap,
                                        label_conflicts, validate_pcap_file)


# ------------------------------------------------------------------ lifecycle --
def test_new_record_defaults_unknown_and_rejects_unknown_fields():
    rec = new_record("DS-X", "X")
    assert rec["state"] == "DISCOVERED"
    assert rec["license"] == UNKNOWN and rec["collection_period"] == UNKNOWN
    with pytest.raises(RegistryError):
        new_record("DS-X", "X", invented_field="value")


def test_illegal_transition_rejected():
    rec = new_record("DS-X", "X")
    with pytest.raises(RegistryError):
        transition(rec, "ADMITTED", "skip ahead")
    with pytest.raises(RegistryError):
        transition(rec, "ACQUIRED", "no license review yet")


def test_acquired_requires_reviewed_license():
    rec = new_record("DS-X", "X")
    rec = transition(rec, "LICENSE_VERIFIED", "reviewed")          # license field still UNKNOWN
    with pytest.raises(RegistryError, match="license"):
        transition(rec, "ACQUIRED", "downloaded")
    rec["license"] = "CC BY 4.0"
    assert transition(rec, "ACQUIRED", "downloaded")["state"] == "ACQUIRED"


def test_admission_requires_report_and_decision():
    rec = new_record("DS-X", "X", license="CC BY 4.0")
    for st, ctx in (("LICENSE_VERIFIED", {}), ("ACQUIRED", {}), ("CONTENT_VERIFIED", {"verified_artifacts": 1}),
                    ("PROCESSED", {"processing_record": "m.json"})):
        rec = transition(rec, st, f"to {st}", context=ctx)
    with pytest.raises(RegistryError):
        transition(rec, "ADMITTED", "looks fine", evidence_refs=["notes.txt"], context={"admission_decision": "ADMIT"})
    with pytest.raises(RegistryError):
        transition(rec, "ADMITTED", "report but no decision", evidence_refs=["data/corpus/admission_report.json"])
    ok = transition(rec, "ADMITTED", "admitted", evidence_refs=["data/corpus/admission_report.json"],
                    context={"admission_decision": "ADMIT_EXPLORATORY"})
    assert ok["state"] == "ADMITTED"
    assert [h["to_state"] for h in ok["history"]][-1] == "ADMITTED"


def test_rejection_requires_reason_and_transition_does_not_mutate_input():
    rec = new_record("DS-X", "X")
    with pytest.raises(RegistryError):
        transition(rec, "REJECTED", "bad")
    rej = transition(rec, "REJECTED", "bad", context={"reason": "license forbids research use"})
    assert rej["exclusion_reasons"] == ["license forbids research use"]
    assert rec["state"] == "DISCOVERED"


def test_every_state_has_transition_table_and_empty_evidence_rejected():
    assert set(LEGAL_TRANSITIONS) == set(STATES)
    with pytest.raises(RegistryError):
        transition(new_record("DS-X", "X"), "BLOCKED", "  ")


def test_registry_persistence_roundtrip(tmp_path):
    reg = DatasetRegistry(tmp_path / "reg.json")
    reg.upsert(new_record("DS-A", "A"))
    reg.apply("DS-A", "BLOCKED", "license unclear")
    reg.save()
    again = DatasetRegistry(tmp_path / "reg.json")
    assert again.get("DS-A")["state"] == "BLOCKED"
    assert len(again.get("DS-A")["history"]) == 2


# --------------------------------------------------------------- provenance --
def test_artifact_manifest_flags_changed_raw_checksum(tmp_path):
    man = ArtifactManifest(tmp_path / "m.json")
    man.record("RAW:C1", tier="RAW", dataset_id="DS", path="a.pcap", sha256="aa", size_bytes=1)
    e = man.record("RAW:C1", tier="RAW", dataset_id="DS", path="a.pcap", sha256="bb", size_bytes=1)
    assert e["verification"]["status"] == "FAILED"
    with pytest.raises(ValueError):
        man.record("X", tier="BOGUS", dataset_id="DS", path="x", sha256=None, size_bytes=None)


# ---------------------------------------------------------------- extraction --
def _zip(tmp_path, members):
    z = tmp_path / "src.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return z


def test_extract_only_pcap_members_and_verify_checksum(tmp_path):
    data = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20
    z = _zip(tmp_path, {"dir/../../evil.pcap": data, "malware.exe": b"MZ"})
    out = tmp_path / "out"
    good = extract_member(z, "dir/../../evil.pcap", out, None, hashlib.sha256(data).hexdigest())
    assert good.status == "EXTRACTED"
    assert (out / "evil.pcap").exists() and not (tmp_path / "evil.pcap").exists()   # basename only: no traversal
    assert extract_member(z, "malware.exe", out, None, None).status == "NOT_PCAP"
    bad = extract_member(z, "dir/../../evil.pcap", tmp_path / "out2", None, "0" * 64)
    assert bad.status == "CHECKSUM_MISMATCH" and not (tmp_path / "out2" / "evil.pcap").exists()


def test_extract_never_overwrites_different_content(tmp_path):
    data = b"\xd4\xc3\xb2\xa1" + b"\x01" * 20
    z = _zip(tmp_path, {"a.pcap": data})
    out = tmp_path / "out"
    out.mkdir()
    (out / "a.pcap").write_bytes(b"different")
    res = extract_member(z, "a.pcap", out, None, hashlib.sha256(data).hexdigest())
    assert res.status == "CHECKSUM_MISMATCH"
    assert (out / "a.pcap").read_bytes() == b"different"


def test_mta_password_scheme():
    assert mta_password("2026-04-16") == b"infected_20260416"
    with pytest.raises(ValueError):
        mta_password("16/04/2026")


# --------------------------------------------------------------- validation --
def _pcap(path, packets, linktype=1):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for ts, buf in packets:
            f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(buf), len(buf)))
            f.write(buf)


def test_pcap_validation_states(tmp_path):
    good = tmp_path / "g.pcap"
    _pcap(good, [(1.0, b"\x00" * 60), (0.5, b"\x00" * 60)])
    chk = validate_pcap_file(good)
    assert chk.status == "VALID" and chk.packet_count == 2 and chk.non_monotonic_timestamps == 1
    empty = tmp_path / "e.pcap"
    _pcap(empty, [])
    assert validate_pcap_file(empty).status == "INVALID"
    junk = tmp_path / "j.pcap"
    junk.write_bytes(b"not a capture at all")
    assert validate_pcap_file(junk).status == "INVALID"
    odd = tmp_path / "o.pcap"
    _pcap(odd, [(1.0, b"\x00" * 10)], linktype=147)
    assert validate_pcap_file(odd).status == "UNSUPPORTED"
    assert validate_pcap_file(tmp_path / "missing.pcap").status == "MISSING"


def test_behavioral_hash_matches_phase7_definition():
    from pipeline.experimental_dataset_constructor import ExperimentConstructor
    ms = pd.DataFrame({"model_safe_index": [0, 1, 2], "label": ["MALICIOUS"] * 3,
                       "flow_duration": [1.0, 1.0, 2.0], "ja3_hash": ["a", "a", None]})
    prov = pd.DataFrame({"model_safe_index": [0, 1, 2], "source_file": ["f"] * 3, "dataset_id": ["DS"] * 3})
    legacy = ExperimentConstructor(ms, prov).full_df["behavioral_hash"]
    ours = behavioral_hash_series(ms, ["flow_duration", "ja3_hash"])
    assert list(legacy) == list(ours)
    assert ours.iloc[0] == ours.iloc[1] != ours.iloc[2]


def test_duplicate_and_conflict_diagnostics():
    df = pd.DataFrame({"behavioral_hash": ["h1", "h1", "h2", "h3", "h3"], "capture_id": ["a", "b", "a", "c", "c"],
                       "dataset_id": ["D1", "D2", "D1", "D1", "D1"], "label": ["MALICIOUS", "BENIGN", "BENIGN", "BENIGN", "BENIGN"]})
    d = duplicate_diagnostics(df)
    assert d["duplicate_groups"] == 2 and d["flows_in_duplicate_groups"] == 4
    assert d["cross_capture_groups"] == 1 and d["cross_label_groups"] == 1
    assert label_conflicts(df) == ["h1"]


def test_fingerprint_overlap_counts():
    df = pd.DataFrame({"ja3_hash": ["x", "x", "y", None], "label": ["MALICIOUS", "BENIGN", "BENIGN", "BENIGN"]})
    o = fingerprint_overlap(df, "ja3_hash")
    assert o["distinct_shared"] == 1 and o["distinct_benign_only"] == 1 and o["flows_with_shared_values"] == 2


def test_capture_plan_generation_is_deterministic():
    from pipeline.corpus.capture_plan import build_default_plan
    a, b = build_default_plan(), build_default_plan()
    assert a == b
    ids = [c["capture_id"] for c in a["captures"]]
    assert len(ids) == len(set(ids))
    for c in a["captures"]:
        assert c["expected_sha256"] == UNKNOWN or len(c["expected_sha256"]) == 64
