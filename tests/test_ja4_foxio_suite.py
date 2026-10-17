"""FoxIO JA4 benchmark plumbing: no silent fallback to historical JA4, provenance in configs."""
import pandas as pd
import pytest

from ml.benchmark import suites as S
from pipeline.corpus import recompute_ja4_foxio as R


def test_invalidated_suite_refuses_to_run():
    with pytest.raises(ValueError, match="invalidated"):
        S.suite_frame(S.SUITES["ja4_v2_comparison"])


def test_invalid_v2_recompute_script_refuses_to_run():
    from pipeline.corpus.recompute_ja4_v2 import build_ja4_v2_corpus
    with pytest.raises(RuntimeError, match="invalid"):
        build_ja4_v2_corpus()


def test_foxio_frame_requires_built_table(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "OUTPUT_MANIFEST", tmp_path / "missing.json")
    monkeypatch.setattr(R, "OUTPUT_TABLE", tmp_path / "missing.parquet")
    with pytest.raises(FileNotFoundError):
        S._with_foxio_ja4(pd.DataFrame({"corpus_index": [0], "ja4": ["historical"]}))


def test_foxio_frame_replaces_historical_ja4_and_withholds_truncated(monkeypatch):
    fox = pd.DataFrame({"corpus_index": [0, 1, 2], "ja4_foxio": ["t13d_a_b", None, None],
                        "ja4_foxio_status": ["COMPUTED", "INCOMPLETE_FIRST_SEGMENT", "NO_CLIENTHELLO"],
                        "ja4_implementation": ["FOXIO_JA4", None, None], "ja4_version": ["v", None, None]})
    monkeypatch.setattr(R, "load_ja4_foxio", lambda require_complete=True: fox)
    out = S._with_foxio_ja4(pd.DataFrame({"corpus_index": [0, 1, 2], "ja4": ["old0", "old1", None]}))
    assert out["ja4"].tolist()[0] == "t13d_a_b"
    assert out["ja4"].isna().tolist() == [False, True, True]       # truncated v1 value is not carried over
    assert "old0" not in out["ja4"].tolist()


def test_foxio_frame_rejects_uncovered_rows(monkeypatch):
    fox = pd.DataFrame({"corpus_index": [0], "ja4_foxio": ["x"], "ja4_foxio_status": ["COMPUTED"],
                        "ja4_implementation": ["FOXIO_JA4"], "ja4_version": ["v"]})
    monkeypatch.setattr(R, "load_ja4_foxio", lambda require_complete=True: fox)
    with pytest.raises(ValueError, match="does not cover"):
        S._with_foxio_ja4(pd.DataFrame({"corpus_index": [0, 1], "ja4": ["a", "b"]}))


def test_ja4_provenance_only_for_foxio_suites_and_ja4_tracks():
    prov = S._ja4_provenance(S.SUITES["ja4_foxio_capture_cv"])
    assert prov["ja4_implementation"] == "FOXIO_JA4" and prov["ja4_version"].startswith("ja4_foxio-")
    assert S._ja4_provenance(S.SUITES["pooled_capture_cv"]) == {}      # historical config hashes unchanged
    assert S.track_uses_ja4("E_JA4_FLOW") and S.track_uses_ja4("A_FLOW@JA4POP")
    assert not S.track_uses_ja4("B_JA3") and not S.track_uses_ja4("A_FLOW")


def test_loader_rejects_checksum_mismatch(tmp_path, monkeypatch):
    table, manifest = tmp_path / "t.parquet", tmp_path / "m.json"
    pd.DataFrame({"corpus_index": [0]}).to_parquet(table)
    manifest.write_text('{"output_sha256": "0", "complete": true}', encoding="utf-8")
    monkeypatch.setattr(R, "OUTPUT_TABLE", table)
    monkeypatch.setattr(R, "OUTPUT_MANIFEST", manifest)
    with pytest.raises(ValueError, match="checksum"):
        R.load_ja4_foxio()
