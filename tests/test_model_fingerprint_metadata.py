"""Registry entries record which fingerprint implementation produced their training values."""
import pandas as pd
import pytest

from ml.model_registry import ModelRegistryError, _fingerprint_implementations
from pipeline.canonical_flow import JA4_VERSION_FOXIO, LEGACY_MODEL_JA4, model_ja4_requirement

JA4_COLS = {"numeric": [], "categorical": ["ja4"]}


def test_corpus_v3_frame_without_tag_records_historical_etth_ja4():
    out = _fingerprint_implementations(pd.DataFrame({"ja4": ["x", None]}), JA4_COLS)
    assert out["ja4"] == LEGACY_MODEL_JA4


def test_tagged_foxio_frame_records_exact_version():
    df = pd.DataFrame({"ja4": ["a", "b"], "ja4_implementation": ["FOXIO_JA4"] * 2, "ja4_version": [JA4_VERSION_FOXIO] * 2})
    assert _fingerprint_implementations(df, JA4_COLS)["ja4"] == {"implementation": "FOXIO_JA4", "version": JA4_VERSION_FOXIO}


def test_mixed_implementations_are_refused_at_registration():
    df = pd.DataFrame({"ja4": ["a", "b"], "ja4_implementation": ["FOXIO_JA4", "ETTH_JA4_V1"]})
    with pytest.raises(ModelRegistryError):
        _fingerprint_implementations(df, JA4_COLS)


def test_flow_only_models_record_no_ja4_requirement():
    assert "ja4" not in _fingerprint_implementations(pd.DataFrame({"x": [1]}), {"numeric": ["x"], "categorical": []})


def test_unrecorded_entries_default_to_the_historical_implementation():
    assert model_ja4_requirement({"model_id": "old"}) == LEGACY_MODEL_JA4
