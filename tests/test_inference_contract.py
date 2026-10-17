"""
Cross-phase inference contract: models trained on ETTH packet features and ETTH JA4 values must
refuse inputs whose provenance differs (sensor aggregates, FoxIO JA4). Synthetic fixtures only.
"""
import pytest

from backend.inference_engine import InferenceEngine
from pipeline.tls_fingerprinting import generate_ja4, parse_client_hello
from tests.ml_fixtures import complete_flow_record, fixture_models

# FoxIO JA4 reference example (JA4 technical details: Chrome ClientHello), lists in wire order.
FOXIO_CIPHERS = [0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303, 0xc013, 0xc014, 0xc02b, 0xc02c,
                 0xc02f, 0xc030, 0xcca8, 0xcca9]
FOXIO_EXTENSIONS = [0x0005, 0x000a, 0x000b, 0x000d, 0x0012, 0x0015, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d,
                    0x0033, 0x4469, 0xff01]
FOXIO_SIG_ALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
FOXIO_JA4 = "t13d1516h2_8daaf6152771_e5627efa2ab1"


def _client_hello() -> bytes:
    def ext(t, body=b""):
        return t.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body
    sig = b"".join(s.to_bytes(2, "big") for s in FOXIO_SIG_ALGS)
    bodies = {0x000a: b"\x00\x02\x00\x1d", 0x000b: b"\x01\x00", 0x000d: len(sig).to_bytes(2, "big") + sig,
              0x002b: b"\x02\x03\x04"}
    name = b"\x00" + (11).to_bytes(2, "big") + b"example.org"
    exts = ext(0x0000, len(name).to_bytes(2, "big") + name) + ext(0x0010, b"\x00\x03\x02h2")
    exts += b"".join(ext(e, bodies.get(e, b"")) for e in FOXIO_EXTENSIONS)
    ciphers = b"".join(c.to_bytes(2, "big") for c in FOXIO_CIPHERS)
    body = (b"\x03\x03" + b"\x22" * 32 + b"\x00" + len(ciphers).to_bytes(2, "big") + ciphers + b"\x01\x00"
            + len(exts).to_bytes(2, "big") + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def test_etth_ja4_differs_from_foxio_reference_vector():
    """Documents the incompatibility: same a/b parts, different c part (ETTH sorts signature algorithms)."""
    etth = generate_ja4(parse_client_hello(_client_hello()))
    assert etth.split("_")[:2] == FOXIO_JA4.split("_")[:2]
    assert etth != FOXIO_JA4
    assert etth == "t13d1516h2_8daaf6152771_0adf69b4533f"


@pytest.fixture()
def engine(tmp_path):
    eng = InferenceEngine(autoload=False)
    for track, (entry, model) in fixture_models(tmp_path).items():
        eng.install(track, entry, model)
    return eng


@pytest.mark.parametrize("track", ["C_JA4", "E_JA4_FLOW"])
def test_foxio_ja4_is_refused_by_etth_ja4_models(engine, track):
    res = engine.predict(complete_flow_record(ja4_implementation="FOXIO_JA4"), track=track)
    assert res["status"] == "SKIPPED" and res["prediction"] == "UNKNOWN" and res["threat_score"] == 0.0
    assert res["skip_reason"].startswith("INCOMPATIBLE_FEATURE_SCHEMA") and "FOXIO_JA4" in res["skip_reason"]


def test_etth_ja4_records_are_still_scored(engine):
    assert engine.predict(complete_flow_record(ja4_implementation="ETTH_JA4_V1"), track="C_JA4")["status"] == "COMPLETED"
    assert engine.predict(complete_flow_record(ja4_version=None), track="C_JA4")["status"] == "COMPLETED"


@pytest.mark.parametrize("track", ["C_JA4", "E_JA4_FLOW"])
@pytest.mark.parametrize("overrides", [
    {"ja4_implementation": None, "ja4_version": None},     # undeclared: fail closed (was accepted before)
    {"ja4_implementation": "UNKNOWN"},
    {"ja4_implementation": "SOME_OTHER_JA4"},
    {"ja4_version": "etth_ja4_v0"},                        # right family, wrong version
])
def test_undeclared_unknown_or_mismatched_ja4_fails_closed(engine, track, overrides):
    res = engine.predict(complete_flow_record(**overrides), track=track)
    assert res["status"] == "SKIPPED" and res["threat_score"] == 0.0
    assert res["skip_reason"].startswith("INCOMPATIBLE_FEATURE_SCHEMA") and "ja4" in res["skip_reason"]


def test_model_declaring_foxio_refuses_etth_v1_and_accepts_exact_foxio(tmp_path):
    from pipeline.canonical_flow import JA4_VERSION_FOXIO
    eng = InferenceEngine(autoload=False)
    entry, model = fixture_models(tmp_path, tracks=["C_JA4"])["C_JA4"]
    entry = dict(entry, fingerprint_implementations={"ja4": {"implementation": "FOXIO_JA4", "version": JA4_VERSION_FOXIO}})
    eng.install("C_JA4", entry, model)
    assert eng.predict(complete_flow_record(), track="C_JA4")["status"] == "SKIPPED"
    ok = complete_flow_record(ja4_implementation="FOXIO_JA4", ja4_version=JA4_VERSION_FOXIO)
    assert eng.predict(ok, track="C_JA4")["status"] == "COMPLETED"
    stale = complete_flow_record(ja4_implementation="FOXIO_JA4", ja4_version="ja4_foxio-older_etth-1")
    assert eng.predict(stale, track="C_JA4")["status"] == "SKIPPED"
    # A sensor's FOXIO_JA4 without a version is not assumed to match ETTH's validated version.
    assert eng.predict(complete_flow_record(ja4_implementation="FOXIO_JA4", ja4_version=None), track="C_JA4")["status"] == "SKIPPED"


def test_missing_ja4_is_missing_not_substituted(engine):
    res = engine.predict(complete_flow_record(ja4=None), track="C_JA4")
    assert res["status"] == "SKIPPED" and "JA4 fingerprint missing" in res["skip_reason"]


def test_ja4_implementation_does_not_affect_ja3_models(engine):
    assert engine.predict(complete_flow_record(ja4_implementation="FOXIO_JA4"), track="B_JA3")["status"] == "COMPLETED"


@pytest.mark.parametrize("track", ["A_FLOW", "D_JA3_FLOW", "E_JA4_FLOW"])
def test_sensor_aggregates_are_refused_by_flow_feature_models(engine, track):
    # Even a record with every column present is refused when its statistics come from a sensor.
    res = engine.predict(complete_flow_record(feature_provenance="SENSOR_AGGREGATE"), track=track)
    assert res["status"] == "SKIPPED" and "SENSOR_AGGREGATE" in res["skip_reason"]


def test_sensor_provenance_does_not_block_fingerprint_only_models(engine):
    rec = complete_flow_record(feature_provenance="SENSOR_AGGREGATE")
    assert engine.predict(rec, track="B_JA3")["status"] == "COMPLETED"
    assert engine.predict(complete_flow_record(feature_provenance="ETTH_PACKET_FEATURES"), track="A_FLOW")["status"] == "COMPLETED"


def test_contract_problem_is_reported_before_absent_columns(engine):
    sparse = {"flow_id": "z", "feature_provenance": "SENSOR_AGGREGATE", "flow_duration": 1.0}
    reason = engine.predict(sparse, track="A_FLOW")["skip_reason"]
    assert reason.index("SENSOR_AGGREGATE") < reason.index("absent")
