"""
Specification and reference tests for JA4 TLS client fingerprinting.
Tests FoxIO reference vectors, ETTH legacy v1 behavior, explicit versioning,
and edge cases (GREASE filtering, empty ciphers/extensions, ALPN/SNI formatting).
"""
import pytest
from pipeline.tls_fingerprinting import (
    generate_ja4,
    generate_ja4_v1,
    generate_ja4_v2,
    generate_ja4_foxio,
    parse_client_hello,
    is_grease
)

# FoxIO JA4 official reference example (Chrome ClientHello with ALPN h2, SNI example.org)
FOXIO_CIPHERS = [
    0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303,
    0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9
]
FOXIO_EXTENSIONS = [
    0x0005, 0x000a, 0x000b, 0x000d, 0x0012, 0x0015, 0x0017,
    0x001b, 0x0023, 0x002b, 0x002d, 0x0033, 0x4469, 0xff01
]
FOXIO_SIG_ALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
FOXIO_JA4_REFERENCE = "t13d1516h2_8daaf6152771_e5627efa2ab1"
ETTH_JA4_V1_REFERENCE = "t13d1516h2_8daaf6152771_0adf69b4533f"


def build_raw_client_hello(
    ciphers=FOXIO_CIPHERS,
    extensions=FOXIO_EXTENSIONS,
    sig_algs=FOXIO_SIG_ALGS,
    sni_hostname="example.org",
    alpn_str="h2",
    supported_version=0x0304
) -> bytes:
    """Builds a realistic synthetic ClientHello matching wire structure."""
    def ext(t, body=b""):
        return t.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body

    sig_bytes = b"".join(s.to_bytes(2, "big") for s in sig_algs)
    bodies = {
        0x000a: b"\x00\x02\x00\x1d",
        0x000b: b"\x01\x00",
        0x000d: len(sig_bytes).to_bytes(2, "big") + sig_bytes,
        0x002b: b"\x02" + supported_version.to_bytes(2, "big") if supported_version else b""
    }

    exts = b""
    if sni_hostname is not None:
        name_bytes = sni_hostname.encode("ascii")
        sni_body = b"\x00" + len(name_bytes).to_bytes(2, "big") + name_bytes
        exts += ext(0x0000, len(sni_body).to_bytes(2, "big") + sni_body)

    if alpn_str:
        alpn_bytes = alpn_str.encode("ascii")
        alpn_body = len(alpn_bytes).to_bytes(1, "big") + alpn_bytes
        exts += ext(0x0010, len(alpn_body).to_bytes(2, "big") + alpn_body)

    exts += b"".join(ext(e, bodies.get(e, b"")) for e in extensions)
    ciphers_bytes = b"".join(c.to_bytes(2, "big") for c in ciphers)
    body = (
        b"\x03\x03" + b"\x22" * 32 + b"\x00"
        + len(ciphers_bytes).to_bytes(2, "big") + ciphers_bytes
        + b"\x01\x00"
        + len(exts).to_bytes(2, "big") + exts
    )
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def test_foxio_reference_vector():
    """Verify official FoxIO reference ClientHello produces exact JA4 reference string."""
    raw = build_raw_client_hello()
    parsed = parse_client_hello(raw)
    assert not parsed.get("error")

    # FoxIO compliant v2
    v2_ja4 = generate_ja4_foxio(parsed)
    assert v2_ja4 == FOXIO_JA4_REFERENCE
    assert generate_ja4_v2(parsed) == FOXIO_JA4_REFERENCE
    assert generate_ja4(parsed, version="v2_foxio") == FOXIO_JA4_REFERENCE
    assert generate_ja4(parsed, version="v2") == FOXIO_JA4_REFERENCE


def test_etth_v1_legacy_compatibility():
    """Verify legacy ETTH v1 behavior is preserved when requested or by default."""
    raw = build_raw_client_hello()
    parsed = parse_client_hello(raw)
    assert not parsed.get("error")

    # Default generate_ja4 uses v1_legacy
    default_ja4 = generate_ja4(parsed)
    assert default_ja4 == ETTH_JA4_V1_REFERENCE
    assert generate_ja4_v1(parsed) == ETTH_JA4_V1_REFERENCE
    assert generate_ja4(parsed, version="v1_legacy") == ETTH_JA4_V1_REFERENCE


def test_ja4_deviations_explicit():
    """Explicitly verify the differences between v1 and v2 on the reference vector."""
    raw = build_raw_client_hello()
    parsed = parse_client_hello(raw)

    v1 = generate_ja4_v1(parsed)
    v2 = generate_ja4_foxio(parsed)

    # Both share JA4_a and JA4_b on this vector
    assert v1.split("_")[0] == v2.split("_")[0] == "t13d1516h2"
    assert v1.split("_")[1] == v2.split("_")[1] == "8daaf6152771"

    # Part c differs because v1 sorts signature algorithms while v2 keeps wire order
    assert v1.split("_")[2] == "0adf69b4533f"
    assert v2.split("_")[2] == "e5627efa2ab1"


def test_sni_formatting_difference():
    """Test missing SNI: v1 uses 'n', v2 uses 'i' (FoxIO)."""
    raw_no_sni = build_raw_client_hello(sni_hostname=None)
    parsed = parse_client_hello(raw_no_sni)

    v1 = generate_ja4_v1(parsed)
    v2 = generate_ja4_foxio(parsed)

    # In v1: t13n...
    assert v1.startswith("t13n")
    # In v2: t13i...
    assert v2.startswith("t13i")


def test_no_signature_algorithms_formatting():
    """When no sig_algs extension exists, v1 hashes ext_str + '_', v2 hashes ext_str."""
    exts_without_13 = [e for e in FOXIO_EXTENSIONS if e != 0x000d]
    raw = build_raw_client_hello(extensions=exts_without_13, sig_algs=[])
    parsed = parse_client_hello(raw)

    v1 = generate_ja4_v1(parsed)
    v2 = generate_ja4_foxio(parsed)

    # Both should be valid strings, but different hashes due to trailing '_' in v1
    assert v1 != v2
    assert len(v1.split("_")[2]) == 12
    assert len(v2.split("_")[2]) == 12


def test_empty_ciphers_and_extensions():
    """Test edge cases with no ciphers and no extensions."""
    ch_empty = {
        "client_version": 0x0303,
        "ciphers": [],
        "extensions": [],
        "supported_versions": [],
        "sig_algs": [],
        "sni_present": False,
        "alpn_str": "",
        "has_supported_versions": False,
        "error": None
    }
    v2 = generate_ja4_foxio(ch_empty)
    # ja4_b and ja4_c must be "000000000000"
    parts = v2.split("_")
    assert parts[0] == "t12i000000"
    assert parts[1] == "000000000000"
    assert parts[2] == "000000000000"


def test_grease_exclusion():
    """Test that GREASE values are filtered out of all parts in v2."""
    ch_grease = {
        "client_version": 0x0303,
        "ciphers": [0x1a1a, 0x1301, 0x2a2a, 0x1302],
        "extensions": [0x3a3a, 0x0005, 0x4a4a],
        "supported_versions": [0x5a5a, 0x0304],
        "sig_algs": [0x6a6a, 0x0403],
        "sni_present": True,
        "alpn_str": "h2",
        "has_supported_versions": True,
        "error": None
    }
    v2 = generate_ja4_foxio(ch_grease)
    # Version should be 13 from 0x0304 (0x5a5a ignored)
    # SNI: d
    # Non-GREASE ciphers count: 2 (0x1301, 0x1302)
    # Non-GREASE extensions count: 1 (0x0005)
    # ALPN: h2
    assert v2.startswith("t13d0201h2_")


def test_extension_count_caps_at_99():
    """FoxIO JA4 caps cipher count and extension count at 99."""
    ch_large = {
        "client_version": 0x0303,
        "ciphers": [i for i in range(1, 150) if not is_grease(i)],
        "extensions": [i for i in range(1, 150) if not is_grease(i)],
        "supported_versions": [0x0304],
        "sig_algs": [],
        "sni_present": False,
        "alpn_str": "",
        "has_supported_versions": True,
        "error": None
    }
    v2 = generate_ja4_foxio(ch_large)
    # Count should be capped at 99
    assert v2.startswith("t13i999900_")


def test_malformed_client_hello_returns_none():
    """Verify None is returned when error is present."""
    assert generate_ja4_foxio({"error": "truncated"}) is None
    assert generate_ja4_v1({"error": "truncated"}) is None
    assert generate_ja4(None) is None
