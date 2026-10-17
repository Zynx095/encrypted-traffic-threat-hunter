"""JA4 conformance against FoxIO's published reference outputs (not self-authored expectations).

Expected values come from the FoxIO reference implementation snapshots pinned in
data/reference/foxio_ja4/vectors.json. The capture files are fetched separately
(``python -m pipeline.fetch_foxio_ja4_vectors``) and verified by SHA-256; when they are absent the
pcap test is skipped with that reason, and conformance must not be claimed from that run.
"""
import hashlib
import json
from pathlib import Path

import pytest

from pipeline.ja4_reference import clienthello_from_stream, extract_tcp_clienthellos
from pipeline.tls_fingerprinting import _foxio_alpn, generate_ja4_foxio, parse_client_hello

REF = Path(__file__).resolve().parent.parent / "data" / "reference" / "foxio_ja4"
MANIFEST = json.loads((REF / "vectors.json").read_text(encoding="utf-8"))


def _pcaps_present():
    for name, digest in MANIFEST["pcap_sha256"].items():
        p = REF / "pcap" / name
        if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest() != digest:
            return False
    return True


def test_manifest_is_pinned_and_nonempty():
    assert len(MANIFEST["commit"]) == 40
    assert len(MANIFEST["vectors"]) >= 100
    assert all(v["ja4"].startswith("t") for v in MANIFEST["vectors"])


@pytest.mark.skipif(not _pcaps_present(), reason="FoxIO reference pcaps not fetched or SHA-256 mismatch")
def test_every_foxio_tcp_vector_matches():
    cache, failures = {}, []
    for v in MANIFEST["vectors"]:
        if v["pcap"] not in cache:
            cache[v["pcap"]] = extract_tcp_clienthellos(str(REF / "pcap" / v["pcap"]))
        rec = cache[v["pcap"]].get((v["client"][0], v["client"][1], v["server"][0], v["server"][1]))
        got = generate_ja4_foxio(parse_client_hello(rec)) if rec else None
        if got != v["ja4"]:
            failures.append((v["pcap"], v["client"], v["ja4"], got))
    assert not failures, failures[:5]


@pytest.mark.parametrize("raw,expected", [
    (b"", "00"), (b"h2", "h2"), (b"http/1.1", "h1"), (b"x", "xx"),
    (b"\xba\xad", "99"),        # FoxIO snapshot tls-non-ascii-alpn.pcapng
    (b"a\xff", "a9"), (b" a", " a"),
])
def test_alpn_follows_reference_implementation(raw, expected):
    assert _foxio_alpn(raw) == expected


def test_version_uses_highest_supported_version_and_ignores_record_version():
    base = {"ciphers": [0x1301], "extensions": [0x002b], "sig_algs": [], "sni_present": False,
            "alpn_first_raw": b"", "error": None}
    assert generate_ja4_foxio({**base, "supported_versions": [0x0a0a, 0x0303, 0x0304], "client_version": 0x0303}).startswith("t13")
    assert generate_ja4_foxio({**base, "supported_versions": [], "client_version": 0x0301}).startswith("t10")
    assert generate_ja4_foxio({**base, "supported_versions": [], "client_version": 0x1234}).startswith("t00")


def test_counts_cap_at_99_and_empty_lists_are_zero_hashes():
    many = list(range(0x0100, 0x0100 + 120))
    fp = generate_ja4_foxio({"ciphers": many, "extensions": many, "sig_algs": [], "supported_versions": [],
                             "client_version": 0x0303, "sni_present": True, "alpn_first_raw": b"", "error": None})
    assert fp[3:8] == "d9999"
    empty = generate_ja4_foxio({"ciphers": [], "extensions": [0x0000, 0x0010], "sig_algs": [], "supported_versions": [],
                                "client_version": 0x0303, "sni_present": True, "alpn_first_raw": b"h2", "error": None})
    assert empty.endswith("_000000000000_000000000000")


def test_missing_or_malformed_hello_gives_no_fingerprint():
    assert generate_ja4_foxio(None) is None
    assert generate_ja4_foxio({"error": "truncated"}) is None
    assert generate_ja4_foxio(parse_client_hello(b"\x16\x03\x01\x00\x05\x01\x00")) is None


def test_stream_helper_refuses_incomplete_clienthello():
    # Record header promises 100 bytes; only 10 present -> no ClientHello, nothing fabricated.
    assert clienthello_from_stream(b"\x16\x03\x01\x00\x64" + b"\x01" * 10) is None
    assert clienthello_from_stream(b"\x17\x03\x03\x00\x01\x00") is None
