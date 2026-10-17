"""Canonical flow contract helpers shared by all event sources (synthetic values only)."""
import hashlib

import pytest

from pipeline.canonical_flow import (RecentKeys, count_features, endpoint, normalize_hash32, normalize_ja3,
                                     normalize_ja4, protocol_name, tls_version_label, unobserved_fields)
from pipeline.feature_extraction import extract_flow_level_features


def test_ja3_hash_is_lowercased_and_kept():
    assert normalize_ja3("6734F37431670B3AB4292B8F60F29984") == ("6734f37431670b3ab4292b8f60f29984", "REPORTED_HASH", None)


def test_ja3_string_in_hash_field_is_hashed_like_ja3():
    s = "771,4865-4866-4867,0-23-65281,29-23-24,0"
    assert normalize_ja3(s) == (hashlib.md5(s.encode()).hexdigest(), "MD5_OF_REPORTED_STRING", None)
    assert normalize_ja3(None, s)[0] == hashlib.md5(s.encode()).hexdigest()


def test_incomplete_or_invalid_ja3_is_rejected_not_kept():
    # Three fields only (the Phase 11 eBPF fixture value): not a JA3 string, not a hash.
    h, derivation, reason = normalize_ja3("771,4865-4866,0-23")
    assert h is None and derivation is None and reason
    assert normalize_ja3("myja3hash")[0] is None
    assert normalize_ja3("-") == (None, None, None) and normalize_ja3(None) == (None, None, None)


def test_ja4_syntax_validation():
    assert normalize_ja4("t13d1516h2_8daaf6152771_e5627efa2ab1") == ("t13d1516h2_8daaf6152771_e5627efa2ab1", None)
    assert normalize_ja4("t12n0705h2_aaaaaaaaaaaa_bbbbbbbbbbbb")[0] is not None   # ETTH 'n' for no SNI
    assert normalize_ja4("t13d1516h2_suricata")[0] is None
    assert normalize_ja4(None) == (None, None)
    assert normalize_hash32("EC74A5C5110605F9F8EAC84B7252E1FB") == "ec74a5c5110605f9f8eac84b7252e1fb"
    assert normalize_hash32("-") is None


@pytest.mark.parametrize("raw,label", [("TLSv12", "1.2"), ("TLSv13", "1.3"), ("TLS 1.2", "1.2"), ("TLS 1.3", "1.3"),
                                       ("TLSv1", "1.0"), ("SSLv3", "SSL3"), (771, "1.2"), ("0x0304", "1.3"),
                                       (1.2, "1.2"), ("UNDETERMINED", None), (None, None)])
def test_tls_version_labels(raw, label):
    assert tls_version_label(raw) == label


def test_count_features_use_offline_formulas():
    got = count_features(2.0, 10, 5, 1000, 500)
    want = extract_flow_level_features({"duration": 2.0, "packet_count": 15, "forward_packet_count": 10,
                                        "reverse_packet_count": 5, "byte_count": 1500, "forward_byte_count": 1000,
                                        "reverse_byte_count": 500})
    assert got == want


def test_count_features_never_substitute_zero_for_unobserved_inputs():
    got = count_features(None, 4, 0, None, None)
    assert got["flow_duration"] is None and got["packets_per_second"] is None
    assert got["total_bytes"] is None and got["bytes_per_second"] is None and got["byte_count_asymmetry"] is None
    assert got["total_packets"] == 4 and got["packet_count_asymmetry"] == 1.0
    # Zero duration is observed: rates are undefined (None), as offline (NaN), never count/0 or count.
    zero = count_features(0.0, 1, 0, 60, 0)
    assert zero["flow_duration"] == 0.0 and zero["packets_per_second"] is None


def test_protocol_and_endpoint_are_not_defaulted():
    assert protocol_name("tcp") == "TCP" and protocol_name(17) == "UDP" and protocol_name("icmp") == "ICMP"
    assert protocol_name(None) is None
    assert endpoint("10.0.0.1", 443) == "10.0.0.1:443"
    assert endpoint(None, 443) is None and endpoint("10.0.0.1", None) is None


def test_unobserved_fields_lists_missing_values():
    flow = {"forward_endpoint": "a:1", "reverse_endpoint": "b:2", "flow_duration": None, "total_packets": 3,
            "total_bytes": float("nan"), "packets_per_second": None, "bytes_per_second": None}
    assert unobserved_fields(flow) == ["flow_duration", "total_bytes", "packets_per_second", "bytes_per_second"]


def test_recent_keys_is_bounded():
    keys = RecentKeys(maxlen=3)
    for k in "abcd":
        keys.add(k)
    assert "a" not in keys and "d" in keys and len(keys) == 3
