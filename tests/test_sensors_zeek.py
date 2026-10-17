import pytest
import asyncio
from pathlib import Path

from backend.event_sources.zeek_source import ZeekEventSource, ZeekCorrelator

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "data" / "fixtures" / "sensors"

# Synthetic, syntactically valid fingerprints (the canonical contract rejects placeholder strings).
JA3_A = "6734f37431670b3ab4292b8f60f29984"
JA3_B = "51c64c77e60f3980eea90869b68c58a8"
JA4_A = "t13d1516h2_8daaf6152771_e5627efa2ab1"


def _conn(uid, **extra):
    rec = {"uid": uid, "id.orig_h": "192.168.1.5", "id.orig_p": 44100, "id.resp_h": "1.2.3.4", "id.resp_p": 443,
           "proto": "tcp", "duration": 1.5, "orig_pkts": 10, "resp_pkts": 12, "orig_bytes": 1000,
           "resp_bytes": 4000, "conn_state": "SF"}
    rec.update(extra)
    return rec


def test_zeek_correlator_conn_then_ssl():
    correlator = ZeekCorrelator()
    conn_rec = _conn("test_uid_1")
    ssl_rec = {
        "uid": "test_uid_1",
        "server_name": "example.com",
        "version": "TLSv13",
        "ja3": JA3_A,
        "ja4": JA4_A,
        "established": True
    }

    # 1. conn arrives first -> cached
    res1 = correlator.add_conn_record(conn_rec)
    assert res1 is None

    # 2. ssl arrives second -> merged & emitted
    res2 = correlator.add_ssl_record(ssl_rec)
    assert res2 is not None
    assert res2["flow_id"] == "test_uid_1"
    assert res2["source_ip"] == "192.168.1.5"
    assert res2["destination_port"] == 443
    assert res2["total_packets"] == 22
    assert res2["total_bytes"] == 5000
    assert res2["sni"] == "example.com"
    assert res2["ja3_hash"] == JA3_A
    assert res2["ja4"] == JA4_A
    assert res2["clienthello_present"] is True

def test_zeek_correlator_ssl_then_conn_out_of_order():
    correlator = ZeekCorrelator()
    conn_rec = {
        "uid": "test_uid_ooo",
        "id.orig_h": "10.0.0.1",
        "id.orig_p": 50000,
        "id.resp_h": "10.0.0.2",
        "id.resp_p": 443,
        "proto": "tcp",
        "duration": 0.5,
        "orig_pkts": 5,
        "resp_pkts": 5,
        "orig_bytes": 500,
        "resp_bytes": 500
    }
    ssl_rec = {
        "uid": "test_uid_ooo",
        "server_name": "google.com",
        "ja3": JA3_B,
        "established": True
    }

    # ssl arrives first -> cached
    res1 = correlator.add_ssl_record(ssl_rec)
    assert res1 is None

    # conn arrives second -> merged & emitted
    res2 = correlator.add_conn_record(conn_rec)
    assert res2 is not None
    assert res2["flow_id"] == "test_uid_ooo"
    assert res2["sni"] == "google.com"
    assert res2["ja3_hash"] == JA3_B
    # ja4 was missing in ssl record, must remain None (non-fabrication)
    assert res2["ja4"] is None

def test_zeek_missing_fingerprint_preservation():
    correlator = ZeekCorrelator()
    conn_rec = {
        "uid": "test_missing_fp",
        "id.orig_h": "192.168.1.10",
        "id.orig_p": 49000,
        "id.resp_h": "8.8.8.8",
        "id.resp_p": 443,
        "proto": "tcp",
        "duration": 0.1,
        "orig_pkts": 2,
        "resp_pkts": 0
    }
    ssl_rec = {
        "uid": "test_missing_fp",
        "server_name": "malicious-c2.net",
        "ja3": "-", # Zeek null placeholder
        "ja4": None
    }
    correlator.add_conn_record(conn_rec)
    flow = correlator.add_ssl_record(ssl_rec)
    assert flow is not None
    assert flow["ja3_hash"] is None
    assert flow["ja4"] is None
    assert flow["sni"] == "malicious-c2.net"

def test_zeek_source_file_ingestion():
    source = ZeekEventSource()
    conn_file = FIXTURE_DIR / "zeek_conn_synthetic.json"
    ssl_file = FIXTURE_DIR / "zeek_ssl_synthetic.json"

    assert conn_file.exists()
    assert ssl_file.exists()

    async def _test():
        await source.start()
        # Ingest ssl first, then conn
        await source.ingest_file(ssl_file, log_hint="ssl")
        await source.ingest_file(conn_file, log_hint="conn")
        await source.stop()

    asyncio.run(_test())

    status = source.get_status()
    assert status["total_lines_read"] > 0
    assert status["malformed_lines"] >= 1  # Malformed lines safely caught
    assert status["flows_emitted"] >= 1
    # Three TLS conns merge with their ssl records; the DNS conn is flushed without TLS at stop().
    assert status["flows_emitted"] == 4 and status["correlator"]["orphan_ssl_dropped"] == 0


# ---------------------------------------------------------------- canonical contract (integration) --

def test_zeek_placeholder_fingerprints_are_rejected_not_copied():
    correlator = ZeekCorrelator()
    correlator.add_ssl_record({"uid": "u", "ja3": "abc123ja3hash", "ja4": "t13d1516h2_example", "version": "TLSv13"})
    flow = correlator.add_conn_record(_conn("u"))
    assert flow["ja3_hash"] is None and flow["ja3_rejected_reason"]
    assert flow["ja4"] is None and flow["ja4_rejected_reason"]


def test_zeek_tls_semantics_are_kept_apart_from_etth_features():
    correlator = ZeekCorrelator()
    correlator.add_ssl_record({"uid": "u", "ja4": JA4_A, "version": "TLSv12", "next_protocol": "h2",
                               "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"})
    flow = correlator.add_conn_record(_conn("u"))
    # Negotiated version / selected ALPN never populate the ETTH model features tls_version / alpn_value.
    assert "tls_version" not in flow and "alpn_value" not in flow
    assert flow["tls_version_observed"] == "1.2" and flow["tls_version_semantics"] == "NEGOTIATED"
    assert flow["alpn_negotiated"] == "h2"
    assert flow["ja4_implementation"] == "FOXIO_JA4"
    assert flow["feature_provenance"] == "SENSOR_AGGREGATE" and flow["sensor_type"] == "ZEEK"
    assert flow["sensor_record_id"] == "u"


def test_zeek_serverhello_is_not_defaulted_from_missing_established():
    correlator = ZeekCorrelator()
    correlator.add_ssl_record({"uid": "u", "server_name": "example.org"})   # no version/cipher/ja3s, no established
    flow = correlator.add_conn_record(_conn("u"))
    assert flow["clienthello_present"] is True and flow["serverhello_present"] is False


def test_zeek_byte_semantics_prefer_ip_bytes():
    ip = ZeekCorrelator.build_flow(_conn("a", orig_ip_bytes=1520, resp_ip_bytes=4640))
    assert ip["total_bytes"] == 6160 and ip["byte_count_semantics"] == "IP_LENGTH"
    payload = ZeekCorrelator.build_flow(_conn("b"))
    assert payload["total_bytes"] == 5000 and payload["byte_count_semantics"] == "TRANSPORT_PAYLOAD"


def test_zeek_missing_values_are_not_fabricated():
    flow = ZeekCorrelator.build_flow({"uid": "x", "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2", "proto": "udp",
                                      "orig_pkts": 1, "resp_pkts": 0})
    assert flow["forward_endpoint"] is None and flow["source_port"] is None   # ports unknown: no ':0'
    assert flow["flow_duration"] is None and flow["packets_per_second"] is None
    assert flow["total_bytes"] is None and flow["byte_count_semantics"] == "UNKNOWN"
    assert ZeekCorrelator.build_flow({"uid": "y", "proto": "tcp"}) is None      # no endpoints at all


def test_zeek_zero_duration_gives_no_rate():
    flow = ZeekCorrelator.build_flow(_conn("z", duration=0.0))
    assert flow["flow_duration"] == 0.0 and flow["packets_per_second"] is None and flow["bytes_per_second"] is None


def test_zeek_nested_id_object_is_supported():
    rec = {"uid": "n", "id": {"orig_h": "10.1.1.1", "orig_p": 5000, "resp_h": "10.1.1.2", "resp_p": 443},
           "proto": "tcp", "duration": 1.0, "orig_pkts": 1, "resp_pkts": 1}
    flow = ZeekCorrelator.build_flow(rec)
    assert flow["forward_endpoint"] == "10.1.1.1:5000" and flow["reverse_endpoint"] == "10.1.1.2:443"


def test_zeek_duplicates_and_late_records_are_counted_not_reemitted():
    correlator = ZeekCorrelator()
    correlator.add_ssl_record({"uid": "d", "ja3": JA3_A})
    assert correlator.add_conn_record(_conn("d")) is not None
    assert correlator.add_conn_record(_conn("d")) is None          # duplicate conn
    assert correlator.add_ssl_record({"uid": "d", "ja3": JA3_A}) is None   # late ssl
    assert correlator.stats["duplicate_records"] == 1 and correlator.stats["late_ssl_records"] == 1


def test_zeek_expired_conn_is_emitted_without_tls_not_dropped():
    correlator = ZeekCorrelator(ttl_seconds=60.0)
    assert correlator.add_conn_record(_conn("e")) is None
    correlator._cache["e"]["created_at"] -= 120.0                    # the record is now older than the TTL
    correlator._last_cleanup = 0.0                                   # force the next housekeeping pass
    correlator.add_ssl_record({"uid": "other", "ja3": JA3_A})
    expired = correlator.pop_expired()
    assert [f["flow_id"] for f in expired] == ["e"] and expired[0]["clienthello_present"] is False
    assert correlator.stats["expired_conn_emitted"] == 1


def test_zeek_cache_overflow_emits_conn_and_counts_dropped_ssl():
    correlator = ZeekCorrelator(max_cached=1)
    assert correlator.add_conn_record(_conn("first")) is None
    overflow = correlator.add_conn_record(_conn("second"))
    assert overflow is not None and overflow["flow_id"] == "second"
    assert correlator.add_ssl_record({"uid": "third", "ja3": JA3_A}) is None
    assert correlator.stats["cache_overflow_conn_emitted"] == 1 and correlator.stats["cache_overflow_ssl_dropped"] == 1


def test_zeek_unsupported_protocol_is_skipped_not_relabelled_tcp():
    correlator = ZeekCorrelator()
    assert correlator.add_conn_record(_conn("icmp", proto="icmp")) is None
    assert correlator.flush_pending_conn() == []
    assert correlator.stats["unsupported_protocol_records"] == 1


def test_zeek_unknown_log_types_are_counted():
    source = ZeekEventSource()
    assert source.parse_line('{"_path": "x509", "fingerprint": "abc"}') is None
    assert source.parse_line("[1, 2, 3]") is None
    status = source.get_status()
    assert status["unsupported_records"] == 1 and status["malformed_lines"] == 1
