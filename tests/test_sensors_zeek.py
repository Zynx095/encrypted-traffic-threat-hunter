import pytest
import asyncio
from pathlib import Path

from backend.event_sources.zeek_source import ZeekEventSource, ZeekCorrelator

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "data" / "fixtures" / "sensors"

def test_zeek_correlator_conn_then_ssl():
    correlator = ZeekCorrelator()
    conn_rec = {
        "uid": "test_uid_1",
        "id.orig_h": "192.168.1.5",
        "id.orig_p": 44100,
        "id.resp_h": "1.2.3.4",
        "id.resp_p": 443,
        "proto": "tcp",
        "duration": 1.5,
        "orig_pkts": 10,
        "resp_pkts": 12,
        "orig_bytes": 1000,
        "resp_bytes": 4000,
        "conn_state": "SF"
    }
    ssl_rec = {
        "uid": "test_uid_1",
        "server_name": "example.com",
        "version": "TLSv13",
        "ja3": "abc123ja3hash",
        "ja4": "t13d1516h2_example",
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
    assert res2["ja3_hash"] == "abc123ja3hash"
    assert res2["ja4"] == "t13d1516h2_example"
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
        "ja3": "googleja3",
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
    assert res2["ja3_hash"] == "googleja3"
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
