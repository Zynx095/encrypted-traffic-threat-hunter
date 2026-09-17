import pytest
import asyncio
import time
import hashlib
from typing import Dict, Any

from backend.event_sources.base import EventSource
from backend.event_sources.replay_source import ReplayEventSource
from backend.event_sources.live_capture import (
    LiveCaptureSource,
    LiveFlowTracker,
    detect_live_capture_capability,
    get_available_interfaces
)
from backend.detection_pipeline import detection_pipeline
from backend.replay_engine import ReplayEngine
from backend.schemas import ETTHStreamEvent

def test_1_eventsource_abstraction():
    class TestSource(EventSource):
        async def start(self, **kwargs):
            pass
        async def stop(self):
            pass
        def get_status(self):
            return {"status": "OK", "mode": self.mode}

    source = TestSource(mode="LIVE")
    assert source.mode == "LIVE"
    assert source.get_status()["status"] == "OK"

def test_2_replay_event_source_compatibility():
    source = ReplayEventSource()
    assert source.mode == "REPLAY"
    asyncio.run(source.start())
    assert source.state == "PLAYING"
    flow = source.get_next_flow()
    assert flow is None or isinstance(flow, dict)
    asyncio.run(source.stop())
    assert source.state == "STOPPED"

def test_3_live_capture_capability_detection():
    cap = detect_live_capture_capability()
    assert "available" in cap
    assert "interfaces" in cap
    assert "error" in cap

def test_4_interface_enumeration():
    ifaces = get_available_interfaces()
    assert isinstance(ifaces, list)

def test_5_packet_normalization_and_5_tuple():
    now = time.time()
    key = ("192.168.1.100", 54321, "10.0.0.5", 443, 6)
    tracker = LiveFlowTracker(
        key=key,
        src_ep="192.168.1.100:54321",
        dst_ep="10.0.0.5:443",
        proto="TCP",
        start_time=now
    )
    # Forward packet
    tracker.update(is_forward=True, pkt_len=200, timestamp=now + 0.1)
    # Reverse packet
    tracker.update(is_forward=False, pkt_len=1500, timestamp=now + 0.2)

    assert tracker.forward_packets == 1
    assert tracker.forward_bytes == 200
    assert tracker.reverse_packets == 1
    assert tracker.reverse_bytes == 1500

    flow_dict = tracker.to_flow_dict()
    assert flow_dict["total_packets"] == 2
    assert flow_dict["total_bytes"] == 1700
    assert flow_dict["protocol"] == "TCP"
    assert flow_dict["dataset_id"] == "LIVE_CAPTURE"

def test_6_bidirectional_flow_handling():
    now = time.time()
    key = ("172.16.0.2", 12345, "93.184.216.34", 443, 6)
    tracker = LiveFlowTracker(key=key, src_ep="172.16.0.2:12345", dst_ep="93.184.216.34:443", proto="TCP", start_time=now)
    
    tracker.update(is_forward=True, pkt_len=100, timestamp=now)
    tracker.update(is_forward=False, pkt_len=500, timestamp=now + 0.5)
    tracker.update(is_forward=True, pkt_len=80, timestamp=now + 1.0)
    
    flow_dict = tracker.to_flow_dict()
    assert flow_dict["forward_packets"] == 2
    assert flow_dict["reverse_packets"] == 1
    assert flow_dict["total_bytes"] == 680

def test_7_flow_finalization_on_fin_rst():
    now = time.time()
    key = ("10.0.0.1", 5000, "10.0.0.2", 80, 6)
    tracker = LiveFlowTracker(key=key, src_ep="10.0.0.1:5000", dst_ep="10.0.0.2:80", proto="TCP", start_time=now)
    
    assert not tracker.is_finalized(now=now + 1.0)
    # Receive FIN flag
    tracker.update(is_forward=True, pkt_len=60, timestamp=now + 1.5, fin_or_rst=True)
    assert tracker.is_finalized(now=now + 1.5)

def test_8_idle_timeout_flow_finalization():
    now = time.time()
    key = ("10.0.0.1", 5001, "10.0.0.2", 80, 6)
    tracker = LiveFlowTracker(key=key, src_ep="10.0.0.1:5001", dst_ep="10.0.0.2:80", proto="TCP", start_time=now)
    
    # 5 seconds elapsed -> not finalized
    assert not tracker.is_finalized(now=now + 5.0, idle_timeout=15.0)
    # 16 seconds elapsed without activity -> finalized
    assert tracker.is_finalized(now=now + 16.0, idle_timeout=15.0)

def test_9_max_duration_flow_finalization():
    now = time.time()
    key = ("10.0.0.1", 5002, "10.0.0.2", 80, 6)
    tracker = LiveFlowTracker(key=key, src_ep="10.0.0.1:5002", dst_ep="10.0.0.2:80", proto="TCP", start_time=now)
    
    # Continuously active packets
    tracker.update(is_forward=True, pkt_len=100, timestamp=now + 55.0)
    assert not tracker.is_finalized(now=now + 55.0, max_duration=60.0)
    
    tracker.update(is_forward=True, pkt_len=100, timestamp=now + 61.0)
    assert tracker.is_finalized(now=now + 61.0, max_duration=60.0)

def test_10_missing_tls_metadata_handling():
    now = time.time()
    key = ("10.0.0.1", 5003, "10.0.0.2", 80, 6)
    tracker = LiveFlowTracker(key=key, src_ep="10.0.0.1:5003", dst_ep="10.0.0.2:80", proto="TCP", start_time=now)
    tracker.update(is_forward=True, pkt_len=100, timestamp=now)
    
    flow_dict = tracker.to_flow_dict()
    assert flow_dict["clienthello_present"] is False
    assert flow_dict["serverhello_present"] is False
    assert flow_dict["ja3_hash"] is None
    assert flow_dict["ja3s_hash"] is None
    assert flow_dict["ja4"] is None
    assert flow_dict["sni_present"] is False
    assert flow_dict["alpn_value"] is None

def test_11_observable_tls_handshake_parsing():
    source = LiveCaptureSource()
    # Fake raw ClientHello record (ContentType 0x16, Version 0x0301, HandshakeType 0x01)
    fake_clienthello = b"\x16\x03\x01\x00\x30\x01\x00\x00\x2c\x03\x03" + (b"\x00" * 32)
    meta = source.parse_tls_metadata(fake_clienthello)
    
    assert meta is not None
    assert meta["clienthello_present"] is True
    assert "ja3_hash" in meta
    assert meta["ja3_hash"] is not None
    assert "ja4" in meta

def test_12_privacy_zero_payload_retention():
    now = time.time()
    key = ("10.0.0.1", 5004, "10.0.0.2", 443, 6)
    tracker = LiveFlowTracker(key=key, src_ep="10.0.0.1:5004", dst_ep="10.0.0.2:443", proto="TCP", start_time=now)
    tracker.update(is_forward=True, pkt_len=1024, timestamp=now)
    
    flow_dict = tracker.to_flow_dict()
    forbidden_keys = ["raw_payload", "payload_bytes", "packet_data", "payload", "cookie", "credential", "password"]
    for k in flow_dict.keys():
        assert k not in forbidden_keys

def test_13_live_mode_event_generation():
    flow_dict = {
        "flow_id": "live_test_001",
        "dataset_id": "LIVE_CAPTURE",
        "forward_endpoint": "192.168.1.50:51234",
        "reverse_endpoint": "142.250.190.46:443",
        "protocol": "TCP",
        "flow_duration": 1.5,
        "total_packets": 10,
        "total_bytes": 2400,
        "clienthello_present": True,
        "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
        "label": "UNKNOWN"
    }

    event = detection_pipeline.process_flow(
        flow=flow_dict,
        track="A_FLOW",
        stream_id="live_stream_100",
        sequence=1,
        mode="LIVE"
    )

    assert isinstance(event, ETTHStreamEvent)
    assert event.mode == "LIVE"
    assert event.source == "LIVE_CAPTURE"
    assert event.flow.flow_id == "live_test_001"

def test_14_live_capture_source_lifecycle():
    source = LiveCaptureSource()
    assert source.state == "STOPPED"
    status = source.get_status()
    assert status["mode"] == "LIVE"
    assert status["packets_observed"] == 0

    asyncio.run(source.stop())
    assert source.state == "STOPPED"

def test_15_dual_mode_replay_engine_start_live():
    engine = ReplayEngine()
    asyncio.run(engine.start_live(interface="mock_iface", track="A_FLOW"))
    assert engine.mode == "LIVE"
    assert engine.source == "LIVE_CAPTURE"
    
    asyncio.run(engine.stop())
    assert engine.state == "STOPPED"
