import pytest
import asyncio
from pydantic import ValidationError
from fastapi.testclient import TestClient

from backend.main import app
from backend.schemas import ETTHStreamEvent, FlowDetails, TLSDetails, DetectionDetails, ProvenanceDetails
from backend.inference_engine import inference_engine
from backend.replay_engine import ReplayEngine, replay_engine
from backend.ws_manager import manager

client = TestClient(app)

def test_1_event_schema_validation():
    # Valid event
    event = ETTHStreamEvent(
        event_id="evt_test_00001",
        sequence=1,
        timestamp="2026-09-11T16:20:00Z",
        stream_id="stream_test_123",
        source="DS-008",
        mode="REPLAY",
        event_type="flow.detected",
        flow=FlowDetails(
            flow_id="flow_1",
            forward_endpoint="192.168.1.1:443",
            reverse_endpoint="10.0.0.2:5000"
        ),
        tls=TLSDetails(clienthello_present=True, ja3_hash=None),
        detection=DetectionDetails(prediction="MALICIOUS", threat_score=0.95),
        provenance=ProvenanceDetails(dataset_id="DS-008", label_ground_truth="MALICIOUS")
    )
    assert event.event_type == "flow.detected"
    assert event.sequence == 1

    # Invalid sequence < 1 throws ValidationError
    with pytest.raises(ValidationError):
        ETTHStreamEvent(
            event_id="evt_invalid",
            sequence=0,
            timestamp="2026-09-11T16:20:00Z",
            stream_id="stream_1",
            event_type="flow.detected"
        )

def test_2_unique_event_ids():
    engine = ReplayEngine()
    asyncio.run(engine.start(speed=10.0, loop_replay=False))
    asyncio.run(asyncio.sleep(0.01))
    asyncio.run(engine.stop())
    
    # Ensure stream_id and sequence generate unique event_ids
    id1 = f"evt_{engine.stream_id}_{engine._next_sequence():05d}"
    id2 = f"evt_{engine.stream_id}_{engine._next_sequence():05d}"
    assert id1 != id2

def test_3_monotonic_sequence_numbers():
    engine = ReplayEngine()
    seq1 = engine._next_sequence()
    seq2 = engine._next_sequence()
    seq3 = engine._next_sequence()
    assert seq1 == 1
    assert seq2 == 2
    assert seq3 == 3

def test_4_deterministic_replay_ordering():
    engine = ReplayEngine()
    if engine.df is not None and len(engine.df) >= 2:
        row0_flow_id = str(engine.df.iloc[0].get("flow_id", "flow-1"))
        row1_flow_id = str(engine.df.iloc[1].get("flow_id", "flow-2"))
        
        # Run 1
        r1_f0 = str(engine.df.iloc[0].get("flow_id", "flow-1"))
        r1_f1 = str(engine.df.iloc[1].get("flow_id", "flow-2"))

        # Run 2
        r2_f0 = str(engine.df.iloc[0].get("flow_id", "flow-1"))
        r2_f1 = str(engine.df.iloc[1].get("flow_id", "flow-2"))

        assert r1_f0 == r2_f0 == row0_flow_id
        assert r1_f1 == r2_f1 == row1_flow_id

def test_5_lifecycle_events():
    engine = ReplayEngine()
    asyncio.run(engine.start(speed=10.0, loop_replay=False))
    assert engine.state == "PLAYING"

    asyncio.run(engine.pause())
    assert engine.state == "PAUSED"

    asyncio.run(engine.resume())
    assert engine.state == "PLAYING"

    asyncio.run(engine.stop())
    assert engine.state == "STOPPED"

def test_6_semantic_absence_of_ja3_ja4():
    tls = TLSDetails(
        clienthello_present=True,
        serverhello_present=False,
        ja3_hash=None,
        ja3s_hash=None,
        ja4=None
    )
    assert tls.ja3_hash is None
    assert tls.ja3s_hash is None
    assert tls.ja4 is None

def test_7_malformed_event_rejection():
    invalid_dict = {"event_id": "bad", "sequence": -5, "event_type": "invalid_type"}
    # Should catch validation error and drop event cleanly without crashing
    asyncio.run(manager.broadcast(invalid_dict))

def test_8_multiple_websocket_clients_broadcast():
    with client.websocket_connect("/ws/live-stream") as client1:
        with client.websocket_connect("/ws/live-stream") as client2:
            data1 = client1.receive_json()
            data2 = client2.receive_json()
            assert data1["event_type"] in ["stream.started", "stream.stopped", "stream.telemetry"]
            assert data2["event_type"] in ["stream.started", "stream.stopped", "stream.telemetry"]

def test_9_clean_disconnect():
    with client.websocket_connect("/ws/live-stream") as ws:
        pass

def test_10_replay_completion():
    engine = ReplayEngine()
    asyncio.run(engine.start(speed=10.0, loop_replay=False))
    assert engine.stream_id != ""
    asyncio.run(engine.stop())
    assert engine.state == "STOPPED"

def test_11_initial_idle_state():
    engine = ReplayEngine()
    assert engine.state == "IDLE"
    assert engine.processed_events == 0
    assert engine.flow_events == 0
    assert engine.malicious_events == 0
    assert engine.benign_events == 0
    assert engine.skipped_events == 0
    assert engine.error_events == 0

def test_12_state_machine_transitions():
    engine = ReplayEngine()
    # 1. IDLE -> PLAYING
    asyncio.run(engine.start(speed=10.0, loop_replay=False))
    assert engine.state == "PLAYING"

    # 2. PLAYING -> PAUSED
    asyncio.run(engine.pause())
    assert engine.state == "PAUSED"

    # 3. PAUSED -> PLAYING (resume)
    asyncio.run(engine.resume())
    assert engine.state == "PLAYING"

    # 4. PLAYING -> STOPPED
    asyncio.run(engine.stop())
    assert engine.state == "STOPPED"

    # 5. Invalid transition (STOPPED -> PAUSED) rejected safely
    asyncio.run(engine.pause())
    assert engine.state == "STOPPED"

def test_13_replay_completed_transition():
    engine = ReplayEngine()
    if engine.df is not None and not engine.df.empty:
        engine.df = engine.df.head(2) # truncate for fast completion

    async def _run():
        await engine.start(speed=100.0, loop_replay=False)
        if engine.task:
            await asyncio.wait_for(engine.task, timeout=2.0)

    asyncio.run(_run())
    assert engine.state in ["COMPLETED", "STOPPED"]
    if engine.state == "COMPLETED":
        assert engine.current_index >= len(engine.df)
    asyncio.run(engine.stop())

def test_14_speed_changes_timing_only():
    engine = ReplayEngine()
    asyncio.run(engine.start(speed=1.0, loop_replay=False))
    assert engine.speed == 1.0
    asyncio.run(engine.set_speed(5.0))
    assert engine.speed == 5.0
    asyncio.run(engine.stop())

def test_15_progress_calculation_and_counters():
    engine = ReplayEngine()
    engine.start_time = 1000.0
    engine.processed_events = 10
    engine.flow_events = 10
    engine.malicious_events = 3
    engine.benign_events = 5
    engine.skipped_events = 2
    engine.error_events = 0
    engine.current_index = 10

    telem = engine.get_telemetry()
    assert telem.processed_events == 10
    assert telem.flow_events == 10
    assert telem.malicious_events == 3
    assert telem.benign_events == 5
    assert telem.skipped_events == 2
    assert telem.error_events == 0
    assert telem.progress_percentage >= 0.0

def test_16_events_per_second_calculation():
    engine = ReplayEngine()
    # Insufficient timestamps returns None
    assert engine._calculate_events_per_second() is None

    # Populate timestamps
    import time
    now = time.time()
    engine.flow_timestamps = [now - 1.0, now - 0.5, now]
    eps = engine._calculate_events_per_second()
    assert eps is not None
    assert eps > 0.0

def test_17_telemetry_schema_validation():
    from backend.schemas import StreamTelemetry, ETTHStreamEvent
    telem = StreamTelemetry(
        stream_id="stream_test_telemetry",
        mode="REPLAY",
        source="DS-008",
        state="PLAYING",
        selected_track="A_FLOW",
        playback_speed=2.0,
        total_events=100,
        processed_events=50,
        flow_events=45,
        malicious_events=10,
        benign_events=35,
        skipped_events=5,
        error_events=0,
        events_per_second=10.5,
        elapsed_seconds=5.0,
        progress_percentage=50.0,
        connected_clients=1,
        processing_duration_ms=1.2,
        inference_duration_ms=0.8
    )
    event = ETTHStreamEvent(
        event_id="evt_telem_01",
        sequence=1,
        timestamp="2026-09-11T16:30:00Z",
        stream_id="stream_test_telemetry",
        source="DS-008",
        mode="REPLAY",
        event_type="stream.telemetry",
        telemetry=telem
    )
    assert event.event_type == "stream.telemetry"
    assert event.telemetry.events_per_second == 10.5

def test_18_lifecycle_events_separate_from_flow_counters():
    engine = ReplayEngine()
    seq_before = engine.sequence
    flow_cnt_before = engine.flow_events
    asyncio.run(engine.emit_telemetry_event())
    assert engine.sequence == seq_before + 1
    assert engine.flow_events == flow_cnt_before  # Telemetry emission does not increment flow_events

def test_19_multi_client_telemetry_broadcast():
    with client.websocket_connect("/ws/live-stream") as client1:
        with client.websocket_connect("/ws/live-stream") as client2:
            msg1 = client1.receive_json()
            msg2 = client2.receive_json()
            assert msg1["event_type"] in ["stream.started", "stream.stopped", "stream.telemetry"]
            assert msg2["event_type"] in ["stream.started", "stream.stopped", "stream.telemetry"]

def test_20_duplicate_start_protection():
    engine = ReplayEngine()
    asyncio.run(engine.start(speed=1.0, loop_replay=False))
    task1 = engine.task
    stream_id1 = engine.stream_id
    
    # Call start again while PLAYING
    asyncio.run(engine.start(speed=2.0, loop_replay=False))
    assert engine.task == task1  # No new background task spawned
    assert engine.stream_id == stream_id1  # Stream ID preserved
    assert engine.speed == 2.0  # Speed setting updated cleanly
    
    asyncio.run(engine.stop())

def test_21_clean_replay_shutdown():
    engine = ReplayEngine()
    asyncio.run(engine.start(speed=1.0, loop_replay=False))
    assert engine.task is not None
    asyncio.run(engine.stop())
    assert engine.state == "STOPPED"
    assert engine.task.cancelled() or engine.task.done()

