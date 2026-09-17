import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.repositories import target_repository, session_repository
from backend.schemas import ETTHStreamEvent, StreamTelemetry
from backend.detection_pipeline import detection_pipeline

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_repositories():
    """Ensure repositories start in a clean state for each test."""
    target_repository._targets.clear()
    target_repository._seed_default_targets()
    session_repository._sessions.clear()

def test_1_target_creation():
    response = client.post("/api/targets", json={
        "hostname": "example.com",
        "display_name": "Example Web",
        "target_type": "WEB"
    })
    assert response.status_code == 201
    data = response.json()
    assert data["target_id"].startswith("tgt_")
    assert data["hostname"] == "example.com"
    assert data["display_name"] == "Example Web"
    assert data["enabled"] is True

def test_2_target_validation():
    # Empty hostname should fail
    response = client.post("/api/targets", json={
        "hostname": "   ",
        "display_name": "Invalid"
    })
    assert response.status_code == 400

def test_3_duplicate_target_handling():
    # Pre-seeded youtube exists
    response = client.post("/api/targets", json={
        "hostname": "youtube.com",
        "display_name": "YouTube Duplicate"
    })
    assert response.status_code == 201
    data = response.json()
    assert data["target_id"] == "target_youtube"

def test_4_target_retrieval():
    response = client.get("/api/targets/target_youtube")
    assert response.status_code == 200
    data = response.json()
    assert data["display_name"] == "YouTube"

    response = client.get("/api/targets/non_existent_target")
    assert response.status_code == 404

def test_5_target_update():
    response = client.patch("/api/targets/target_youtube", json={
        "display_name": "YouTube Video Engine"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["display_name"] == "YouTube Video Engine"

def test_6_target_disable_delete_behavior():
    response = client.delete("/api/targets/target_youtube")
    assert response.status_code == 200
    
    # Target should now be soft-deleted (enabled=False)
    get_res = client.get("/api/targets/target_youtube")
    assert get_res.status_code == 200
    assert get_res.json()["enabled"] is False

def test_7_session_creation():
    response = client.post("/api/targets/target_github/sessions", json={
        "source_mode": "REPLAY"
    })
    assert response.status_code == 201
    data = response.json()
    assert data["session_id"].startswith("sess_")
    assert data["target_id"] == "target_github"
    assert data["status"] == "ACTIVE"

def test_8_session_target_relationship():
    sess = session_repository.create({
        "target_id": "target_youtube",
        "source_mode": "LIVE"
    })
    assert sess["target_id"] == "target_youtube"
    
    target_sessions = session_repository.get_by_target("target_youtube")
    assert any(s["session_id"] == sess["session_id"] for s in target_sessions)

def test_9_session_lifecycle():
    sess = session_repository.create({"target_id": "target_youtube"})
    assert sess["status"] == "ACTIVE"
    assert sess["ended_at"] is None

    stopped = session_repository.stop(sess["session_id"])
    assert stopped["status"] == "STOPPED"
    assert stopped["ended_at"] is not None

def test_10_session_retrieval():
    sess = session_repository.create({"target_id": "target_github"})
    response = client.get(f"/api/sessions/{sess['session_id']}")
    assert response.status_code == 200
    assert response.json()["session_id"] == sess["session_id"]

def test_11_target_session_listing():
    session_repository.create({"target_id": "target_github", "source_mode": "REPLAY"})
    session_repository.create({"target_id": "target_github", "source_mode": "LIVE"})

    response = client.get("/api/targets/target_github/sessions")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 2

def test_12_session_stop():
    sess = session_repository.create({"target_id": "target_github"})
    response = client.post(f"/api/sessions/{sess['session_id']}/stop")
    assert response.status_code == 200
    assert response.json()["status"] == "STOPPED"

def test_13_event_target_session_association():
    flow = {"flow_duration": 1.2, "total_packets": 10, "total_bytes": 1000}
    event = detection_pipeline.process_flow(
        flow=flow,
        track="A_FLOW",
        stream_id="stream_test",
        sequence=1,
        mode="REPLAY",
        target_id="target_youtube",
        session_id="sess_12345"
    )
    assert event.target_id == "target_youtube"
    assert event.session_id == "sess_12345"

def test_14_missing_target_session_backward_compatibility():
    flow = {"flow_duration": 1.2, "total_packets": 10, "total_bytes": 1000}
    event = detection_pipeline.process_flow(
        flow=flow,
        track="A_FLOW",
        stream_id="stream_test",
        sequence=1,
        mode="REPLAY"
    )
    assert event.target_id is None
    assert event.session_id is None

def test_15_live_stream_target_session_integration():
    from backend.replay_engine import ReplayEngine
    engine = ReplayEngine()
    
    # Starting engine with target_id auto-creates session_id if omitted
    import asyncio
    asyncio.run(engine.start(target_id="target_youtube", loop_replay=False))
    assert engine.current_target_id == "target_youtube"
    assert engine.current_session_id is not None
    assert engine.current_session_id.startswith("sess_")
    asyncio.run(engine.stop())

def test_16_replay_compatibility():
    from backend.replay_engine import ReplayEngine
    engine = ReplayEngine()
    import asyncio
    asyncio.run(engine.start(speed=50.0, loop_replay=False))
    assert engine.current_target_id is None
    assert engine.current_session_id is None
    asyncio.run(engine.stop())

def test_17_multiple_sessions_isolated():
    s1 = session_repository.create({"target_id": "target_youtube"})
    s2 = session_repository.create({"target_id": "target_github"})

    session_repository.increment_counters(s1["session_id"], is_threat=True)
    session_repository.increment_counters(s2["session_id"], is_threat=False)

    s1_fresh = session_repository.get(s1["session_id"])
    s2_fresh = session_repository.get(s2["session_id"])

    assert s1_fresh["threat_count"] == 1
    assert s1_fresh["approved_flow_count"] == 0
    assert s2_fresh["threat_count"] == 0
    assert s2_fresh["approved_flow_count"] == 1

def test_18_multiple_websocket_clients_observing_same_session():
    with client.websocket_connect("/ws/live-stream") as ws1:
        with client.websocket_connect("/ws/live-stream") as ws2:
            data1 = ws1.receive_json()
            data2 = ws2.receive_json()
            assert data1["event_type"] == "stream.telemetry"
            assert data2["event_type"] == "stream.telemetry"

def test_19_no_orphan_sessions():
    sess = session_repository.create({"target_id": "target_youtube"})
    # Soft deleting target preserves target entity and session reference
    target_repository.delete("target_youtube")
    
    tgt = target_repository.get("target_youtube")
    assert tgt is not None
    assert tgt["enabled"] is False
    
    sess_retrieved = session_repository.get(sess["session_id"])
    assert sess_retrieved["target_id"] == "target_youtube"

def test_20_persistence_repository_behavior():
    all_targets = target_repository.all(include_disabled=True)
    assert len(all_targets) >= 2
    
    all_sessions = session_repository.all()
    assert isinstance(all_sessions, list)
