from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import json
import pandas as pd
from pathlib import Path

app = FastAPI(
    title="Encrypted Traffic Threat Hunter (ETTH) API",
    description="Read-only API server providing access to ETTH research artifacts, experiment results, and model-safe datasets.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent.parent

@app.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "etth-backend"}

@app.get("/api/pilot/summary")
def get_pilot_summary():
    summary_path = BASE_DIR / "data" / "experiments" / "phase7_step5_pilot" / "pilot_summary.json"
    if not summary_path.exists():
        raise HTTPException(status_code=404, detail="Pilot summary not found")
    with open(summary_path, "r", encoding="utf-8") as f:
        return json.load(f)

@app.get("/api/pilot/fold-results")
def get_pilot_fold_results():
    csv_path = BASE_DIR / "data" / "experiments" / "phase7_step5_pilot" / "pilot_fold_results.csv"
    if not csv_path.exists():
        raise HTTPException(status_code=404, detail="Pilot fold results not found")
    df = pd.read_csv(csv_path)
    return json.loads(df.to_json(orient="records"))

@app.get("/api/manifests/phase6-audit")
def get_phase6_audit():
    manifest_path = BASE_DIR / "data" / "manifests" / "phase6_final_audit.json"
    if not manifest_path.exists():
        raise HTTPException(status_code=404, detail="Phase 6 audit manifest not found")
    with open(manifest_path, "r", encoding="utf-8") as f:
        return json.load(f)

@app.get("/api/manifests/experimental")
def get_experimental_manifest():
    manifest_path = BASE_DIR / "data" / "manifests" / "experimental_dataset_manifest.json"
    if not manifest_path.exists():
        raise HTTPException(status_code=404, detail="Experimental dataset manifest not found")
    with open(manifest_path, "r", encoding="utf-8") as f:
        return json.load(f)

@app.get("/api/manifests/statistical-audit")
def get_statistical_audit():
    manifest_path = BASE_DIR / "data" / "manifests" / "phase7_step2_statistical_audit.json"
    if not manifest_path.exists():
        raise HTTPException(status_code=404, detail="Statistical audit manifest not found")
    with open(manifest_path, "r", encoding="utf-8") as f:
        return json.load(f)

@app.get("/api/flows/model-safe")
def get_model_safe_flows(limit: int = 100, offset: int = 0):
    parquet_path = BASE_DIR / "data" / "processed" / "model_safe" / "flows_model_safe.parquet"
    if not parquet_path.exists():
        raise HTTPException(status_code=404, detail="Model-safe flows parquet not found")
    df = pd.read_parquet(parquet_path)
    total = len(df)
    subset = df.iloc[offset : offset + limit]
    flows_list = json.loads(subset.to_json(orient="records"))
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "flows": flows_list
    }

from typing import Optional

@app.get("/api/flows/behavioral")
def get_behavioral_features(
    limit: int = 100, 
    offset: int = 0,
    label: Optional[str] = None,
    dataset: Optional[str] = None,
    ja3: Optional[str] = None,
    ja4: Optional[str] = None
):
    parquet_path = BASE_DIR / "data" / "processed" / "features" / "flows_behavioral_features.parquet"
    if not parquet_path.exists():
        raise HTTPException(status_code=404, detail="Behavioral features parquet not found")
    df = pd.read_parquet(parquet_path)
    
    if label:
        df = df[df["label"] == label]
    if dataset:
        df = df[df["dataset_id"] == dataset]
    if ja3:
        df = df[df["ja3_hash"] == ja3]
    if ja4:
        df = df[df["ja4"] == ja4]
        
    total = len(df)
    subset = df.iloc[offset : offset + limit]
    features_list = json.loads(subset.to_json(orient="records"))
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "features": features_list
    }

@app.get("/api/flows/behavioral/{flow_id}")
def get_behavioral_flow(flow_id: str):
    parquet_path = BASE_DIR / "data" / "processed" / "features" / "flows_behavioral_features.parquet"
    if not parquet_path.exists():
        raise HTTPException(status_code=404, detail="Behavioral features parquet not found")
    df = pd.read_parquet(parquet_path)
    flow = df[df["flow_id"] == flow_id]
    if flow.empty:
        raise HTTPException(status_code=404, detail="Flow not found")
    return json.loads(flow.iloc[0].to_json())

@app.get("/api/fingerprints/stats")
def get_all_fingerprints_stats(fp_type: str = "ja3"):
    if fp_type not in ["ja3", "ja3s", "ja4"]:
        raise HTTPException(status_code=400, detail="Invalid fingerprint type")
    
    parquet_path = BASE_DIR / "data" / "processed" / "features" / "flows_behavioral_features.parquet"
    if not parquet_path.exists():
        raise HTTPException(status_code=404, detail="Features parquet not found")
    df = pd.read_parquet(parquet_path)
    
    col_map = {"ja3": "ja3_hash", "ja3s": "ja3s_hash", "ja4": "ja4"}
    col_name = col_map[fp_type]
    
    valid_fps = df.dropna(subset=[col_name])
    if valid_fps.empty:
        return []
        
    stats = valid_fps.groupby(col_name).agg(
        total_flows=('flow_id', 'count'),
        malicious_flows=('label', lambda x: (x == 'MALICIOUS').sum()),
        benign_flows=('label', lambda x: (x == 'BENIGN').sum()),
    ).reset_index()
    
    stats = stats.rename(columns={col_name: 'hash'})
    stats['type'] = fp_type
    
    stats = stats.sort_values('total_flows', ascending=False)
    
    return json.loads(stats.to_json(orient="records"))

@app.get("/api/fingerprints/{fp_type}/{hash_val}")
def get_fingerprint_stats(fp_type: str, hash_val: str):
    if fp_type not in ["ja3", "ja3s", "ja4"]:
        raise HTTPException(status_code=400, detail="Invalid fingerprint type")
    
    parquet_path = BASE_DIR / "data" / "processed" / "features" / "flows_behavioral_features.parquet"
    if not parquet_path.exists():
        raise HTTPException(status_code=404, detail="Features parquet not found")
    df = pd.read_parquet(parquet_path)
    
    col_map = {"ja3": "ja3_hash", "ja3s": "ja3s_hash", "ja4": "ja4"}
    col_name = col_map[fp_type]
    
    subset = df[df[col_name] == hash_val]
    if subset.empty:
        raise HTTPException(status_code=404, detail="Fingerprint not found")
        
    return {
        "hash": hash_val,
        "type": fp_type,
        "total_flows": len(subset),
        "malicious_flows": int((subset["label"] == "MALICIOUS").sum()),
        "benign_flows": int((subset["label"] == "BENIGN").sum()),
        "datasets": subset["dataset_id"].unique().tolist()
    }

@app.get("/api/live-stream/interfaces")
def get_live_stream_interfaces():
    from backend.event_sources.live_capture import detect_live_capture_capability
    return detect_live_capture_capability()

@app.get("/api/live-stream/status")
def get_live_stream_status():
    return replay_engine.live_capture_source.get_status()

from pydantic import BaseModel

class DNSObservationRequest(BaseModel):
    hostname: str
    resolved_ip: str
    ttl: Optional[int] = 300
    source: Optional[str] = "api"

@app.post("/api/dns/observations", status_code=201)
def add_dns_observation(payload: DNSObservationRequest):
    if not payload.hostname or not payload.resolved_ip:
        raise HTTPException(status_code=400, detail="Hostname and resolved_ip are required.")
    from backend.target_resolver import target_resolver
    target_resolver.dns_cache.add_observation(
        hostname=payload.hostname,
        resolved_ip=payload.resolved_ip,
        ttl=payload.ttl or 300,
        source=payload.source or "api"
    )
    return {"status": "success", "hostname": payload.hostname, "resolved_ip": payload.resolved_ip}

from typing import List, Optional
from backend.repositories import target_repository, session_repository
from backend.schemas import (
    Target,
    CreateTargetRequest,
    UpdateTargetRequest,
    Session,
    CreateSessionRequest
)

@app.get("/api/targets", response_model=List[Target])
def list_targets(include_disabled: bool = False):
    return target_repository.all(include_disabled=include_disabled)

@app.post("/api/targets", response_model=Target, status_code=201)
def create_target(payload: CreateTargetRequest):
    if not payload.hostname or not payload.hostname.strip():
        raise HTTPException(status_code=400, detail="Hostname is required.")
    data = payload.dict()
    if payload.logo:
        data["logo"] = payload.logo.dict()
    try:
        created = target_repository.create(data)
        return created
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

@app.get("/api/targets/{target_id}", response_model=Target)
def get_target(target_id: str):
    tgt = target_repository.get(target_id)
    if not tgt:
        raise HTTPException(status_code=404, detail="Target not found")
    return tgt

@app.patch("/api/targets/{target_id}", response_model=Target)
def update_target(target_id: str, payload: UpdateTargetRequest):
    tgt = target_repository.get(target_id)
    if not tgt:
        raise HTTPException(status_code=404, detail="Target not found")
    data = payload.dict(exclude_unset=True)
    if payload.logo:
        data["logo"] = payload.logo.dict()
    updated = target_repository.update(target_id, data)
    return updated

@app.delete("/api/targets/{target_id}")
def delete_target(target_id: str):
    tgt = target_repository.get(target_id)
    if not tgt:
        raise HTTPException(status_code=404, detail="Target not found")
    success = target_repository.delete(target_id)
    return {"status": "success", "target_id": target_id, "disabled": True}

@app.get("/api/targets/{target_id}/sessions", response_model=List[Session])
def list_target_sessions(target_id: str):
    tgt = target_repository.get(target_id)
    if not tgt:
        raise HTTPException(status_code=404, detail="Target not found")
    return session_repository.get_by_target(target_id)

@app.post("/api/targets/{target_id}/sessions", response_model=Session, status_code=201)
def create_target_session(target_id: str, payload: CreateSessionRequest):
    tgt = target_repository.get(target_id)
    if not tgt:
        raise HTTPException(status_code=404, detail="Target not found")
    data = payload.dict()
    data["target_id"] = target_id
    created = session_repository.create(data)
    return created

@app.get("/api/sessions", response_model=List[Session])
def list_sessions():
    return session_repository.all()

@app.get("/api/sessions/{session_id}", response_model=Session)
def get_session(session_id: str):
    sess = session_repository.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    return sess

@app.post("/api/sessions/{session_id}/stop", response_model=Session)
def stop_session(session_id: str):
    sess = session_repository.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    stopped = session_repository.stop(session_id)
    return stopped

from fastapi import WebSocket, WebSocketDisconnect
from backend.ws_manager import manager
from backend.replay_engine import replay_engine
from backend.schemas import ETTHStreamEvent
import datetime

@app.websocket("/ws/live-stream")
async def websocket_live_stream(websocket: WebSocket):
    await manager.connect(websocket)
    # Send initial telemetry handshake event
    init_event = ETTHStreamEvent(
        event_id=f"evt_init_{id(websocket)}",
        sequence=1,
        timestamp=datetime.datetime.utcnow().isoformat() + "Z",
        stream_id=replay_engine.stream_id or "stream_init",
        target_id=replay_engine.current_target_id,
        session_id=replay_engine.current_session_id,
        source=replay_engine.source,
        mode=replay_engine.mode,
        event_type="stream.telemetry",
        telemetry=replay_engine.get_telemetry()
    )
    await manager.send_event(init_event, websocket)

    try:
        while True:
            data = await websocket.receive_json()
            if not isinstance(data, dict):
                continue
                
            action = data.get("action")
            
            if action == "START_REPLAY":
                speed = float(data.get("speed", 1.0))
                threats_only = bool(data.get("threats_only", False))
                track = str(data.get("track", "A_FLOW"))
                target_id = data.get("target_id")
                session_id = data.get("session_id")
                await replay_engine.start(
                    speed=speed, 
                    threats_only=threats_only, 
                    track=track,
                    target_id=target_id,
                    session_id=session_id
                )
                
            elif action == "START_LIVE":
                iface = data.get("interface") or data.get("interface_id")
                track = str(data.get("track", "A_FLOW"))
                target_id = data.get("target_id")
                session_id = data.get("session_id")
                await replay_engine.start_live(
                    interface=iface, 
                    track=track,
                    target_id=target_id,
                    session_id=session_id
                )

            elif action == "PAUSE_REPLAY":
                await replay_engine.pause()
                
            elif action == "RESUME_REPLAY":
                await replay_engine.resume()
                
            elif action == "SET_SPEED":
                speed = float(data.get("speed", 1.0))
                await replay_engine.set_speed(speed)

            elif action == "SET_TRACK":
                track = str(data.get("track", "A_FLOW"))
                await replay_engine.set_track(track)
                
            elif action in ["STOP_REPLAY", "STOP_LIVE", "STOP_STREAM"]:
                await replay_engine.stop()

            elif action == "SELECT_INTERFACE":
                iface = data.get("interface")
                if iface:
                    replay_engine.live_capture_source.selected_interface = str(iface)
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)




