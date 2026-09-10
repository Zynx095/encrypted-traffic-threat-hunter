from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os
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

from fastapi import Query
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
