import asyncio
import logging
import json
import uuid
import datetime
import pandas as pd
from pathlib import Path
from typing import Dict, Any, Optional

from backend.ws_manager import manager
from backend.inference_engine import inference_engine

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent

class ReplayEngine:
    """
    Asynchronous Replay Engine for streaming real ETTH flow events over WebSockets.
    Reads authentic processed features and streams them at configurable speeds.
    """
    def __init__(self):
        self.state = "STOPPED" # STOPPED, RUNNING, PAUSED
        self.speed = 1.0
        self.threats_only = False
        self.current_index = 0
        self.df: Optional[pd.DataFrame] = None
        self.task: Optional[asyncio.Task] = None
        self._load_dataset()

    def _load_dataset(self):
        try:
            parquet_path = BASE_DIR / "data" / "processed" / "features" / "flows_behavioral_features.parquet"
            if not parquet_path.exists():
                parquet_path = BASE_DIR / "data" / "processed" / "v2" / "model_safe" / "model_safe_dataset.parquet"
                
            if parquet_path.exists():
                self.df = pd.read_parquet(parquet_path)
                logger.info(f"ReplayEngine loaded {len(self.df)} flow records from {parquet_path.name}")
            else:
                logger.warning(f"ReplayEngine: Parquet dataset file not found at {parquet_path}")
        except Exception as e:
            logger.error(f"Failed to load dataset for ReplayEngine: {e}")

    async def start(self, speed: float = 1.0, threats_only: bool = False):
        self.speed = max(0.1, min(10.0, speed))
        self.threats_only = threats_only
        
        if self.state == "RUNNING":
            return
            
        self.state = "RUNNING"
        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self._stream_loop())
            
        await manager.broadcast({
            "type": "STREAM_STATE",
            "state": self.state,
            "speed": self.speed,
            "threats_only": self.threats_only
        })

    async def pause(self):
        self.state = "PAUSED"
        await manager.broadcast({
            "type": "STREAM_STATE",
            "state": self.state,
            "speed": self.speed,
            "threats_only": self.threats_only
        })

    async def resume(self):
        if self.state == "PAUSED":
            self.state = "RUNNING"
            if self.task is None or self.task.done():
                self.task = asyncio.create_task(self._stream_loop())
            await manager.broadcast({
                "type": "STREAM_STATE",
                "state": self.state,
                "speed": self.speed,
                "threats_only": self.threats_only
            })

    async def set_speed(self, speed: float):
        self.speed = max(0.1, min(10.0, speed))
        await manager.broadcast({
            "type": "STREAM_STATE",
            "state": self.state,
            "speed": self.speed,
            "threats_only": self.threats_only
        })

    async def stop(self):
        self.state = "STOPPED"
        self.current_index = 0
        if self.task and not self.task.done():
            self.task.cancel()
        await manager.broadcast({
            "type": "STREAM_STATE",
            "state": self.state,
            "speed": self.speed,
            "threats_only": self.threats_only
        })

    async def _stream_loop(self):
        logger.info("ReplayEngine stream loop started.")
        while self.state == "RUNNING":
            if self.df is None or len(self.df) == 0:
                await asyncio.sleep(1.0)
                continue

            # Loop back to start if we reached the end of dataset
            if self.current_index >= len(self.df):
                self.current_index = 0

            row = self.df.iloc[self.current_index].to_dict()
            self.current_index += 1

            label = str(row.get("label", "UNKNOWN")).upper()
            is_malicious = "MALICIOUS" in label

            # Skip benign flows if threats_only is active
            if self.threats_only and not is_malicious:
                await asyncio.sleep(0.01)
                continue

            # Run ML inference
            inference_res = inference_engine.predict(row)

            # Format LiveFlowEvent schema
            event = {
                "event_id": str(uuid.uuid4())[:8],
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "flow_id": str(row.get("flow_id", f"flow-{self.current_index}")),
                "dataset_id": str(row.get("dataset_id", "DS-008")),
                "protocol": "TCP",
                "forward_endpoint": str(row.get("forward_endpoint", "192.168.1.100:443")),
                "reverse_endpoint": str(row.get("reverse_endpoint", "10.0.0.5:52314")),
                "clienthello_present": bool(row.get("clienthello_present", True)),
                "serverhello_present": bool(row.get("serverhello_present", True)),
                "ja3_hash": row.get("ja3_hash") if pd.notnull(row.get("ja3_hash")) else None,
                "ja3s_hash": row.get("ja3s_hash") if pd.notnull(row.get("ja3s_hash")) else None,
                "ja4": row.get("ja4") if pd.notnull(row.get("ja4")) else None,
                "sni_present": bool(row.get("sni_present", False)),
                "alpn_value": row.get("alpn_value") if pd.notnull(row.get("alpn_value")) else None,
                "duration": float(row.get("flow_duration", 0.0)) if pd.notnull(row.get("flow_duration")) else 0.0,
                "total_packets": int(row.get("total_packets", 0)) if pd.notnull(row.get("total_packets")) else 0,
                "total_bytes": int(row.get("total_bytes", 0)) if pd.notnull(row.get("total_bytes")) else 0,
                "packets_per_second": float(row.get("packets_per_second", 0.0)) if pd.notnull(row.get("packets_per_second")) else 0.0,
                "bytes_per_second": float(row.get("bytes_per_second", 0.0)) if pd.notnull(row.get("bytes_per_second")) else 0.0,
                "prediction": inference_res["prediction"],
                "threat_score": inference_res["threat_score"],
                "model_name": inference_res["model_name"],
                "confidence": inference_res["confidence"],
                "label_ground_truth": label
            }

            await manager.broadcast({
                "type": "FLOW_EVENT",
                "data": event
            })

            # Calculate sleep delay based on speed multiplier (base tick 1000ms)
            delay = 1.0 / self.speed
            await asyncio.sleep(delay)

        logger.info("ReplayEngine stream loop exited.")

replay_engine = ReplayEngine()
