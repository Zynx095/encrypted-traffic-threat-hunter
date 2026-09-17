import asyncio
import logging
import uuid
import datetime
import time
import pandas as pd
from pathlib import Path
from typing import Optional, List, Literal, Dict, Any

from backend.ws_manager import manager
from backend.event_sources.live_capture import LiveCaptureSource
from backend.detection_pipeline import detection_pipeline
from backend.repositories import session_repository
from backend.schemas import (
    ETTHStreamEvent,
    StreamTelemetry,
    StreamState,
    ModelTrack,
    StreamLifecycleMetadata
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent

class ReplayEngine:
    """
    Deterministic Asynchronous Stream Engine & State Machine for ETTH.
    Orchestrates PCAP/Dataset REPLAY mode, Real-time LIVE CAPTURE mode,
    and Target/Session monitoring contexts.
    """
    def __init__(self):
        self.mode: Literal["REPLAY", "LIVE"] = "REPLAY"
        self.state: StreamState = "IDLE"
        self.speed: float = 1.0
        self.track: ModelTrack = "A_FLOW"
        self.threats_only: bool = False
        self.loop_replay: bool = True
        
        self.stream_id: str = ""
        self.current_target_id: Optional[str] = None
        self.current_session_id: Optional[str] = None
        self.source: str = "DS-008"
        self.current_index: int = 0
        self.sequence: int = 0
        self.df: Optional[pd.DataFrame] = None
        self.task: Optional[asyncio.Task] = None
        self.live_capture_source: LiveCaptureSource = LiveCaptureSource()
        
        # Operational Telemetry Counters
        self.processed_events: int = 0
        self.flow_events: int = 0
        self.malicious_events: int = 0
        self.benign_events: int = 0
        self.skipped_events: int = 0
        self.error_events: int = 0
        
        # Timing & Throughput tracking
        self.start_time: Optional[float] = None
        self.flow_timestamps: List[float] = []
        self.last_proc_ms: Optional[float] = None
        self.last_inf_ms: Optional[float] = None
        
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

    def _next_sequence(self) -> int:
        self.sequence += 1
        return self.sequence

    def _generate_stream_id(self) -> str:
        timestamp_str = int(datetime.datetime.utcnow().timestamp())
        unique_suffix = str(uuid.uuid4())[:6]
        prefix = "live" if self.mode == "LIVE" else "stream"
        return f"{prefix}_{timestamp_str}_{unique_suffix}"

    def _calculate_events_per_second(self) -> Optional[float]:
        now = time.time()
        # Keep timestamps from the last 5.0 seconds
        self.flow_timestamps = [t for t in self.flow_timestamps if (now - t) <= 5.0]
        if len(self.flow_timestamps) < 2:
            return None
        elapsed = now - self.flow_timestamps[0]
        if elapsed < 0.2:
            return None
        return round(len(self.flow_timestamps) / elapsed, 2)

    def get_telemetry(self) -> StreamTelemetry:
        if self.mode == "LIVE":
            total = self.live_capture_source.packets_observed
            progress = 100.0 if self.state == "PLAYING" else 0.0
        else:
            total = len(self.df) if self.df is not None else 0
            progress = round((self.current_index / total) * 100.0, 2) if total > 0 else 0.0

        elapsed = round(time.time() - self.start_time, 2) if (self.start_time and self.state == "PLAYING") else 0.0

        return StreamTelemetry(
            stream_id=self.stream_id or "stream_none",
            target_id=self.current_target_id,
            session_id=self.current_session_id,
            mode=self.mode,
            source=self.source,
            state=self.state,
            selected_track=self.track,
            playback_speed=self.speed,
            total_events=total,
            processed_events=self.processed_events,
            flow_events=self.flow_events,
            malicious_events=self.malicious_events,
            benign_events=self.benign_events,
            skipped_events=self.skipped_events,
            error_events=self.error_events,
            events_per_second=self._calculate_events_per_second(),
            elapsed_seconds=elapsed,
            progress_percentage=progress,
            connected_clients=manager.get_client_count(),
            processing_duration_ms=self.last_proc_ms,
            inference_duration_ms=self.last_inf_ms
        )

    async def emit_telemetry_event(self):
        telemetry = self.get_telemetry()
        event = ETTHStreamEvent(
            event_id=f"evt_{self.stream_id}_telem_{self.sequence}",
            sequence=self._next_sequence(),
            timestamp=datetime.datetime.utcnow().isoformat() + "Z",
            stream_id=self.stream_id,
            target_id=self.current_target_id,
            session_id=self.current_session_id,
            source=self.source,
            mode=self.mode,
            event_type="stream.telemetry",
            telemetry=telemetry
        )
        await manager.broadcast(event)

    async def start(
        self, 
        speed: float = 1.0, 
        threats_only: bool = False, 
        track: str = "A_FLOW", 
        loop_replay: bool = True,
        target_id: Optional[str] = None,
        session_id: Optional[str] = None
    ):
        # Stop live capture if switching back to replay
        if self.mode == "LIVE":
            await self.live_capture_source.stop()

        self.mode = "REPLAY"

        # Prevent duplicate background tasks if already playing
        if self.state == "PLAYING":
            logger.info("ReplayEngine.start called while PLAYING; updating controls without restarting stream.")
            await self.set_speed(speed)
            await self.set_track(track)
            return

        self.speed = max(0.1, min(100.0, speed))
        self.threats_only = threats_only
        self.track = track if track in ["A_FLOW", "B_JA3", "C_JA4", "D_JA3_FLOW", "E_JA4_FLOW"] else "A_FLOW"
        self.loop_replay = loop_replay
        
        # Target & Session handling
        self.current_target_id = target_id
        if session_id:
            self.current_session_id = session_id
        elif target_id:
            new_sess = session_repository.create({
                "target_id": target_id,
                "source_mode": "REPLAY"
            })
            self.current_session_id = new_sess["session_id"]
        else:
            self.current_session_id = None

        self.state = "PLAYING"
        self.current_index = 0
        self.sequence = 0
        self.processed_events = 0
        self.flow_events = 0
        self.malicious_events = 0
        self.benign_events = 0
        self.skipped_events = 0
        self.error_events = 0
        self.flow_timestamps = []
        self.start_time = time.time()
        self.stream_id = self._generate_stream_id()

        if self.df is not None and not self.df.empty and "dataset_id" in self.df.columns:
            first_ds = str(self.df.iloc[0]["dataset_id"])
            if first_ds and first_ds.lower() != "nan":
                self.source = first_ds

        logger.info(f"State transition -> PLAYING (REPLAY stream_id={self.stream_id} target_id={self.current_target_id} session_id={self.current_session_id})")

        start_event = ETTHStreamEvent(
            event_id=f"evt_{self.stream_id}_start",
            sequence=self._next_sequence(),
            timestamp=datetime.datetime.utcnow().isoformat() + "Z",
            stream_id=self.stream_id,
            target_id=self.current_target_id,
            session_id=self.current_session_id,
            source=self.source,
            mode="REPLAY",
            event_type="stream.started",
            metadata=StreamLifecycleMetadata(
                speed=self.speed,
                threats_only=self.threats_only,
                total_events=len(self.df) if self.df is not None else 0,
                state=self.state
            )
        )
        await manager.broadcast(start_event)
        await self.emit_telemetry_event()

        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self._stream_loop())

    async def start_live(
        self, 
        interface: Optional[str] = None, 
        track: str = "A_FLOW",
        target_id: Optional[str] = None,
        session_id: Optional[str] = None
    ):
        if self.state == "PLAYING" and self.mode == "LIVE":
            logger.info("ReplayEngine.start_live called while PLAYING LIVE; updating track.")
            await self.set_track(track)
            return

        if self.mode == "REPLAY" and self.state == "PLAYING":
            await self.stop()

        self.mode = "LIVE"
        self.track = track if track in ["A_FLOW", "B_JA3", "C_JA4", "D_JA3_FLOW", "E_JA4_FLOW"] else "A_FLOW"
        
        # Target & Session handling
        self.current_target_id = target_id
        if session_id:
            self.current_session_id = session_id
        elif target_id:
            new_sess = session_repository.create({
                "target_id": target_id,
                "source_mode": "LIVE",
                "interface_id": interface
            })
            self.current_session_id = new_sess["session_id"]
        else:
            self.current_session_id = None

        self.state = "PLAYING"
        self.current_index = 0
        self.sequence = 0
        self.processed_events = 0
        self.flow_events = 0
        self.malicious_events = 0
        self.benign_events = 0
        self.skipped_events = 0
        self.error_events = 0
        self.flow_timestamps = []
        self.start_time = time.time()
        self.stream_id = self._generate_stream_id()
        self.source = "LIVE_CAPTURE"

        logger.info(f"State transition -> PLAYING (LIVE stream_id={self.stream_id} target_id={self.current_target_id} session_id={self.current_session_id})")

        start_event = ETTHStreamEvent(
            event_id=f"evt_{self.stream_id}_start",
            sequence=self._next_sequence(),
            timestamp=datetime.datetime.utcnow().isoformat() + "Z",
            stream_id=self.stream_id,
            target_id=self.current_target_id,
            session_id=self.current_session_id,
            source=self.source,
            mode="LIVE",
            event_type="stream.started",
            metadata=StreamLifecycleMetadata(
                speed=1.0,
                threats_only=False,
                total_events=0,
                state=self.state
            )
        )
        await manager.broadcast(start_event)
        await self.emit_telemetry_event()

        async def _on_live_flow(flow_dict: Dict[str, Any]):
            if self.mode != "LIVE" or self.state != "PLAYING":
                return
            self.processed_events += 1
            seq_num = self._next_sequence()
            event = detection_pipeline.process_flow(
                flow=flow_dict,
                track=self.track,
                stream_id=self.stream_id,
                sequence=seq_num,
                mode="LIVE",
                target_id=self.current_target_id,
                session_id=self.current_session_id
            )
            self.flow_events += 1
            self.flow_timestamps.append(time.time())
            
            if hasattr(event, "_proc_duration_ms"):
                self.last_proc_ms = round(getattr(event, "_proc_duration_ms"), 2)
            if hasattr(event, "_inf_duration_ms"):
                self.last_inf_ms = round(getattr(event, "_inf_duration_ms"), 2)

            is_threat = False
            is_skipped = False
            if event.detection:
                if event.detection.status == "SKIPPED":
                    self.skipped_events += 1
                    is_skipped = True
                elif event.detection.status == "ERROR":
                    self.error_events += 1
                elif event.detection.prediction == "MALICIOUS":
                    self.malicious_events += 1
                    is_threat = True
                elif event.detection.prediction == "BENIGN":
                    self.benign_events += 1

            if self.current_session_id:
                session_repository.increment_counters(self.current_session_id, is_threat=is_threat, is_skipped=is_skipped)

            await manager.broadcast(event)
            await self.emit_telemetry_event()

        await self.live_capture_source.start(interface=interface, callback=_on_live_flow)
        if self.live_capture_source.state == "CAPTURE_UNAVAILABLE":
            self.state = "ERROR"
            error_event = ETTHStreamEvent(
                event_id=f"evt_{self.stream_id}_err",
                sequence=self._next_sequence(),
                timestamp=datetime.datetime.utcnow().isoformat() + "Z",
                stream_id=self.stream_id,
                target_id=self.current_target_id,
                session_id=self.current_session_id,
                source=self.source,
                mode="LIVE",
                event_type="stream.error",
                metadata=StreamLifecycleMetadata(
                    state="ERROR",
                    error_message=self.live_capture_source.error_message or "Live capture unavailable."
                )
            )
            await manager.broadcast(error_event)
            await self.emit_telemetry_event()

    async def pause(self):
        if self.mode == "LIVE":
            logger.warning("Pause action is disabled for Live Network Capture.")
            return

        if self.state != "PLAYING":
            logger.warning(f"Invalid state transition attempted: {self.state} -> PAUSED")
            return
            
        self.state = "PAUSED"
        logger.info(f"State transition -> PAUSED (stream_id={self.stream_id})")
        
        pause_event = ETTHStreamEvent(
            event_id=f"evt_{self.stream_id}_pause_{self.sequence}",
            sequence=self._next_sequence(),
            timestamp=datetime.datetime.utcnow().isoformat() + "Z",
            stream_id=self.stream_id,
            source=self.source,
            mode=self.mode,
            event_type="stream.paused",
            metadata=StreamLifecycleMetadata(
                speed=self.speed,
                threats_only=self.threats_only,
                state=self.state
            )
        )
        await manager.broadcast(pause_event)
        await self.emit_telemetry_event()

    async def resume(self):
        if self.mode == "LIVE":
            logger.warning("Resume action is disabled for Live Network Capture.")
            return

        if self.state != "PAUSED":
            logger.warning(f"Invalid state transition attempted: {self.state} -> PLAYING (resume)")
            return
            
        self.state = "PLAYING"
        logger.info(f"State transition -> PLAYING (resumed stream_id={self.stream_id})")
        
        resume_event = ETTHStreamEvent(
            event_id=f"evt_{self.stream_id}_resume_{self.sequence}",
            sequence=self._next_sequence(),
            timestamp=datetime.datetime.utcnow().isoformat() + "Z",
            stream_id=self.stream_id,
            source=self.source,
            mode=self.mode,
            event_type="stream.resumed",
            metadata=StreamLifecycleMetadata(
                speed=self.speed,
                threats_only=self.threats_only,
                state=self.state
            )
        )
        await manager.broadcast(resume_event)
        await self.emit_telemetry_event()
        
        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self._stream_loop())

    async def set_speed(self, speed: float):
        self.speed = max(0.1, min(100.0, speed))
        logger.info(f"Playback speed changed to {self.speed}x")
        await self.emit_telemetry_event()

    async def set_track(self, track: str):
        if track in ["A_FLOW", "B_JA3", "C_JA4", "D_JA3_FLOW", "E_JA4_FLOW"]:
            self.track = track
            logger.info(f"Model track changed to {self.track}")
            await self.emit_telemetry_event()

    async def stop(self):
        if self.state == "STOPPED":
            return

        if self.mode == "LIVE":
            await self.live_capture_source.stop()
            
        self.state = "STOPPED"
        logger.info(f"State transition -> STOPPED (stream_id={self.stream_id})")
        
        stop_event = ETTHStreamEvent(
            event_id=f"evt_{self.stream_id}_stop_{self.sequence}",
            sequence=self._next_sequence(),
            timestamp=datetime.datetime.utcnow().isoformat() + "Z",
            stream_id=self.stream_id,
            source=self.source,
            mode=self.mode,
            event_type="stream.stopped",
            metadata=StreamLifecycleMetadata(
                speed=self.speed,
                threats_only=self.threats_only,
                state=self.state
            )
        )
        await manager.broadcast(stop_event)
        await self.emit_telemetry_event()
        
        if self.task and not self.task.done():
            self.task.cancel()

    async def _stream_loop(self):
        logger.info(f"ReplayEngine stream loop started for stream_id={self.stream_id}")
        while self.state == "PLAYING" and self.mode == "REPLAY":
            if self.df is None or len(self.df) == 0:
                await asyncio.sleep(1.0)
                continue

            if self.current_index >= len(self.df):
                if self.loop_replay:
                    self.current_index = 0
                else:
                    self.state = "COMPLETED"
                    logger.info(f"State transition -> COMPLETED (stream_id={self.stream_id})")
                    complete_event = ETTHStreamEvent(
                        event_id=f"evt_{self.stream_id}_completed",
                        sequence=self._next_sequence(),
                        timestamp=datetime.datetime.utcnow().isoformat() + "Z",
                        stream_id=self.stream_id,
                        source=self.source,
                        mode="REPLAY",
                        event_type="stream.completed",
                        metadata=StreamLifecycleMetadata(
                            speed=self.speed,
                            threats_only=self.threats_only,
                            total_events=len(self.df),
                            state=self.state
                        )
                    )
                    await manager.broadcast(complete_event)
                    await self.emit_telemetry_event()
                    break

            row = self.df.iloc[self.current_index].to_dict()
            self.current_index += 1
            self.processed_events += 1

            label_raw = str(row.get("label", "UNKNOWN")).upper()
            is_malicious = "MALICIOUS" in label_raw

            if self.threats_only and not is_malicious:
                await asyncio.sleep(0.001)
                continue

            seq_num = self._next_sequence()

            # Process flow through DetectionPipeline
            event = detection_pipeline.process_flow(
                flow=row,
                track=self.track,
                stream_id=self.stream_id,
                sequence=seq_num,
                mode="REPLAY",
                target_id=self.current_target_id,
                session_id=self.current_session_id
            )

            # Record telemetry counters cleanly
            self.flow_events += 1
            self.flow_timestamps.append(time.time())
            
            if hasattr(event, "_proc_duration_ms"):
                self.last_proc_ms = round(getattr(event, "_proc_duration_ms"), 2)
            if hasattr(event, "_inf_duration_ms"):
                self.last_inf_ms = round(getattr(event, "_inf_duration_ms"), 2)

            is_threat = False
            is_skipped = False
            if event.detection:
                if event.detection.status == "SKIPPED":
                    self.skipped_events += 1
                    is_skipped = True
                elif event.detection.status == "ERROR":
                    self.error_events += 1
                elif event.detection.prediction == "MALICIOUS":
                    self.malicious_events += 1
                    is_threat = True
                elif event.detection.prediction == "BENIGN":
                    self.benign_events += 1

            if self.current_session_id:
                session_repository.increment_counters(self.current_session_id, is_threat=is_threat, is_skipped=is_skipped)

            await manager.broadcast(event)

            # Periodically emit telemetry update (every 5 flow events)
            if self.flow_events % 5 == 0:
                await self.emit_telemetry_event()

            delay = 1.0 / self.speed
            await asyncio.sleep(delay)

        logger.info(f"ReplayEngine stream loop exited for stream_id={self.stream_id}")

replay_engine = ReplayEngine()

