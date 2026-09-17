import threading
import datetime
import uuid
import logging
from typing import Dict, Any, List, Optional
from backend.repositories.base import BaseRepository

logger = logging.getLogger(__name__)

class SessionRepository(BaseRepository):
    """
    In-Memory & Lightweight File Repository for Monitoring Sessions.
    Links historical monitoring sessions to targets without mixing event sequences.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._sessions: Dict[str, Dict[str, Any]] = {}

    def all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._sessions.values())

    def get(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._sessions.get(session_id)

    def get_by_target(self, target_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            return [s for s in self._sessions.values() if s.get("target_id") == target_id]

    def create(self, data: Dict[str, Any]) -> Dict[str, Any]:
        target_id = data.get("target_id")
        source_mode = data.get("source_mode", "REPLAY")
        interface_id = data.get("interface_id")
        
        session_id = data.get("session_id") or f"sess_{int(datetime.datetime.utcnow().timestamp())}_{uuid.uuid4().hex[:6]}"
        now = datetime.datetime.utcnow().isoformat() + "Z"

        session = {
            "session_id": session_id,
            "target_id": target_id,
            "status": "ACTIVE",
            "started_at": now,
            "ended_at": None,
            "source_mode": source_mode,
            "interface_id": interface_id,
            "flow_count": 0,
            "threat_count": 0,
            "approved_flow_count": 0,
            "skipped_flow_count": 0,
            "metadata": data.get("metadata", {})
        }

        with self._lock:
            self._sessions[session_id] = session
        logger.info(f"SessionRepository created session_id={session_id} target_id={target_id} mode={source_mode}")
        return session

    def update(self, session_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            for key in ["status", "ended_at", "flow_count", "threat_count", "approved_flow_count", "skipped_flow_count", "metadata"]:
                if key in data and data[key] is not None:
                    session[key] = data[key]
            return session

    def increment_counters(self, session_id: str, is_threat: bool = False, is_skipped: bool = False):
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return
            session["flow_count"] += 1
            if is_skipped:
                session["skipped_flow_count"] += 1
            elif is_threat:
                session["threat_count"] += 1
            else:
                session["approved_flow_count"] += 1

    def stop(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            session["status"] = "STOPPED"
            session["ended_at"] = datetime.datetime.utcnow().isoformat() + "Z"
            logger.info(f"SessionRepository stopped session_id={session_id}")
            return session

    def delete(self, session_id: str) -> bool:
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False

session_repository = SessionRepository()
