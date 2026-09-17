import threading
import datetime
import uuid
import logging
from typing import Dict, Any, List, Optional
from backend.repositories.base import BaseRepository

logger = logging.getLogger(__name__)

class TargetRepository(BaseRepository):
    """
    In-Memory & Lightweight File Repository for Target Entities.
    Pre-seeds default monitored targets and enforces soft-deletion data integrity.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._targets: Dict[str, Dict[str, Any]] = {}
        self._seed_default_targets()

    def _seed_default_targets(self):
        defaults = [
            {
                "target_id": "target_youtube",
                "name": "youtube",
                "hostname": "youtube.com",
                "display_name": "YouTube",
                "target_type": "WEB",
                "logo": {
                    "type": "favicon",
                    "reference": "https://www.youtube.com/favicon.ico"
                },
                "aliases": ["www.youtube.com", "m.youtube.com", "googlevideo.com"],
                "enabled": True,
                "created_at": datetime.datetime.utcnow().isoformat() + "Z",
                "metadata": {"category": "Streaming Video"}
            },
            {
                "target_id": "target_github",
                "name": "github",
                "hostname": "github.com",
                "display_name": "GitHub",
                "target_type": "WEB",
                "logo": {
                    "type": "favicon",
                    "reference": "https://github.githubassets.com/favicons/favicon.png"
                },
                "aliases": ["www.github.com", "api.github.com", "raw.githubusercontent.com"],
                "enabled": True,
                "created_at": datetime.datetime.utcnow().isoformat() + "Z",
                "metadata": {"category": "Code Repository"}
            }
        ]
        for t in defaults:
            self._targets[t["target_id"]] = t

    def all(self, include_disabled: bool = False) -> List[Dict[str, Any]]:
        with self._lock:
            if include_disabled:
                return list(self._targets.values())
            return [t for t in self._targets.values() if t.get("enabled", True)]

    def get(self, target_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._targets.get(target_id)

    def get_by_hostname(self, hostname: str) -> Optional[Dict[str, Any]]:
        clean_host = hostname.strip().lower()
        with self._lock:
            for t in self._targets.values():
                if t.get("hostname", "").strip().lower() == clean_host:
                    return t
                if clean_host in [a.strip().lower() for a in t.get("aliases", [])]:
                    return t
        return None

    def create(self, data: Dict[str, Any]) -> Dict[str, Any]:
        hostname = str(data.get("hostname", "")).strip().lower()
        if not hostname:
            raise ValueError("Target hostname is required.")

        existing = self.get_by_hostname(hostname)
        if existing:
            # Re-enable if previously disabled
            if not existing.get("enabled"):
                existing["enabled"] = True
                return existing
            return existing

        display_name = data.get("display_name") or hostname.split(".")[0].capitalize()
        target_type = data.get("target_type", "WEB")
        target_id = data.get("target_id") or f"tgt_{uuid.uuid4().hex[:8]}"

        target = {
            "target_id": target_id,
            "name": hostname.split(".")[0].lower(),
            "hostname": hostname,
            "display_name": display_name,
            "target_type": target_type,
            "logo": data.get("logo", {"type": "default", "reference": ""}),
            "aliases": data.get("aliases", []),
            "enabled": True,
            "created_at": datetime.datetime.utcnow().isoformat() + "Z",
            "metadata": data.get("metadata", {})
        }

        with self._lock:
            self._targets[target_id] = target
        logger.info(f"TargetRepository created target_id={target_id} hostname={hostname}")
        return target

    def update(self, target_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self._lock:
            target = self._targets.get(target_id)
            if not target:
                return None
            for key in ["display_name", "target_type", "logo", "aliases", "enabled", "metadata"]:
                if key in data and data[key] is not None:
                    target[key] = data[key]
            return target

    def delete(self, target_id: str) -> bool:
        """
        Soft deletes target by setting enabled=False.
        Preserves historical session integrity.
        """
        with self._lock:
            target = self._targets.get(target_id)
            if not target:
                return False
            target["enabled"] = False
            logger.info(f"TargetRepository soft-deleted target_id={target_id}")
            return True

target_repository = TargetRepository()
