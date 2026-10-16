"""
ETTH Suricata Sensor Ingestion Adapter (Phase 11)
Parses, correlates, and normalizes Suricata EVE JSON events (flow, tls, alert)
into canonical ETTH flow dictionaries for real-time zero-decryption threat detection.

Enforces:
1. ZERO payload decryption or packet payload retention.
2. ZERO fingerprint fabrication (missing JA3/JA4 remains None).
3. Stateful flow_id correlation across multi-event streams.
4. Bounded memory and out-of-order tolerance.
"""

import json
import time
import logging
import asyncio
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

from backend.event_sources.base import EventSource

logger = logging.getLogger(__name__)


class SuricataCorrelator:
    """
    Correlates Suricata EVE events sharing the same flow_id (flow, tls, alert).
    Suricata emits separate events for flow lifecycle, TLS handshakes, and signatures.
    """
    def __init__(self, max_cached: int = 50000, ttl_seconds: float = 60.0):
        self.max_cached = max_cached
        self.ttl_seconds = ttl_seconds
        # Maps flow_id -> {"flow": {...}, "tls": {...}, "alerts": [...], "created_at": float}
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._last_cleanup = time.time()

    def _cleanup_stale(self, now: float):
        if now - self._last_cleanup < 10.0:
            return
        self._last_cleanup = now
        stale_ids = [
            fid for fid, item in self._cache.items()
            if (now - item["created_at"]) > self.ttl_seconds
        ]
        for fid in stale_ids:
            del self._cache[fid]

    def add_eve_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Ingests a single EVE event. If the event represents a finalized flow (event_type == 'flow'),
        or if all expected data is merged, normalizes and emits an ETTH flow dict.
        """
        now = time.time()
        self._cleanup_stale(now)

        event_type = str(event.get("event_type", "")).lower()
        flow_id = str(event.get("flow_id", ""))

        if not flow_id:
            # Standalone event without flow_id
            if event_type == "flow":
                return self.build_flow(flow_event=event, tls_event=None, alerts=[])
            return None

        if flow_id not in self._cache:
            if len(self._cache) >= self.max_cached:
                self._evict_oldest()
            self._cache[flow_id] = {
                "created_at": now,
                "flow": None,
                "tls": None,
                "alerts": []
            }

        cache_entry = self._cache[flow_id]

        if event_type == "tls":
            cache_entry["tls"] = event
            # If flow was already captured, emit updated flow
            if cache_entry["flow"]:
                return self.build_flow(
                    flow_event=cache_entry["flow"],
                    tls_event=cache_entry["tls"],
                    alerts=cache_entry["alerts"]
                )

        elif event_type == "alert":
            cache_entry["alerts"].append(event)
            # If flow was already captured, emit updated flow
            if cache_entry["flow"]:
                return self.build_flow(
                    flow_event=cache_entry["flow"],
                    tls_event=cache_entry["tls"],
                    alerts=cache_entry["alerts"]
                )

        elif event_type == "flow":
            cache_entry["flow"] = event
            # Flow event signifies flow finalization in Suricata!
            res = self.build_flow(
                flow_event=cache_entry["flow"],
                tls_event=cache_entry["tls"],
                alerts=cache_entry["alerts"]
            )
            # Evict finalized flow from active cache
            del self._cache[flow_id]
            return res

        return None

    def _evict_oldest(self):
        if not self._cache:
            return
        oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k]["created_at"])
        del self._cache[oldest_key]

    def flush_pending(self) -> List[Dict[str, Any]]:
        """
        Flushes any unfinalized cached flows.
        """
        flushed = []
        for flow_id, entry in list(self._cache.items()):
            if entry.get("flow"):
                f = self.build_flow(
                    flow_event=entry["flow"],
                    tls_event=entry["tls"],
                    alerts=entry["alerts"]
                )
                if f:
                    flushed.append(f)
        self._cache.clear()
        return flushed

    @staticmethod
    def build_flow(
        flow_event: Dict[str, Any],
        tls_event: Optional[Dict[str, Any]] = None,
        alerts: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Normalizes merged Suricata EVE data into a canonical ETTH flow dictionary.
        """
        try:
            src_ip = str(flow_event.get("src_ip", "0.0.0.0"))
            src_port = int(flow_event.get("src_port", 0))
            dest_ip = str(flow_event.get("dest_ip", "0.0.0.0"))
            dest_port = int(flow_event.get("dest_port", 0))
            proto_raw = str(flow_event.get("proto", "TCP")).upper()
            protocol = "TCP" if proto_raw == "TCP" else ("UDP" if proto_raw == "UDP" else "TCP")

            flow_sub = flow_event.get("flow", {})
            pkts_toserver = int(flow_sub.get("pkts_toserver") or flow_event.get("pkts_toserver") or 0)
            pkts_toclient = int(flow_sub.get("pkts_toclient") or flow_event.get("pkts_toclient") or 0)
            bytes_toserver = int(flow_sub.get("bytes_toserver") or flow_event.get("bytes_toserver") or 0)
            bytes_toclient = int(flow_sub.get("bytes_toclient") or flow_event.get("bytes_toclient") or 0)

            total_packets = pkts_toserver + pkts_toclient
            total_bytes = bytes_toserver + bytes_toclient

            age = float(flow_sub.get("age") or 0.0)
            pps = (total_packets / age) if age > 0 else float(total_packets)
            bps = (total_bytes / age) if age > 0 else float(total_bytes)

            asym_pkts = (pkts_toserver / max(1, pkts_toclient)) if pkts_toclient > 0 else float(pkts_toserver)
            asym_bytes = (bytes_toserver / max(1, bytes_toclient)) if bytes_toclient > 0 else float(bytes_toserver)

            fid = str(flow_event.get("flow_id") or f"suricata_{src_ip}_{src_port}_{dest_ip}_{dest_port}")

            flow_dict: Dict[str, Any] = {
                "flow_id": fid,
                "dataset_id": "SURICATA_SENSOR",
                "protocol": protocol,
                "forward_endpoint": f"{src_ip}:{src_port}",
                "reverse_endpoint": f"{dest_ip}:{dest_port}",
                "source_ip": src_ip,
                "source_port": src_port,
                "destination_ip": dest_ip,
                "destination_port": dest_port,
                "flow_duration": age,
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "forward_packets": pkts_toserver,
                "reverse_packets": pkts_toclient,
                "forward_bytes": bytes_toserver,
                "reverse_bytes": bytes_toclient,
                "packets_per_second": pps,
                "bytes_per_second": bps,
                "asymmetry_ratio_packets": asym_pkts,
                "asymmetry_ratio_bytes": asym_bytes,
                "sensor_type": "SURICATA",
                "sensor_flow_state": str(flow_sub.get("state", "UNKNOWN")),
                "sensor_alerts": [a.get("alert", {}).get("signature", "Unknown Alert") for a in (alerts or [])],
                # TLS Structural defaults
                "clienthello_present": False,
                "serverhello_present": False,
                "sni": None,
                "sni_present": False,
                "ja3_hash": None,
                "ja3s_hash": None,
                "ja4": None,
                "alpn_value": None,
                "tls_version": None,
            }

            # Enrich from tls_event if present
            if tls_event:
                tls_data = tls_event.get("tls", {})
                flow_dict["clienthello_present"] = True
                flow_dict["serverhello_present"] = True
                flow_dict["tls_version"] = tls_data.get("version")

                sni = tls_data.get("sni")
                if sni and str(sni).strip() not in ["", "-", "None"]:
                    flow_dict["sni"] = str(sni).strip().lower()
                    flow_dict["sni_present"] = True

                # JA3 fingerprint extraction
                ja3_obj = tls_data.get("ja3")
                ja3_val = None
                if isinstance(ja3_obj, dict):
                    ja3_val = ja3_obj.get("hash") or ja3_obj.get("string")
                elif isinstance(ja3_obj, str):
                    ja3_val = ja3_obj
                if ja3_val and str(ja3_val).strip() not in ["", "-", "None"]:
                    flow_dict["ja3_hash"] = str(ja3_val).strip()

                # JA3S fingerprint extraction
                ja3s_obj = tls_data.get("ja3s")
                ja3s_val = None
                if isinstance(ja3s_obj, dict):
                    ja3s_val = ja3s_obj.get("hash")
                elif isinstance(ja3s_obj, str):
                    ja3s_val = ja3s_obj
                if ja3s_val and str(ja3s_val).strip() not in ["", "-", "None"]:
                    flow_dict["ja3s_hash"] = str(ja3s_val).strip()

                # JA4 fingerprint extraction
                ja4_val = tls_data.get("ja4")
                if ja4_val and str(ja4_val).strip() not in ["", "-", "None"]:
                    flow_dict["ja4"] = str(ja4_val).strip()

                # ALPN
                alpn_val = tls_data.get("alpn")
                if alpn_val and str(alpn_val).strip() not in ["", "-", "None"]:
                    flow_dict["alpn_value"] = str(alpn_val).strip()

            return flow_dict
        except Exception as e:
            logger.warning(f"Error normalizing Suricata EVE record: {e}")
            return None


class SuricataEventSource(EventSource):
    """
    Suricata Event Source Adapter for ETTH.
    Streams and ingests Suricata EVE JSON event feeds.
    """
    def __init__(self, queue_maxsize: int = 5000):
        super().__init__(mode="LIVE")
        self.state: str = "IDLE"
        self.correlator = SuricataCorrelator()
        self.queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=queue_maxsize)

        # Operational metrics
        self.total_events_read = 0
        self.flow_events_read = 0
        self.tls_events_read = 0
        self.alert_events_read = 0
        self.malformed_lines = 0
        self.flows_emitted = 0
        self.start_time: Optional[float] = None

    async def start(self, **kwargs) -> None:
        self.state = "CAPTURING"
        self.start_time = time.time()
        logger.info("SuricataEventSource started in streaming sensor mode.")

    async def stop(self) -> None:
        self.state = "STOPPED"
        for flow in self.correlator.flush_pending():
            if not self.queue.full():
                self.queue.put_nowait(flow)
                self.flows_emitted += 1
        logger.info("SuricataEventSource stopped.")

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parses a single JSON line from Suricata eve.json.
        Returns canonical flow dict if a flow was finalized, otherwise None.
        """
        line_clean = line.strip()
        if not line_clean:
            return None

        self.total_events_read += 1
        try:
            event = json.loads(line_clean)
        except Exception:
            self.malformed_lines += 1
            return None

        etype = str(event.get("event_type", "")).lower()
        if etype == "flow":
            self.flow_events_read += 1
        elif etype == "tls":
            self.tls_events_read += 1
        elif etype == "alert":
            self.alert_events_read += 1

        flow = self.correlator.add_eve_event(event)
        if flow:
            self.flows_emitted += 1
            if not self.queue.full():
                self.queue.put_nowait(flow)

        return flow

    async def ingest_file(self, file_path: Path) -> int:
        """
        Asynchronously reads and parses an entire Suricata eve.json log file.
        Returns count of flows finalized.
        """
        flows_before = self.flows_emitted
        if not file_path.exists():
            logger.error(f"Suricata EVE log file not found: {file_path}")
            return 0

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                self.parse_line(line)
                if self.total_events_read % 500 == 0:
                    await asyncio.sleep(0)

        return self.flows_emitted - flows_before

    async def get_next_flow(self, timeout: float = 0.5) -> Optional[Dict[str, Any]]:
        try:
            return await asyncio.wait_for(self.queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def get_status(self) -> Dict[str, Any]:
        now = time.time()
        elapsed = round(now - self.start_time, 2) if (self.start_time and self.state == "CAPTURING") else 0.0
        return {
            "status": self.state,
            "sensor": "SURICATA",
            "mode": "LIVE",
            "total_events_read": self.total_events_read,
            "flow_events_read": self.flow_events_read,
            "tls_events_read": self.tls_events_read,
            "alert_events_read": self.alert_events_read,
            "malformed_lines": self.malformed_lines,
            "flows_emitted": self.flows_emitted,
            "queue_depth": self.queue.qsize(),
            "active_correlations": len(self.correlator._cache),
            "elapsed_seconds": elapsed
        }
