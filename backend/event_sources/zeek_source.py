"""
ETTH Zeek Sensor Ingestion Adapter (Phase 11)
Parses, correlates, and normalizes Zeek JSON logs (conn.log, ssl.log, x509.log)
into canonical ETTH flow dictionaries for real-time zero-decryption threat detection.

Enforces:
1. ZERO payload decryption or plaintext inspection.
2. ZERO fingerprint fabrication (missing JA3/JA4 remains None).
3. Stateful UID correlation between conn.log and ssl.log.
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


class ZeekCorrelator:
    """
    Stateful correlator for Zeek logs sharing connection UIDs.
    Zeek emits separate conn.log and ssl.log events asynchronously.
    This correlator merges them into a unified ETTH flow dictionary.
    """
    def __init__(self, max_cached: int = 50000, ttl_seconds: float = 60.0):
        self.max_cached = max_cached
        self.ttl_seconds = ttl_seconds
        # Maps uid -> {"conn": {...}, "ssl": {...}, "created_at": float}
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._last_cleanup = time.time()

    def _cleanup_stale(self, now: float):
        if now - self._last_cleanup < 10.0:
            return
        self._last_cleanup = now
        stale_uids = [
            uid for uid, item in self._cache.items()
            if (now - item["created_at"]) > self.ttl_seconds
        ]
        for uid in stale_uids:
            del self._cache[uid]

    def add_conn_record(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Ingests a conn.log record. If matching ssl.log was already cached, merges and returns.
        Otherwise caches conn record.
        """
        now = time.time()
        self._cleanup_stale(now)

        uid = str(record.get("uid") or record.get("id", ""))
        if not uid:
            # Standalone connection without UID, build immediately
            return self.build_flow(conn=record, ssl=None)

        if uid in self._cache and "ssl" in self._cache[uid]:
            ssl_record = self._cache[uid].pop("ssl")
            if not self._cache[uid]:
                del self._cache[uid]
            return self.build_flow(conn=record, ssl=ssl_record)

        if len(self._cache) < self.max_cached:
            if uid not in self._cache:
                self._cache[uid] = {"created_at": now}
            self._cache[uid]["conn"] = record

        return None

    def add_ssl_record(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Ingests an ssl.log record. If matching conn.log was already cached, merges and returns.
        Otherwise caches ssl record.
        """
        now = time.time()
        self._cleanup_stale(now)

        uid = str(record.get("uid") or record.get("id", ""))
        if not uid:
            return None

        if uid in self._cache and "conn" in self._cache[uid]:
            conn_record = self._cache[uid].pop("conn")
            if not self._cache[uid]:
                del self._cache[uid]
            return self.build_flow(conn=conn_record, ssl=record)

        if len(self._cache) < self.max_cached:
            if uid not in self._cache:
                self._cache[uid] = {"created_at": now}
            self._cache[uid]["ssl"] = record

        return None

    def flush_pending_conn(self) -> List[Dict[str, Any]]:
        """
        Flushes all unmatched conn records as flows without TLS details.
        """
        flushed = []
        for uid, item in list(self._cache.items()):
            if "conn" in item:
                flow = self.build_flow(conn=item["conn"], ssl=None)
                if flow:
                    flushed.append(flow)
        self._cache.clear()
        return flushed

    @staticmethod
    def build_flow(conn: Dict[str, Any], ssl: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """
        Normalizes merged Zeek conn + ssl records into a canonical ETTH flow dict.
        """
        try:
            # Extract 5-tuple
            orig_h = str(conn.get("id.orig_h") or conn.get("orig_h") or "0.0.0.0")
            orig_p = int(conn.get("id.orig_p") or conn.get("orig_p") or 0)
            resp_h = str(conn.get("id.resp_h") or conn.get("resp_h") or "0.0.0.0")
            resp_p = int(conn.get("id.resp_p") or conn.get("resp_p") or 0)
            proto_raw = str(conn.get("proto") or "tcp").upper()
            protocol = "TCP" if proto_raw == "TCP" else ("UDP" if proto_raw == "UDP" else "TCP")

            # Timing & statistics
            duration = float(conn.get("duration") or 0.0)
            orig_pkts = int(conn.get("orig_pkts") or 0)
            resp_pkts = int(conn.get("resp_pkts") or 0)
            orig_bytes = int(conn.get("orig_bytes") or 0)
            resp_bytes = int(conn.get("resp_bytes") or 0)

            total_packets = orig_pkts + resp_pkts
            total_bytes = orig_bytes + resp_bytes
            pps = (total_packets / duration) if duration > 0 else float(total_packets)
            bps = (total_bytes / duration) if duration > 0 else float(total_bytes)

            asymmetry_pkts = (orig_pkts / max(1, resp_pkts)) if resp_pkts > 0 else float(orig_pkts)
            asymmetry_bytes = (orig_bytes / max(1, resp_bytes)) if resp_bytes > 0 else float(orig_bytes)

            uid = str(conn.get("uid") or f"zeek_{orig_h}_{orig_p}_{resp_h}_{resp_p}")

            flow_dict: Dict[str, Any] = {
                "flow_id": uid,
                "dataset_id": "ZEEK_SENSOR",
                "protocol": protocol,
                "forward_endpoint": f"{orig_h}:{orig_p}",
                "reverse_endpoint": f"{resp_h}:{resp_p}",
                "source_ip": orig_h,
                "source_port": orig_p,
                "destination_ip": resp_h,
                "destination_port": resp_p,
                "flow_duration": duration,
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "forward_packets": orig_pkts,
                "reverse_packets": resp_pkts,
                "forward_bytes": orig_bytes,
                "reverse_bytes": resp_bytes,
                "packets_per_second": pps,
                "bytes_per_second": bps,
                "asymmetry_ratio_packets": asymmetry_pkts,
                "asymmetry_ratio_bytes": asymmetry_bytes,
                "sensor_type": "ZEEK",
                "sensor_conn_state": str(conn.get("conn_state", "UNKNOWN")),
                "sensor_service": str(conn.get("service", "")),
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
                "tls_cipher": None,
            }

            # Enrich from ssl.log if available
            if ssl:
                flow_dict["clienthello_present"] = True
                flow_dict["serverhello_present"] = bool(ssl.get("established", True))
                flow_dict["tls_version"] = ssl.get("version")
                flow_dict["tls_cipher"] = ssl.get("cipher")

                server_name = ssl.get("server_name")
                if server_name and str(server_name).strip() not in ["", "-", "None"]:
                    flow_dict["sni"] = str(server_name).strip().lower()
                    flow_dict["sni_present"] = True

                # Fingerprint mapping with strict non-fabrication
                raw_ja3 = ssl.get("ja3")
                if raw_ja3 and str(raw_ja3).strip() not in ["", "-", "None"]:
                    flow_dict["ja3_hash"] = str(raw_ja3).strip()

                raw_ja3s = ssl.get("ja3s")
                if raw_ja3s and str(raw_ja3s).strip() not in ["", "-", "None"]:
                    flow_dict["ja3s_hash"] = str(raw_ja3s).strip()

                raw_ja4 = ssl.get("ja4")
                if raw_ja4 and str(raw_ja4).strip() not in ["", "-", "None"]:
                    flow_dict["ja4"] = str(raw_ja4).strip()

                raw_alpn = ssl.get("alpn") or ssl.get("next_protocol")
                if raw_alpn and str(raw_alpn).strip() not in ["", "-", "None"]:
                    flow_dict["alpn_value"] = str(raw_alpn).strip()

            return flow_dict
        except Exception as e:
            logger.warning(f"Error normalizing Zeek record to ETTH flow: {e}")
            return None


class ZeekEventSource(EventSource):
    """
    Zeek Event Source Adapter for ETTH.
    Streams and ingests Zeek JSON log files (conn.log, ssl.log).
    """
    def __init__(self, queue_maxsize: int = 5000):
        super().__init__(mode="LIVE")
        self.state: str = "IDLE"
        self.correlator = ZeekCorrelator()
        self.queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=queue_maxsize)
        
        # Operational telemetry
        self.total_lines_read = 0
        self.conn_records_read = 0
        self.ssl_records_read = 0
        self.malformed_lines = 0
        self.flows_emitted = 0
        self.active_correlations = 0
        self.start_time: Optional[float] = None

    async def start(self, **kwargs) -> None:
        self.state = "CAPTURING"
        self.start_time = time.time()
        logger.info("ZeekEventSource started in streaming sensor mode.")

    async def stop(self) -> None:
        self.state = "STOPPED"
        # Flush any remaining unclosed flows
        for flow in self.correlator.flush_pending_conn():
            if not self.queue.full():
                self.queue.put_nowait(flow)
                self.flows_emitted += 1
        logger.info("ZeekEventSource stopped.")

    def parse_line(self, line: str, log_hint: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Parses a single JSON line from Zeek and processes it through the correlator.
        Returns canonical flow dict if a flow was finalized, otherwise None.
        """
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#"):
            return None

        self.total_lines_read += 1
        try:
            record = json.loads(line_clean)
        except Exception:
            self.malformed_lines += 1
            return None

        # Determine log type by schema heuristic or hint
        is_ssl = (log_hint == "ssl") or ("server_name" in record) or ("ja3" in record) or ("version" in record and "cipher" in record)
        is_conn = (log_hint == "conn") or ("conn_state" in record) or ("orig_bytes" in record) or ("id.orig_h" in record)

        flow = None
        if is_ssl and not is_conn:
            self.ssl_records_read += 1
            flow = self.correlator.add_ssl_record(record)
        elif is_conn:
            self.conn_records_read += 1
            flow = self.correlator.add_conn_record(record)
        else:
            # Fallback attempt as conn record
            self.conn_records_read += 1
            flow = self.correlator.add_conn_record(record)

        if flow:
            self.flows_emitted += 1
            if not self.queue.full():
                self.queue.put_nowait(flow)

        return flow

    async def ingest_file(self, file_path: Path, log_hint: Optional[str] = None) -> int:
        """
        Asynchronously reads and parses an entire Zeek JSON log file.
        Returns count of flows finalized from this file.
        """
        flows_before = self.flows_emitted
        if not file_path.exists():
            logger.error(f"Zeek log file not found: {file_path}")
            return 0

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                self.parse_line(line, log_hint=log_hint)
                # Yield control to event loop periodically
                if self.total_lines_read % 500 == 0:
                    await asyncio.sleep(0)

        return self.flows_emitted - flows_before

    async def get_next_flow(self, timeout: float = 0.5) -> Optional[Dict[str, Any]]:
        """
        Retrieves the next normalized flow from the queue with backpressure handling.
        """
        try:
            return await asyncio.wait_for(self.queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def get_status(self) -> Dict[str, Any]:
        now = time.time()
        elapsed = round(now - self.start_time, 2) if (self.start_time and self.state == "CAPTURING") else 0.0
        return {
            "status": self.state,
            "sensor": "ZEEK",
            "mode": "LIVE",
            "total_lines_read": self.total_lines_read,
            "conn_records_read": self.conn_records_read,
            "ssl_records_read": self.ssl_records_read,
            "malformed_lines": self.malformed_lines,
            "flows_emitted": self.flows_emitted,
            "queue_depth": self.queue.qsize(),
            "active_correlations": len(self.correlator._cache),
            "elapsed_seconds": elapsed
        }
