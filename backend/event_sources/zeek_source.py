"""
ETTH Zeek Sensor Ingestion Adapter (Phase 11, reconciled with the Phase 8-10 canonical flow contract)

Parses and correlates Zeek JSON logs (conn.log, ssl.log) into canonical ETTH flow dicts
(pipeline.canonical_flow). This is log-file parsing only: no Zeek process is started or managed.

Guarantees:
1. No payload decryption or inspection: only Zeek's own log fields are read.
2. No fabrication. Missing JA3/JA4/SNI stay None, unknown endpoints/protocols are not
   defaulted, and rates are not computed from a missing or zero duration.
3. Fields whose meaning differs from the ETTH features of the same topic are kept apart:
   * ssl.log `version` is the NEGOTIATED version -> `tls_version_observed`, never `tls_version`
     (ETTH's model feature is the version OFFERED in the ClientHello);
   * `next_protocol` is the server-SELECTED ALPN -> `alpn_negotiated`, never `alpn_value`;
   * `ja4` comes from the FoxIO Zeek package -> tagged `ja4_implementation=FOXIO_JA4`;
   * bytes come from `*_ip_bytes` (IP length, as ETTH) when present, else from
     `orig_bytes`/`resp_bytes` (transport payload), tagged in `byte_count_semantics`.
   Flow statistics are tagged `feature_provenance=SENSOR_AGGREGATE`, so models trained on ETTH
   packet features refuse them.
4. UID correlation between conn.log and ssl.log in either order, bounded memory, duplicate
   suppression, and no silent loss: conn records that expire or overflow the cache are
   emitted without TLS enrichment and counted.
"""

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.event_sources.base import EventSource
from pipeline.canonical_flow import (BYTES_IP_LENGTH, BYTES_TRANSPORT_PAYLOAD, BYTES_UNKNOWN, FEATURE_PROVENANCE_SENSOR,
                                     JA4_IMPLEMENTATION_FOXIO, SUPPORTED_PROTOCOLS, RecentKeys, as_float, as_int,
                                     clean_str, count_features, endpoint, normalize_hash32, normalize_ja3,
                                     normalize_ja4, protocol_name, tls_version_label)

logger = logging.getLogger(__name__)


def _field(record: Dict[str, Any], flat: str) -> Any:
    """Zeek JSON is normally flat ('id.orig_h'); some shippers nest it ({'id': {'orig_h': ...}})."""
    if flat in record:
        return record[flat]
    head, _, tail = flat.partition(".")
    nested = record.get(head)
    return nested.get(tail) if tail and isinstance(nested, dict) else None


def _uid(record: Dict[str, Any]) -> Optional[str]:
    return clean_str(record.get("uid"))


class ZeekCorrelator:
    """
    Merges conn.log and ssl.log records that share a Zeek connection UID.

    Zeek writes ssl.log when the handshake finishes and conn.log when the connection ends, so
    ssl usually precedes conn, but file-by-file ingestion can deliver either order.
    """

    def __init__(self, max_cached: int = 50000, ttl_seconds: float = 60.0, dedup_window: int = 100_000):
        self.max_cached = max_cached
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Dict[str, Any]] = {}      # uid -> {"conn"?, "ssl"?, "created_at"}
        self._emitted = RecentKeys(dedup_window)
        self._expired: List[Dict[str, Any]] = []
        self._last_cleanup = time.time()
        self.stats = {"duplicate_records": 0, "late_ssl_records": 0, "expired_conn_emitted": 0,
                      "orphan_ssl_dropped": 0, "cache_overflow_conn_emitted": 0, "cache_overflow_ssl_dropped": 0,
                      "invalid_records": 0, "unsupported_protocol_records": 0}

    # ------------------------------------------------------------------ cache housekeeping --
    def _cleanup_stale(self, now: float) -> None:
        if now - self._last_cleanup < 10.0:
            return
        self._last_cleanup = now
        for uid in [u for u, item in self._cache.items() if (now - item["created_at"]) > self.ttl_seconds]:
            item = self._cache.pop(uid)
            if "conn" in item:
                flow = self._finish(uid, item["conn"], None)
                if flow:
                    self._expired.append(flow)
                    self.stats["expired_conn_emitted"] += 1
            else:
                self.stats["orphan_ssl_dropped"] += 1

    def pop_expired(self) -> List[Dict[str, Any]]:
        """Flows released by TTL expiry since the last call (conn records whose ssl never arrived)."""
        out, self._expired = self._expired, []
        return out

    def _finish(self, uid: Optional[str], conn: Dict[str, Any], ssl: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        flow = self.build_flow(conn=conn, ssl=ssl)
        if flow is None:
            self.stats["invalid_records"] += 1
            return None
        if flow.get("protocol") not in SUPPORTED_PROTOCOLS:
            self.stats["unsupported_protocol_records"] += 1
            return None
        if uid:
            self._emitted.add(uid)
        return flow

    # --------------------------------------------------------------------------- ingestion --
    def add_conn_record(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Returns the merged flow when the matching ssl record is already cached, else caches."""
        now = time.time()
        self._cleanup_stale(now)
        uid = _uid(record)
        if not uid:
            return self._finish(None, record, None)
        if uid in self._emitted:
            self.stats["duplicate_records"] += 1
            return None
        item = self._cache.get(uid)
        if item is not None and "conn" in item:
            self.stats["duplicate_records"] += 1
            return None
        if item is not None and "ssl" in item:
            del self._cache[uid]
            return self._finish(uid, record, item["ssl"])
        if len(self._cache) >= self.max_cached:
            self.stats["cache_overflow_conn_emitted"] += 1
            return self._finish(uid, record, None)
        self._cache[uid] = {"created_at": now, "conn": record}
        return None

    def add_ssl_record(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Returns the merged flow when the matching conn record is already cached, else caches."""
        now = time.time()
        self._cleanup_stale(now)
        uid = _uid(record)
        if not uid:
            self.stats["invalid_records"] += 1
            return None
        if uid in self._emitted:
            self.stats["late_ssl_records"] += 1
            return None
        item = self._cache.get(uid)
        if item is not None and "ssl" in item:
            self.stats["duplicate_records"] += 1
            return None
        if item is not None and "conn" in item:
            del self._cache[uid]
            return self._finish(uid, item["conn"], record)
        if len(self._cache) >= self.max_cached:
            self.stats["cache_overflow_ssl_dropped"] += 1
            return None
        self._cache[uid] = {"created_at": now, "ssl": record}
        return None

    def flush_pending_conn(self) -> List[Dict[str, Any]]:
        """Emits every cached conn record without TLS enrichment; cached ssl-only records are counted as orphans."""
        flushed = []
        for uid, item in list(self._cache.items()):
            if "conn" in item:
                flow = self._finish(uid, item["conn"], None)
                if flow:
                    flushed.append(flow)
            else:
                self.stats["orphan_ssl_dropped"] += 1
        self._cache.clear()
        return flushed

    # ----------------------------------------------------------------------- normalisation --
    @staticmethod
    def build_flow(conn: Dict[str, Any], ssl: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Normalises a conn record (plus an optional ssl record) into a canonical ETTH flow dict."""
        orig_h, resp_h = clean_str(_field(conn, "id.orig_h")), clean_str(_field(conn, "id.resp_h"))
        orig_p, resp_p = as_int(_field(conn, "id.orig_p")), as_int(_field(conn, "id.resp_p"))
        if not orig_h or not resp_h:
            return None
        protocol = protocol_name(conn.get("proto"))

        if conn.get("orig_ip_bytes") is not None or conn.get("resp_ip_bytes") is not None:
            fwd_bytes, rev_bytes = as_int(conn.get("orig_ip_bytes")), as_int(conn.get("resp_ip_bytes"))
            byte_semantics = BYTES_IP_LENGTH
        else:
            fwd_bytes, rev_bytes = as_int(conn.get("orig_bytes")), as_int(conn.get("resp_bytes"))
            byte_semantics = BYTES_TRANSPORT_PAYLOAD if fwd_bytes is not None or rev_bytes is not None else BYTES_UNKNOWN
        duration = as_float(conn.get("duration"))
        start = as_float(conn.get("ts"))
        uid = _uid(conn)

        flow: Dict[str, Any] = {
            "flow_id": uid or f"zeek_{orig_h}_{orig_p}_{resp_h}_{resp_p}_{start}",
            "dataset_id": "ZEEK_SENSOR",
            "source_file": None,
            "label": "UNKNOWN",
            "protocol": protocol,
            "forward_endpoint": endpoint(orig_h, orig_p),
            "reverse_endpoint": endpoint(resp_h, resp_p),
            "source_ip": orig_h, "source_port": orig_p, "destination_ip": resp_h, "destination_port": resp_p,
            "start_time": start,
            "end_time": start + duration if start is not None and duration is not None else None,
            **count_features(duration, as_int(conn.get("orig_pkts")), as_int(conn.get("resp_pkts")), fwd_bytes, rev_bytes),
            "feature_provenance": FEATURE_PROVENANCE_SENSOR,
            "byte_count_semantics": byte_semantics,
            "sensor_type": "ZEEK",
            "sensor_record_id": uid,
            "sensor_conn_state": clean_str(conn.get("conn_state")),
            "sensor_service": clean_str(conn.get("service")),
            "sensor_history": clean_str(conn.get("history")),
            # TLS: unobserved unless an ssl.log record is merged.
            "clienthello_present": False,
            "serverhello_present": False,
            "sni": None,
            "sni_present": False,
            "ja3_hash": None,
            "ja3s_hash": None,
            "ja4": None,
            "tls_version_observed": None,
            "tls_version_semantics": None,
            "alpn_negotiated": None,
            "tls_cipher": None,
        }
        if ssl:
            ja3, ja3_derivation, ja3_reason = normalize_ja3(ssl.get("ja3"))
            ja4, ja4_reason = normalize_ja4(ssl.get("ja4"))
            version = tls_version_label(ssl.get("version"))
            cipher = clean_str(ssl.get("cipher"))
            ja3s = normalize_hash32(ssl.get("ja3s"))
            sni = clean_str(ssl.get("server_name"))
            flow.update({
                # An ssl.log record means Zeek's TLS analyser confirmed a handshake.
                "clienthello_present": True,
                # The negotiated version and cipher come from the ServerHello; `established`
                # (handshake completed) is a different property and is not used here.
                "serverhello_present": bool(version or cipher or ja3s),
                "sni": sni.lower() if sni else None,
                "sni_present": bool(sni),
                "ja3_hash": ja3, "ja3_derivation": ja3_derivation, "ja3_rejected_reason": ja3_reason,
                "ja3s_hash": ja3s,
                "ja4": ja4, "ja4_implementation": JA4_IMPLEMENTATION_FOXIO if ja4 else None,
                "ja4_rejected_reason": ja4_reason,
                "tls_version_observed": version,
                "tls_version_semantics": "NEGOTIATED" if version else None,
                "alpn_negotiated": clean_str(ssl.get("next_protocol")),
                "tls_cipher": cipher,
                "tls_established": ssl.get("established") if isinstance(ssl.get("established"), bool) else None,
            })
        return flow


class ZeekEventSource(EventSource):
    """Streams Zeek JSON log lines (or whole files) through ZeekCorrelator into a bounded queue."""

    def __init__(self, queue_maxsize: int = 5000):
        super().__init__(mode="LIVE")
        self.state: str = "IDLE"
        self.correlator = ZeekCorrelator()
        self.queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=queue_maxsize)
        self.total_lines_read = 0
        self.conn_records_read = 0
        self.ssl_records_read = 0
        self.unsupported_records = 0
        self.malformed_lines = 0
        self.flows_emitted = 0
        self.queue_dropped = 0
        self.start_time: Optional[float] = None

    async def start(self, **kwargs) -> None:
        self.state = "CAPTURING"
        self.start_time = time.time()
        logger.info("ZeekEventSource started (log-line parsing; no Zeek process is managed).")

    async def stop(self) -> None:
        self.state = "STOPPED"
        for flow in self.correlator.flush_pending_conn():
            self._emit(flow)
        logger.info("ZeekEventSource stopped.")

    def _emit(self, flow: Dict[str, Any]) -> None:
        self.flows_emitted += 1
        if self.queue.full():
            self.queue_dropped += 1
        else:
            self.queue.put_nowait(flow)

    @staticmethod
    def _log_type(record: Dict[str, Any], log_hint: Optional[str]) -> Optional[str]:
        if log_hint in ("conn", "ssl"):
            return log_hint
        path = str(record.get("_path") or "").lower()
        if path in ("conn", "ssl"):
            return path
        if "conn_state" in record or "orig_pkts" in record or "orig_bytes" in record:
            return "conn"
        if any(k in record for k in ("server_name", "ja3", "ja4", "cipher", "established", "ssl_history")):
            return "ssl"
        return None

    def parse_line(self, line: str, log_hint: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Parses one JSON line; returns the canonical flow if this line completed one."""
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#"):
            return None
        self.total_lines_read += 1
        try:
            record = json.loads(line_clean)
            if not isinstance(record, dict):
                raise ValueError("not a JSON object")
        except Exception:
            self.malformed_lines += 1
            return None

        kind = self._log_type(record, log_hint)
        if kind == "conn":
            self.conn_records_read += 1
            flow = self.correlator.add_conn_record(record)
        elif kind == "ssl":
            self.ssl_records_read += 1
            flow = self.correlator.add_ssl_record(record)
        else:
            # x509.log, dns.log, ... are not used; they are counted, not guessed into a flow.
            self.unsupported_records += 1
            flow = None

        for expired in self.correlator.pop_expired():
            self._emit(expired)
        if flow:
            self._emit(flow)
        return flow

    async def ingest_file(self, file_path: Path, log_hint: Optional[str] = None) -> int:
        """Reads a whole Zeek JSON log file. Returns the number of flows finalised while reading it."""
        flows_before = self.flows_emitted
        if not file_path.exists():
            logger.error("Zeek log file not found: %s", file_path.name)
            return 0
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                self.parse_line(line, log_hint=log_hint)
                if self.total_lines_read % 500 == 0:
                    await asyncio.sleep(0)
        return self.flows_emitted - flows_before

    async def get_next_flow(self, timeout: float = 0.5) -> Optional[Dict[str, Any]]:
        try:
            return await asyncio.wait_for(self.queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def get_status(self) -> Dict[str, Any]:
        elapsed = round(time.time() - self.start_time, 2) if (self.start_time and self.state == "CAPTURING") else 0.0
        return {
            "status": self.state,
            "sensor": "ZEEK",
            "mode": "LOG_PARSING",
            "total_lines_read": self.total_lines_read,
            "conn_records_read": self.conn_records_read,
            "ssl_records_read": self.ssl_records_read,
            "unsupported_records": self.unsupported_records,
            "malformed_lines": self.malformed_lines,
            "flows_emitted": self.flows_emitted,
            "queue_depth": self.queue.qsize(),
            "queue_dropped": self.queue_dropped,
            "active_correlations": len(self.correlator._cache),
            "correlator": dict(self.correlator.stats),
            "elapsed_seconds": elapsed,
        }
