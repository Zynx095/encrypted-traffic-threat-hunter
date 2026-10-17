"""
ETTH Suricata Sensor Ingestion Adapter (Phase 11, reconciled with the Phase 8-10 canonical flow contract)

Parses and correlates Suricata EVE JSON events (flow, tls, alert) by `flow_id` into canonical
ETTH flow dicts (pipeline.canonical_flow). This is log parsing only: no Suricata process is
started or managed.

Guarantees:
1. No payload decryption or retention; only EVE metadata is read.
2. No fabrication. Missing JA3/JA4/SNI stay None, `serverhello_present` is True only when
   ServerHello-derived fields exist, endpoints/protocol are never defaulted, and rates are not
   computed from a missing or zero duration.
3. Semantics are kept apart from ETTH model features:
   * `tls.version` is the NEGOTIATED version -> `tls_version_observed`, never `tls_version`;
   * `tls.client_alpns[0]` is the first ALPN the client offered, which is what ETTH's
     `alpn_value` means; `tls.server_alpns[0]` -> `alpn_negotiated`;
   * `tls.ja4` (Suricata >= 7) is FoxIO JA4 -> `ja4_implementation=FOXIO_JA4`;
   * a JA3 string without its hash is hashed with MD5 (the JA3 definition);
   * duration is `flow.end - flow.start` (microseconds); the integer-second `flow.age` is only a
     tagged fallback; byte counters are not documented as IP length and are tagged UNKNOWN.
   Flow statistics are tagged `feature_provenance=SENSOR_AGGREGATE`.
4. Alerts are third-party signature matches. They are carried as `sensor_alerts` context only:
   never as `label`, never as a prediction, never as a model input (the feature allow-list in
   ml.features.governance does not contain them).
5. Duplicate flow events are not re-emitted; tls/alert events that arrive after their flow
   event, or that never meet one, are counted.
"""

import asyncio
import datetime
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.event_sources.base import EventSource
from pipeline.canonical_flow import (BYTES_UNKNOWN, FEATURE_PROVENANCE_SENSOR, JA4_IMPLEMENTATION_FOXIO,
                                     SUPPORTED_PROTOCOLS, RecentKeys, as_float, as_int, clean_str, count_features,
                                     endpoint, normalize_hash32, normalize_ja3, normalize_ja4, protocol_name,
                                     tls_version_label)

logger = logging.getLogger(__name__)


def _epoch(value: Any) -> Optional[float]:
    """Suricata timestamps look like '2026-10-16T12:00:00.000000+0000'."""
    s = clean_str(value)
    if s is None:
        return None
    try:
        return datetime.datetime.fromisoformat(s).timestamp()
    except ValueError:
        try:
            return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
        except ValueError:
            return None


def _first(values: Any) -> Optional[str]:
    if isinstance(values, list) and values:
        return clean_str(values[0])
    return None


class SuricataCorrelator:
    """Correlates Suricata EVE events that share a `flow_id`; the `flow` event finalises a flow."""

    def __init__(self, max_cached: int = 50000, ttl_seconds: float = 60.0, dedup_window: int = 100_000):
        self.max_cached = max_cached
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Dict[str, Any]] = {}   # flow_id -> {"tls", "alerts", "created_at"}
        self._emitted = RecentKeys(dedup_window)
        self._last_cleanup = time.time()
        self.stats = {"duplicate_flow_events": 0, "late_events": 0, "expired_without_flow": 0,
                      "cache_overflow_evicted": 0, "invalid_events": 0, "unsupported_protocol_events": 0,
                      "ignored_event_types": 0}

    def _cleanup_stale(self, now: float) -> None:
        if now - self._last_cleanup < 10.0:
            return
        self._last_cleanup = now
        for fid in [f for f, item in self._cache.items() if (now - item["created_at"]) > self.ttl_seconds]:
            del self._cache[fid]
            self.stats["expired_without_flow"] += 1

    def _evict_oldest(self) -> None:
        if self._cache:
            oldest = min(self._cache, key=lambda k: self._cache[k]["created_at"])
            del self._cache[oldest]
            self.stats["cache_overflow_evicted"] += 1

    def _finish(self, fid: Optional[str], flow_event: Dict[str, Any], entry: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        flow = self.build_flow(flow_event=flow_event, tls_event=(entry or {}).get("tls"),
                               alerts=(entry or {}).get("alerts", []))
        if flow is None:
            self.stats["invalid_events"] += 1
            return None
        if flow.get("protocol") not in SUPPORTED_PROTOCOLS:
            self.stats["unsupported_protocol_events"] += 1
            return None
        if fid:
            self._emitted.add(fid)
        return flow

    def add_eve_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Ingests one EVE event; returns the canonical flow when a `flow` event finalises it."""
        now = time.time()
        self._cleanup_stale(now)
        event_type = str(event.get("event_type", "")).lower()
        fid = clean_str(event.get("flow_id"))
        if event_type not in ("flow", "tls", "alert"):
            self.stats["ignored_event_types"] += 1
            return None
        if not fid:
            return self._finish(None, event, None) if event_type == "flow" else None
        if fid in self._emitted:
            self.stats["duplicate_flow_events" if event_type == "flow" else "late_events"] += 1
            return None

        entry = self._cache.get(fid)
        if event_type == "flow":
            if entry is not None:
                del self._cache[fid]
            return self._finish(fid, event, entry)

        if entry is None:
            if len(self._cache) >= self.max_cached:
                self._evict_oldest()
            entry = self._cache[fid] = {"created_at": now, "tls": None, "alerts": []}
        if event_type == "tls":
            entry["tls"] = entry["tls"] or event      # first TLS event wins, as ETTH's first-ClientHello policy
        else:
            entry["alerts"].append(event)
        return None

    def flush_pending(self) -> List[Dict[str, Any]]:
        """tls/alert entries without a flow event cannot become flows; they are counted and cleared."""
        self.stats["expired_without_flow"] += len(self._cache)
        self._cache.clear()
        return []

    @staticmethod
    def build_flow(flow_event: Dict[str, Any], tls_event: Optional[Dict[str, Any]] = None,
                   alerts: Optional[List[Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
        """Normalises a Suricata flow event (plus optional tls and alert events) into a canonical flow dict."""
        src_ip, dest_ip = clean_str(flow_event.get("src_ip")), clean_str(flow_event.get("dest_ip"))
        if not src_ip or not dest_ip:
            return None
        src_port, dest_port = as_int(flow_event.get("src_port")), as_int(flow_event.get("dest_port"))
        flow_sub = flow_event.get("flow") if isinstance(flow_event.get("flow"), dict) else {}

        start, end = _epoch(flow_sub.get("start")), _epoch(flow_sub.get("end"))
        if start is not None and end is not None and end >= start:
            duration, duration_source = round(end - start, 6), "flow.end - flow.start"
        elif as_float(flow_sub.get("age")) is not None:
            duration, duration_source = as_float(flow_sub.get("age")), "flow.age (integer seconds)"
        else:
            duration, duration_source = None, None

        fid = clean_str(flow_event.get("flow_id"))
        alert_details = [
            {"signature": clean_str((a.get("alert") or {}).get("signature")),
             "signature_id": as_int((a.get("alert") or {}).get("signature_id")),
             "severity": as_int((a.get("alert") or {}).get("severity")),
             "category": clean_str((a.get("alert") or {}).get("category"))}
            for a in (alerts or [])
        ]
        flow: Dict[str, Any] = {
            "flow_id": fid or f"suricata_{src_ip}_{src_port}_{dest_ip}_{dest_port}_{start}",
            "dataset_id": "SURICATA_SENSOR",
            "source_file": None,
            "label": "UNKNOWN",
            "protocol": protocol_name(flow_event.get("proto")),
            "forward_endpoint": endpoint(src_ip, src_port),
            "reverse_endpoint": endpoint(dest_ip, dest_port),
            "source_ip": src_ip, "source_port": src_port, "destination_ip": dest_ip, "destination_port": dest_port,
            "start_time": start,
            "end_time": end,
            **count_features(duration, as_int(flow_sub.get("pkts_toserver")), as_int(flow_sub.get("pkts_toclient")),
                             as_int(flow_sub.get("bytes_toserver")), as_int(flow_sub.get("bytes_toclient"))),
            "feature_provenance": FEATURE_PROVENANCE_SENSOR,
            "byte_count_semantics": BYTES_UNKNOWN,
            "sensor_duration_source": duration_source,
            "sensor_type": "SURICATA",
            "sensor_record_id": fid,
            "sensor_flow_state": clean_str(flow_sub.get("state")),
            "sensor_flow_end_reason": clean_str(flow_sub.get("reason")),
            "sensor_app_proto": clean_str(flow_event.get("app_proto")),
            # Third-party signature matches: context only (never label, prediction or model input).
            "sensor_alerts": [d["signature"] for d in alert_details if d["signature"]],
            "sensor_alert_details": alert_details,
            "clienthello_present": False,
            "serverhello_present": False,
            "sni": None,
            "sni_present": False,
            "ja3_hash": None,
            "ja3s_hash": None,
            "ja4": None,
            "alpn_value": None,
            "alpn_negotiated": None,
            "tls_version_observed": None,
            "tls_version_semantics": None,
        }
        if tls_event:
            tls = tls_event.get("tls") if isinstance(tls_event.get("tls"), dict) else {}
            ja3_obj, ja3s_obj = tls.get("ja3"), tls.get("ja3s")
            ja3, ja3_derivation, ja3_reason = (normalize_ja3(ja3_obj.get("hash"), ja3_obj.get("string"))
                                               if isinstance(ja3_obj, dict) else normalize_ja3(ja3_obj))
            ja3s = normalize_hash32(ja3s_obj.get("hash") if isinstance(ja3s_obj, dict) else ja3s_obj)
            ja4, ja4_reason = normalize_ja4(tls.get("ja4"))
            version = tls_version_label(tls.get("version"))
            sni = clean_str(tls.get("sni"))
            flow.update({
                "clienthello_present": True,
                "serverhello_present": bool(version or ja3s or tls.get("server_alpns")),
                "sni": sni.lower() if sni else None,
                "sni_present": bool(sni),
                "ja3_hash": ja3, "ja3_derivation": ja3_derivation, "ja3_rejected_reason": ja3_reason,
                "ja3s_hash": ja3s,
                "ja4": ja4, "ja4_implementation": JA4_IMPLEMENTATION_FOXIO if ja4 else None,
                "ja4_rejected_reason": ja4_reason,
                "alpn_value": _first(tls.get("client_alpns")),
                "alpn_negotiated": _first(tls.get("server_alpns")),
                "tls_version_observed": version,
                "tls_version_semantics": "NEGOTIATED" if version else None,
            })
        return flow


class SuricataEventSource(EventSource):
    """Streams Suricata eve.json lines (or whole files) through SuricataCorrelator into a bounded queue."""

    def __init__(self, queue_maxsize: int = 5000):
        super().__init__(mode="LIVE")
        self.state: str = "IDLE"
        self.correlator = SuricataCorrelator()
        self.queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=queue_maxsize)
        self.total_events_read = 0
        self.flow_events_read = 0
        self.tls_events_read = 0
        self.alert_events_read = 0
        self.malformed_lines = 0
        self.flows_emitted = 0
        self.queue_dropped = 0
        self.start_time: Optional[float] = None

    async def start(self, **kwargs) -> None:
        self.state = "CAPTURING"
        self.start_time = time.time()
        logger.info("SuricataEventSource started (EVE log parsing; no Suricata process is managed).")

    async def stop(self) -> None:
        self.state = "STOPPED"
        self.correlator.flush_pending()
        logger.info("SuricataEventSource stopped.")

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parses one eve.json line; returns the canonical flow if this line finalised one."""
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#"):
            return None
        self.total_events_read += 1
        try:
            event = json.loads(line_clean)
            if not isinstance(event, dict):
                raise ValueError("not a JSON object")
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
            if self.queue.full():
                self.queue_dropped += 1
            else:
                self.queue.put_nowait(flow)
        return flow

    async def ingest_file(self, file_path: Path) -> int:
        """Reads a whole eve.json file. Returns the number of flows finalised while reading it."""
        flows_before = self.flows_emitted
        if not file_path.exists():
            logger.error("Suricata EVE log file not found: %s", file_path.name)
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
        elapsed = round(time.time() - self.start_time, 2) if (self.start_time and self.state == "CAPTURING") else 0.0
        return {
            "status": self.state,
            "sensor": "SURICATA",
            "mode": "LOG_PARSING",
            "total_events_read": self.total_events_read,
            "flow_events_read": self.flow_events_read,
            "tls_events_read": self.tls_events_read,
            "alert_events_read": self.alert_events_read,
            "malformed_lines": self.malformed_lines,
            "flows_emitted": self.flows_emitted,
            "queue_depth": self.queue.qsize(),
            "queue_dropped": self.queue_dropped,
            "active_correlations": len(self.correlator._cache),
            "correlator": dict(self.correlator.stats),
            "elapsed_seconds": elapsed,
        }
