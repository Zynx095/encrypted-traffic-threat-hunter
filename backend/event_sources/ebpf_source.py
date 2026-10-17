"""
ETTH eBPF Telemetry Adapter & Event Contract (Phase 11, reconciled with the Phase 8-10 canonical flow contract)

What this module is:
* a JSON event contract for an EXTERNAL eBPF collector (one flow/socket summary per event), and
* an adapter that validates those events and normalises them into canonical ETTH flow dicts;
* a capability probe that reports whether this host could attach eBPF programs.

What it is NOT: ETTH ships no eBPF program, loader or kernel probe. Parsing JSON events (for
example the synthetic fixture) exercises the adapter only; it is not evidence that native
kernel attachment works. `detect_ebpf_capability()` keeps the two apart.

Contract rules (pipeline.canonical_flow):
* durations come in nanoseconds (`duration_ns`, or `end_ns - start_ns`) or seconds
  (`flow_duration`); a missing duration stays None and no rate is computed from it;
* byte counters have collector-defined meaning unless the event declares
  `byte_count_semantics` (IP_LENGTH, LINK_LAYER_FRAME, TRANSPORT_PAYLOAD);
* `ja3_hash`/`ja3` must be an MD5 hex digest or a complete JA3 string (hashed with MD5);
  anything else is rejected with a reason;
* JA4 is kept with the implementation the collector declares (`ja4_implementation`), else
  UNKNOWN, so models trained on ETTH JA4 refuse it;
* TLS version and ALPN have collector-defined meaning and never populate the ETTH model
  features `tls_version` / `alpn_value`;
* flow statistics are tagged `feature_provenance=SENSOR_AGGREGATE`.
"""

import asyncio
import json
import logging
import os
import platform
import time
from typing import Any, Dict, Optional

from backend.event_sources.base import EventSource
from pipeline.canonical_flow import (BYTE_SEMANTICS, BYTES_UNKNOWN, FEATURE_PROVENANCE_SENSOR, JA4_IMPLEMENTATION_ETTH,
                                     JA4_IMPLEMENTATION_FOXIO, JA4_IMPLEMENTATION_UNKNOWN, SUPPORTED_PROTOCOLS,
                                     RecentKeys, as_float, as_int, clean_str, count_features, endpoint,
                                     normalize_ja3, normalize_ja4, protocol_name, tls_version_label)

logger = logging.getLogger(__name__)

_JA4_IMPLEMENTATIONS = {JA4_IMPLEMENTATION_ETTH, JA4_IMPLEMENTATION_FOXIO}


def detect_ebpf_capability() -> Dict[str, Any]:
    """
    Reports whether this host could attach native eBPF programs. Never raises.
    `available` keeps its Phase 11 meaning (kernel capability), and `native_probe_included`
    states that ETTH itself ships no probe. The JSON adapter works on every platform.
    """
    system = platform.system()
    base = {"adapter_available": True, "native_probe_included": False,
            "collector": "external collector required (none shipped with ETTH)",
            "kernel_version": platform.release(), "os": system}
    if system.lower() != "linux":
        return {**base, "available": False, "btf_available": False, "privileges": "N/A",
                "reason": (f"Native eBPF kernel probes require Linux (current OS: {system}). "
                           "Events from an external collector can still be parsed as JSON.")}
    has_btf = os.path.exists("/sys/kernel/btf/vmlinux")
    is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
    available = has_btf and is_root
    return {**base, "available": available, "btf_available": has_btf,
            "privileges": "root" if is_root else "unprivileged (CAP_BPF not checked)",
            "reason": None if available else "Root and /sys/kernel/btf/vmlinux are required for native attachment."}


class EBPFEventSource(EventSource):
    """Validates and normalises JSON flow events produced by an external eBPF collector."""

    def __init__(self, queue_maxsize: int = 5000, dedup_window: int = 100_000):
        super().__init__(mode="LIVE")
        self.state: str = "IDLE"
        self.queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=queue_maxsize)
        self.capabilities = detect_ebpf_capability()
        self._emitted = RecentKeys(dedup_window)
        self.events_received = 0
        self.flows_emitted = 0
        self.malformed_events = 0
        self.unsupported_events = 0
        self.duplicate_events = 0
        self.queue_dropped = 0
        self.start_time: Optional[float] = None

    async def start(self, **kwargs) -> None:
        self.state = "CAPTURING"
        self.start_time = time.time()
        logger.info("EBPFEventSource started (JSON adapter). Native attachment possible on this host: %s",
                    self.capabilities["available"])

    async def stop(self) -> None:
        self.state = "STOPPED"
        logger.info("EBPFEventSource stopped.")

    @staticmethod
    def _duration(event: Dict[str, Any]) -> Optional[float]:
        if as_float(event.get("duration_ns")) is not None:
            return as_float(event["duration_ns"]) / 1e9
        start, end = as_int(event.get("start_ns")), as_int(event.get("end_ns"))
        if start is not None and end is not None and end >= start:
            return (end - start) / 1e9
        return as_float(event.get("flow_duration"))

    def parse_event(self, event_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Validates one collector event; returns the canonical flow dict, or None (counted)."""
        self.events_received += 1
        if not isinstance(event_data, dict):
            self.malformed_events += 1
            return None
        saddr = clean_str(event_data.get("saddr") or event_data.get("src_ip"))
        daddr = clean_str(event_data.get("daddr") or event_data.get("dest_ip"))
        sport = as_int(event_data.get("sport") if event_data.get("sport") is not None else event_data.get("src_port"))
        dport = as_int(event_data.get("dport") if event_data.get("dport") is not None else event_data.get("dest_port"))
        if not saddr or not daddr or not (sport and 0 < sport < 65536) or not (dport and 0 < dport < 65536):
            self.malformed_events += 1
            return None
        protocol = protocol_name(event_data.get("protocol") if event_data.get("protocol") is not None
                                 else event_data.get("proto"))
        if protocol not in SUPPORTED_PROTOCOLS:
            self.unsupported_events += 1
            return None

        reported_id = clean_str(event_data.get("flow_id"))
        if reported_id and reported_id in self._emitted:
            self.duplicate_events += 1
            return None

        duration = self._duration(event_data)
        ja3, ja3_derivation, ja3_reason = normalize_ja3(event_data.get("ja3_hash") or event_data.get("ja3"),
                                                        event_data.get("ja3_string"))
        ja4, ja4_reason = normalize_ja4(event_data.get("ja4"))
        declared_impl = clean_str(event_data.get("ja4_implementation"))
        sni = clean_str(event_data.get("tls_sni") or event_data.get("sni"))
        semantics = clean_str(event_data.get("byte_count_semantics"))
        start_ns = as_int(event_data.get("start_ns"))
        pid = as_int(event_data.get("pid"))

        flow: Dict[str, Any] = {
            "flow_id": reported_id or f"ebpf_{saddr}_{sport}_{daddr}_{dport}_{pid if pid is not None else 'net'}_{start_ns}",
            "dataset_id": "EBPF_OBSERVABILITY",
            "source_file": None,
            "label": "UNKNOWN",
            "protocol": protocol,
            "forward_endpoint": endpoint(saddr, sport),
            "reverse_endpoint": endpoint(daddr, dport),
            "source_ip": saddr, "source_port": sport, "destination_ip": daddr, "destination_port": dport,
            **count_features(duration,
                             as_int(event_data.get("packets_sent") if event_data.get("packets_sent") is not None else event_data.get("tx_packets")),
                             as_int(event_data.get("packets_recv") if event_data.get("packets_recv") is not None else event_data.get("rx_packets")),
                             as_int(event_data.get("bytes_sent") if event_data.get("bytes_sent") is not None else event_data.get("tx_bytes")),
                             as_int(event_data.get("bytes_recv") if event_data.get("bytes_recv") is not None else event_data.get("rx_bytes"))),
            "feature_provenance": FEATURE_PROVENANCE_SENSOR,
            "byte_count_semantics": semantics if semantics in BYTE_SEMANTICS else BYTES_UNKNOWN,
            "sensor_type": "EBPF",
            "sensor_record_id": reported_id,
            "process_pid": pid,
            "process_name": clean_str(event_data.get("comm")),
            "clienthello_present": bool(ja3 or ja4 or sni),
            "serverhello_present": event_data.get("serverhello_present") is True,
            "sni": sni.lower() if sni else None,
            "sni_present": bool(sni),
            "ja3_hash": ja3, "ja3_derivation": ja3_derivation, "ja3_rejected_reason": ja3_reason,
            "ja3s_hash": None,
            "ja4": ja4,
            "ja4_implementation": (declared_impl if declared_impl in _JA4_IMPLEMENTATIONS else JA4_IMPLEMENTATION_UNKNOWN) if ja4 else None,
            "ja4_rejected_reason": ja4_reason,
            "tls_version_observed": tls_version_label(event_data.get("tls_version")),
            "tls_version_semantics": "COLLECTOR_DEFINED" if tls_version_label(event_data.get("tls_version")) else None,
            "sensor_alpn": clean_str(event_data.get("alpn")),
        }
        if reported_id:
            self._emitted.add(reported_id)
        self.flows_emitted += 1
        if self.queue.full():
            self.queue_dropped += 1
        else:
            self.queue.put_nowait(flow)
        return flow

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#"):
            return None
        try:
            data = json.loads(line_clean)
        except Exception:
            self.events_received += 1
            self.malformed_events += 1
            return None
        return self.parse_event(data)

    async def get_next_flow(self, timeout: float = 0.5) -> Optional[Dict[str, Any]]:
        try:
            return await asyncio.wait_for(self.queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def get_status(self) -> Dict[str, Any]:
        elapsed = round(time.time() - self.start_time, 2) if (self.start_time and self.state == "CAPTURING") else 0.0
        return {
            "status": self.state,
            "sensor": "EBPF",
            "mode": "JSON_EVENT_PARSING",
            "native_ebpf_available": self.capabilities["available"],
            "native_probe_included": False,
            "os_environment": self.capabilities["os"],
            "environment_limitation": self.capabilities.get("reason"),
            "events_received": self.events_received,
            "flows_emitted": self.flows_emitted,
            "malformed_events": self.malformed_events,
            "unsupported_events": self.unsupported_events,
            "duplicate_events": self.duplicate_events,
            "queue_depth": self.queue.qsize(),
            "queue_dropped": self.queue_dropped,
            "elapsed_seconds": elapsed,
        }
