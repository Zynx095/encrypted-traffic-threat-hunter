"""
ETTH eBPF Sensor Ingestion Adapter & Event Contract (Phase 11)
Defines the canonical eBPF kernel telemetry interface, ring buffer schema,
and adapter for ingesting eBPF socket/flow events into ETTH zero-decryption detection.

Operational Boundary & Disclaimer:
- Native eBPF programs require Linux kernel 5.8+ with BTF and root / CAP_BPF privileges.
- On Windows, native kernel probes are unsupported without eBPF for Windows preview or Linux VM/WSL2.
- This module provides the production ingestion adapter and contract interface for eBPF collectors.
- Zero payload decryption is performed; missing TLS fingerprints remain None.
"""

import os
import json
import time
import platform
import logging
import asyncio
from typing import Dict, Any, Optional, List

from backend.event_sources.base import EventSource

logger = logging.getLogger(__name__)


def detect_ebpf_capability() -> Dict[str, Any]:
    """
    Checks whether the local operating system and kernel support native eBPF tracing.
    Returns structured diagnostic status. Does not crash on Windows/unsupported platforms.
    """
    system = platform.system().lower()
    if system != "linux":
        return {
            "available": False,
            "os": platform.system(),
            "reason": (
                f"Native eBPF kernel probes require Linux (current OS: {platform.system()}). "
                "Deploy on Linux kernel >= 5.8 or use a containerized collector sending JSON telemetry."
            ),
            "kernel_version": platform.release(),
            "btf_available": False,
            "privileges": "N/A"
        }

    # Check Linux kernel and BTF
    btf_path = "/sys/kernel/btf/vmlinux"
    has_btf = os.path.exists(btf_path)
    is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False

    available = has_btf and is_root
    reason = None if available else (
        "Root / CAP_BPF privileges and /sys/kernel/btf/vmlinux required for native kernel attachment."
    )

    return {
        "available": available,
        "os": "Linux",
        "reason": reason,
        "kernel_version": platform.release(),
        "btf_available": has_btf,
        "privileges": "root" if is_root else "unprivileged"
    }


class EBPFEventSource(EventSource):
    """
    eBPF Flow & Socket Telemetry Event Source Adapter for ETTH.
    Ingests normalized ring-buffer events emitted by eBPF user-space collectors.
    """
    def __init__(self, queue_maxsize: int = 5000):
        super().__init__(mode="LIVE")
        self.state: str = "IDLE"
        self.queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=queue_maxsize)
        self.capabilities = detect_ebpf_capability()

        # Operational counters
        self.events_received = 0
        self.flows_emitted = 0
        self.malformed_events = 0
        self.unsupported_events = 0
        self.start_time: Optional[float] = None

    async def start(self, **kwargs) -> None:
        self.state = "CAPTURING"
        self.start_time = time.time()
        logger.info(
            f"EBPFEventSource started. Native eBPF probe availability: {self.capabilities['available']} "
            f"({self.capabilities.get('reason') or 'Fully Supported'})"
        )

    async def stop(self) -> None:
        self.state = "STOPPED"
        logger.info("EBPFEventSource stopped.")

    def parse_event(self, event_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Validates an incoming eBPF ring-buffer event and normalizes it to a canonical ETTH flow dict.
        """
        self.events_received += 1
        try:
            # 1. Validate mandatory 5-tuple fields
            saddr = str(event_data.get("saddr") or event_data.get("src_ip") or "")
            daddr = str(event_data.get("daddr") or event_data.get("dest_ip") or "")
            sport = int(event_data.get("sport") or event_data.get("src_port") or 0)
            dport = int(event_data.get("dport") or event_data.get("dest_port") or 0)
            proto_val = event_data.get("protocol") or event_data.get("proto") or 6

            if not saddr or not daddr or sport <= 0 or dport <= 0:
                self.malformed_events += 1
                return None

            protocol = "TCP" if proto_val in [6, "TCP", "tcp"] else ("UDP" if proto_val in [17, "UDP", "udp"] else "TCP")

            # 2. Timing normalization (converts kernel nanoseconds to seconds)
            duration = 0.0
            if "duration_ns" in event_data:
                duration = float(event_data["duration_ns"]) / 1e9
            elif "start_ns" in event_data and "end_ns" in event_data:
                duration = max(0.0, float(event_data["end_ns"] - event_data["start_ns"]) / 1e9)
            elif "flow_duration" in event_data:
                duration = float(event_data["flow_duration"])

            # 3. Packet & byte counters
            bytes_sent = int(event_data.get("bytes_sent") or event_data.get("tx_bytes") or 0)
            bytes_recv = int(event_data.get("bytes_recv") or event_data.get("rx_bytes") or 0)
            pkts_sent = int(event_data.get("packets_sent") or event_data.get("tx_packets") or 0)
            pkts_recv = int(event_data.get("packets_recv") or event_data.get("rx_packets") or 0)

            total_packets = pkts_sent + pkts_recv
            total_bytes = bytes_sent + bytes_recv

            pps = (total_packets / duration) if duration > 0 else float(total_packets)
            bps = (total_bytes / duration) if duration > 0 else float(total_bytes)

            asym_pkts = (pkts_sent / max(1, pkts_recv)) if pkts_recv > 0 else float(pkts_sent)
            asym_bytes = (bytes_sent / max(1, bytes_recv)) if bytes_recv > 0 else float(bytes_sent)

            # Process context metadata from eBPF
            pid = event_data.get("pid")
            comm = str(event_data.get("comm") or "")

            fid = str(event_data.get("flow_id") or f"ebpf_{saddr}_{sport}_{daddr}_{dport}_{pid or 'net'}")

            # 4. Observable TLS metadata (strictly non-fabricated)
            sni = event_data.get("tls_sni") or event_data.get("sni")
            clean_sni = str(sni).strip().lower() if sni and str(sni).strip() not in ["", "-", "None"] else None

            ja3 = event_data.get("ja3_hash") or event_data.get("ja3")
            clean_ja3 = str(ja3).strip() if ja3 and str(ja3).strip() not in ["", "-", "None"] else None

            ja4 = event_data.get("ja4")
            clean_ja4 = str(ja4).strip() if ja4 and str(ja4).strip() not in ["", "-", "None"] else None

            flow_dict: Dict[str, Any] = {
                "flow_id": fid,
                "dataset_id": "EBPF_OBSERVABILITY",
                "protocol": protocol,
                "forward_endpoint": f"{saddr}:{sport}",
                "reverse_endpoint": f"{daddr}:{dport}",
                "source_ip": saddr,
                "source_port": sport,
                "destination_ip": daddr,
                "destination_port": dport,
                "flow_duration": duration,
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "forward_packets": pkts_sent,
                "reverse_packets": pkts_recv,
                "forward_bytes": bytes_sent,
                "reverse_bytes": bytes_recv,
                "packets_per_second": pps,
                "bytes_per_second": bps,
                "asymmetry_ratio_packets": asym_pkts,
                "asymmetry_ratio_bytes": asym_bytes,
                "sensor_type": "EBPF",
                "process_pid": pid,
                "process_name": comm,
                # TLS Metadata
                "clienthello_present": bool(clean_ja3 or clean_ja4 or clean_sni),
                "serverhello_present": bool(event_data.get("serverhello_present", False)),
                "sni": clean_sni,
                "sni_present": bool(clean_sni),
                "ja3_hash": clean_ja3,
                "ja3s_hash": None,
                "ja4": clean_ja4,
                "alpn_value": event_data.get("alpn"),
                "tls_version": event_data.get("tls_version"),
            }

            self.flows_emitted += 1
            if not self.queue.full():
                self.queue.put_nowait(flow_dict)

            return flow_dict
        except Exception as e:
            logger.warning(f"Error parsing eBPF event: {e}")
            self.malformed_events += 1
            return None

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        line_clean = line.strip()
        if not line_clean:
            return None
        try:
            data = json.loads(line_clean)
            return self.parse_event(data)
        except Exception:
            self.malformed_events += 1
            return None

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
            "sensor": "EBPF",
            "mode": "LIVE",
            "native_ebpf_available": self.capabilities["available"],
            "os_environment": self.capabilities["os"],
            "environment_limitation": self.capabilities.get("reason"),
            "events_received": self.events_received,
            "flows_emitted": self.flows_emitted,
            "malformed_events": self.malformed_events,
            "queue_depth": self.queue.qsize(),
            "elapsed_seconds": elapsed
        }
