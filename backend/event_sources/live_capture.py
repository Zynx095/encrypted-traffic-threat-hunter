import asyncio
import logging
import time
import uuid
import threading
from typing import Dict, Any, Optional, List, Callable, Tuple
from backend.event_sources.base import EventSource
from pipeline.canonical_flow import BYTES_IP_LENGTH, FEATURE_PROVENANCE_ETTH, JA4_IMPLEMENTATION_ETTH

logger = logging.getLogger(__name__)

# Safely check for Scapy availability
SCAPY_AVAILABLE = False
try:
    import scapy
    from scapy.all import sniff, get_if_list, IFACES, IP, IPv6, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    scapy = None


def detect_live_capture_capability() -> Dict[str, Any]:
    """
    Detects local packet capture capabilities (Scapy / Npcap / WinPcap).
    Returns structured status dict. Does not crash if capture drivers are missing.
    """
    if not SCAPY_AVAILABLE:
        return {
            "available": False,
            "error": "Scapy library is not installed in Python environment.",
            "interfaces": [],
            "library": None
        }

    try:
        interfaces = get_available_interfaces()
        # Interface enumeration works without a capture driver; sniffing does not. Scapy installs a
        # placeholder socket class when libpcap/Npcap is missing (e.g. "wpcap.dll missing").
        listener = getattr(scapy.all.conf, "L2listen", None)
        if getattr(listener, "__name__", "") == "_NotAvailableSocket":
            return {
                "available": False,
                "error": f"Packet capture driver unavailable ({str(listener).strip('<>')}). Install Npcap (Windows) or libpcap.",
                "interfaces": interfaces,
                "library": f"Scapy {getattr(scapy, '__version__', '2.7.0')}"
            }
        return {
            "available": True,
            "error": None,
            "interfaces": interfaces,
            "library": f"Scapy {getattr(scapy, '__version__', '2.7.0')}"
        }
    except Exception as e:
        logger.warning(f"Live capture driver detection warning: {e}")
        return {
            "available": False,
            "error": f"Live capture initialization error: {str(e)}. Npcap driver or Administrator privileges required on Windows.",
            "interfaces": [],
            "library": f"Scapy {getattr(scapy, '__version__', '2.7.0')}"
        }


def get_available_interfaces() -> List[Dict[str, Any]]:
    """
    Enumerates available network capture interfaces on Windows/Linux.
    """
    if not SCAPY_AVAILABLE:
        return []

    interfaces = []
    try:
        if hasattr(scapy.all, "IFACES") and getattr(scapy.all, "IFACES"):
            for iface_name, iface_obj in scapy.all.IFACES.items():
                name = getattr(iface_obj, "name", str(iface_name))
                description = getattr(iface_obj, "description", name)
                win_name = getattr(iface_obj, "win_name", name)
                ip = getattr(iface_obj, "ip", "0.0.0.0") or "0.0.0.0"
                interfaces.append({
                    "id": win_name or name,
                    "name": description or name,
                    "win_name": win_name or name,
                    "ip": ip
                })
    except Exception as e:
        logger.debug(f"Failed to query IFACES dict: {e}")

    if not interfaces:
        try:
            for iface_name in scapy.all.get_if_list():
                interfaces.append({
                    "id": str(iface_name),
                    "name": str(iface_name),
                    "win_name": str(iface_name),
                    "ip": "0.0.0.0"
                })
        except Exception as e:
            logger.warning(f"Failed get_if_list: {e}")

    return interfaces


LIVE_FEATURE_WINDOW = 5000   # packets kept per flow for feature computation (bounded memory)
# Flow boundaries follow the offline reconstructor (pipeline.flow_reconstruction): a packet that
# arrives after FIN/RST, or more than DEFAULT_FLOW_IDLE_TIMEOUT (120 s) after the previous packet,
# starts a new flow. Live capture additionally splits flows at LIVE_MAX_FLOW_DURATION so results
# appear in bounded time; split segments are flagged (live_flow_split) and flow-feature models
# refuse them, because the offline pipeline would not have split them.
LIVE_MAX_FLOW_DURATION = 300.0


class LiveFlowTracker:
    """
    Stateful 5-Tuple Flow Aggregator for Live Traffic.
    Keeps per-packet sizes, relative times, directions and TCP flags (header metadata only, no
    payload bytes) for up to LIVE_FEATURE_WINDOW packets and computes features with the SAME
    functions as the offline pipeline (pipeline.feature_extraction), so live and training
    features share one definition. Flows longer than the window are flagged
    (live_feature_window_truncated) instead of being silently approximated.
    Enforces ZERO payload retention and ZERO payload decryption.
    """
    def __init__(self, key: Tuple, src_ep: str, dst_ep: str, proto: str, start_time: float,
                 forward_tuple: Optional[Tuple[str, int]] = None):
        self.key = key
        self.flow_id = f"live_flow_{uuid.uuid4().hex[:10]}"
        # Forward = initiator = source of the first packet seen, as offline (Flow.forward_ep).
        self.forward_endpoint = src_ep
        self.reverse_endpoint = dst_ep
        self.forward_tuple = forward_tuple
        self.split = False          # this segment was cut at LIVE_MAX_FLOW_DURATION or continues a cut flow
        self.protocol = proto
        self.start_time = start_time
        self.last_seen = start_time

        self.forward_packets = 0
        self.reverse_packets = 0
        self.forward_bytes = 0
        self.reverse_bytes = 0

        self.packet_lengths: List[int] = []
        self.relative_times: List[float] = []
        self.directions: List[int] = []
        self.tcp_flags: List[int] = []
        self.window_truncated = False

        self.clienthello_present = False
        self.serverhello_present = False
        self.sni_present = False
        self.alpn_value: Optional[str] = None
        self.ja3_hash: Optional[str] = None
        self.ja3_string: Optional[str] = None
        self.ja3s_hash: Optional[str] = None
        self.ja3s_string: Optional[str] = None
        self.ja4: Optional[str] = None
        self.ja4_v2: Optional[str] = None
        self.ja4_implementation: Optional[str] = None
        self.ja4_version: Optional[str] = None
        self.tls_version: Optional[float] = None
        self.clienthello_record_truncated: Optional[bool] = None
        self.has_fin_rst = False

    def update(self, is_forward: bool, pkt_len: int, timestamp: float, fin_or_rst: bool = False,
               tls_meta: Optional[Dict[str, Any]] = None, tcp_flags: int = -1):
        self.last_seen = timestamp
        if is_forward:
            self.forward_packets += 1
            self.forward_bytes += pkt_len
        else:
            self.reverse_packets += 1
            self.reverse_bytes += pkt_len

        if len(self.packet_lengths) < LIVE_FEATURE_WINDOW:
            self.packet_lengths.append(int(pkt_len))
            self.relative_times.append(max(0.0, float(timestamp - self.start_time)))
            self.directions.append(1 if is_forward else -1)
            self.tcp_flags.append(int(tcp_flags))
        else:
            self.window_truncated = True

        if fin_or_rst:
            self.has_fin_rst = True

        if tls_meta:
            # First valid ClientHello / ServerHello only, mirroring the offline policy.
            if tls_meta.get("clienthello_present") and not self.clienthello_present and tls_meta.get("ja3_hash"):
                self.clienthello_present = True
                self.sni_present = bool(tls_meta.get("sni"))
                self.alpn_value = tls_meta.get("alpn") or None
                self.ja3_hash = tls_meta.get("ja3_hash")
                self.ja3_string = tls_meta.get("ja3_string")
                self.ja4 = tls_meta.get("ja4")
                self.ja4_v2 = tls_meta.get("ja4_v2")
                self.ja4_implementation = tls_meta.get("ja4_implementation")
                self.ja4_version = tls_meta.get("ja4_version")
                self.tls_version = tls_meta.get("tls_version")
                self.clienthello_record_truncated = tls_meta.get("clienthello_record_truncated")
            if tls_meta.get("serverhello_present") and not self.serverhello_present and tls_meta.get("ja3s_hash"):
                self.serverhello_present = True
                self.ja3s_hash = tls_meta.get("ja3s_hash")
                self.ja3s_string = tls_meta.get("ja3s_string")

    def is_finalized(self, now: float, idle_timeout: Optional[float] = None,
                     max_duration: float = LIVE_MAX_FLOW_DURATION) -> bool:
        if idle_timeout is None:
            from pipeline.flow_reconstruction import DEFAULT_FLOW_IDLE_TIMEOUT
            idle_timeout = DEFAULT_FLOW_IDLE_TIMEOUT
        if self.has_fin_rst:
            return True
        if (now - self.last_seen) >= idle_timeout:
            return True
        if (now - self.start_time) >= max_duration:
            return True
        return False

    def to_flow_dict(self) -> Dict[str, Any]:
        from pipeline.feature_extraction import (extract_burst_features, extract_flow_level_features,
                                                 extract_iat_features, extract_packet_length_features)
        total_pkts = self.forward_packets + self.reverse_packets
        total_bytes = self.forward_bytes + self.reverse_bytes
        duration = self.last_seen - self.start_time      # unrounded, as offline (Flow.to_dict)
        base = {
            "duration": duration, "packet_count": total_pkts, "forward_packet_count": self.forward_packets,
            "reverse_packet_count": self.reverse_packets, "byte_count": total_bytes,
            "forward_byte_count": self.forward_bytes, "reverse_byte_count": self.reverse_bytes,
            "packet_lengths": self.packet_lengths, "relative_times": self.relative_times,
            "direction_sequence": self.directions,
        }
        record: Dict[str, Any] = {
            "flow_id": self.flow_id,
            "dataset_id": "LIVE_CAPTURE",
            "source_file": "live_interface",
            "forward_endpoint": self.forward_endpoint,
            "reverse_endpoint": self.reverse_endpoint,
            "protocol": self.protocol,
        }
        record.update(extract_flow_level_features(base))
        record.update(extract_packet_length_features(base))
        record.update(extract_iat_features(base))
        record.update(extract_burst_features(base))
        record.update({
            "clienthello_present": self.clienthello_present,
            "serverhello_present": self.serverhello_present,
            "sni_present": self.sni_present,
            "alpn_value": self.alpn_value,
            "ja3_hash": self.ja3_hash,
            "ja3_string": self.ja3_string,
            "ja3s_hash": self.ja3s_hash,
            "ja3s_string": self.ja3s_string,
            "ja4": self.ja4,
            "ja4_v2": self.ja4_v2,
            "tls_version": self.tls_version,
            "clienthello_record_truncated": self.clienthello_record_truncated,
            "live_feature_window_truncated": self.window_truncated,
            "live_feature_window": LIVE_FEATURE_WINDOW,
            "live_flow_split": self.split,
            "start_time": self.start_time,
            "end_time": self.last_seen,
            "feature_provenance": FEATURE_PROVENANCE_ETTH,
            "byte_count_semantics": BYTES_IP_LENGTH,
            "ja4_implementation": self.ja4_implementation or (JA4_IMPLEMENTATION_ETTH if self.ja4 else None),
            "ja4_version": self.ja4_version or ("v1_legacy" if self.ja4 else None),
            "label": "UNKNOWN",
        })
        return record


class LiveCaptureSource(EventSource):
    """
    Live Network Packet Capture Adapter.
    Performs non-blocking packet acquisition, 5-tuple flow aggregation,
    and observable TLS handshake parsing. Emits finalized flows to a callback.
    """
    def __init__(self, idle_timeout: Optional[float] = None, max_duration: float = LIVE_MAX_FLOW_DURATION):
        super().__init__(mode="LIVE")
        from pipeline.flow_reconstruction import DEFAULT_FLOW_IDLE_TIMEOUT
        self.idle_timeout = DEFAULT_FLOW_IDLE_TIMEOUT if idle_timeout is None else idle_timeout
        self.max_duration = max_duration
        self._lock = threading.Lock()
        self._closed: List[LiveFlowTracker] = []          # rotated out by a new packet, awaiting emission
        self._split_last_seen: Dict[Tuple, float] = {}    # key -> last packet time of a segment cut at max_duration
        self.state: str = "STOPPED"
        self.selected_interface: Optional[str] = None
        self.packets_observed: int = 0
        self.active_flows: Dict[Tuple, LiveFlowTracker] = {}
        self.finalized_flows_count: int = 0
        self.capture_errors: int = 0
        self.start_time: Optional[float] = None
        self.error_message: Optional[str] = None
        
        self.stop_event = threading.Event()
        self.capture_thread: Optional[threading.Thread] = None
        self.sweep_task: Optional[asyncio.Task] = None
        self.callback: Optional[Callable[[Dict[str, Any]], None]] = None

    def parse_tls_metadata(self, raw_payload: bytes) -> Optional[Dict[str, Any]]:
        """
        Parses an unencrypted TLS ClientHello / ServerHello in a single TCP segment with the SAME
        parser and fingerprint functions as the offline pipeline (pipeline.tls_fingerprinting).
        Returns None for non-handshake payloads. If a handshake record cannot be parsed, the
        fingerprint fields are None and `fingerprint_error` explains why; no fingerprint is
        ever synthesised. ZERO payload decryption or retention.
        """
        from pipeline.tls_fingerprinting import (generate_ja3, generate_ja3s, generate_ja4,
                                                 parse_client_hello, parse_server_hello)
        if not raw_payload or len(raw_payload) < 6 or raw_payload[0] != 0x16:
            return None
        handshake_type = raw_payload[5]
        meta: Dict[str, Any] = {}
        if handshake_type == 0x01:
            meta["clienthello_present"] = True
            ch = parse_client_hello(raw_payload)
            if ch.get("error"):
                meta.update(ja3_hash=None, ja3_string=None, ja4=None, fingerprint_error=ch["error"])
            else:
                ja3_string, ja3_hash = generate_ja3(ch)
                record_len = int.from_bytes(raw_payload[3:5], "big")
                meta.update(
                    ja3_hash=ja3_hash,
                    ja3_string=ja3_string,
                    ja4=generate_ja4(ch, version="v1_legacy"),
                    ja4_v2=generate_ja4(ch, version="v2_foxio"),
                    ja4_implementation=JA4_IMPLEMENTATION_ETTH,
                    ja4_version="v1_legacy",
                    sni=ch["sni_present"],
                    alpn=ch["alpn_str"] or None,
                    tls_version=1.3 if ch["has_supported_versions"] else 1.2,
                    clienthello_record_truncated=(5 + record_len) > len(raw_payload)
                )
        elif handshake_type == 0x02:
            meta["serverhello_present"] = True
            sh = parse_server_hello(raw_payload)
            if sh.get("error"):
                meta.update(ja3s_hash=None, ja3s_string=None, fingerprint_error=sh["error"])
            else:
                ja3s_string, ja3s_hash = generate_ja3s(sh)
                meta.update(ja3s_hash=ja3s_hash, ja3s_string=ja3s_string)
        return meta or None

    def _process_packet(self, pkt: Any):
        """
        Processes an individual captured packet frame.
        Performs 5-tuple normalization and passes stats to active flow tracker.
        Immediately discards payload (zero payload storage).
        """
        self.packets_observed += 1
        now = float(getattr(pkt, "time", None) or time.time())  # capture timestamp when available

        try:
            if not SCAPY_AVAILABLE:
                return

            if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
                return

            ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto_num = ip_layer.proto if pkt.haslayer(IP) else ip_layer.nh

            fin_or_rst = False
            tcp_flag_value = -1

            # Only TCP and UDP flows are reconstructed, as offline (other protocols are ignored).
            if pkt.haslayer(TCP):
                transport = pkt[TCP]
                proto_str = "TCP"
                flags = int(getattr(transport, "flags", 0))
                tcp_flag_value = flags
                # Check FIN (0x01) or RST (0x04)
                if flags and (flags & 0x01 or flags & 0x04):
                    fin_or_rst = True
                header_len = int(transport.dataofs or 5) * 4
            elif pkt.haslayer(UDP):
                transport = pkt[UDP]
                proto_str = "UDP"
                header_len = 8
            else:
                return
            src_port = transport.sport
            dst_port = transport.dport

            # IP length from the header, matching the offline pipeline (dpkt len(ip)). len(ip_layer)
            # would also count Ethernet trailer padding that scapy attaches to short frames.
            if pkt.haslayer(IP):
                pkt_len = int(ip_layer.len)
                ip_payload_len = pkt_len - int(ip_layer.ihl) * 4
            else:
                pkt_len = 40 + int(ip_layer.plen)
                ip_payload_len = int(ip_layer.plen)
            payload_len = max(0, ip_payload_len - header_len)

            # Canonical (direction-independent) 5-tuple key, used for lookup only.
            endpoint_a = (src_ip, src_port)
            endpoint_b = (dst_ip, dst_port)
            if endpoint_a <= endpoint_b:
                canonical_key = (src_ip, src_port, dst_ip, dst_port, proto_num)
            else:
                canonical_key = (dst_ip, dst_port, src_ip, src_port, proto_num)

            # TLS metadata extraction (unencrypted handshakes only). Transport payload bytes, without
            # Ethernet padding, exactly as offline (dpkt transport.data).
            tls_meta = None
            if payload_len >= 6:
                tls_meta = self.parse_tls_metadata(bytes(transport.payload)[:payload_len])

            with self._lock:
                flow_tracker = self.active_flows.get(canonical_key)
                if flow_tracker is not None and (flow_tracker.has_fin_rst or (now - flow_tracker.last_seen) > self.idle_timeout):
                    # Offline semantics: a packet after FIN/RST or after the idle timeout starts a new flow.
                    self._closed.append(self.active_flows.pop(canonical_key))
                    flow_tracker = None
                if flow_tracker is None:
                    flow_tracker = LiveFlowTracker(
                        key=canonical_key,
                        src_ep=f"{src_ip}:{src_port}",
                        dst_ep=f"{dst_ip}:{dst_port}",
                        proto=proto_str,
                        start_time=now,
                        forward_tuple=(src_ip, src_port),
                    )
                    cut = self._split_last_seen.pop(canonical_key, None)
                    if cut is not None and (now - cut) <= self.idle_timeout:
                        flow_tracker.split = True      # continuation of a flow cut at max_duration
                    self.active_flows[canonical_key] = flow_tracker
                is_forward = (src_ip, src_port) == flow_tracker.forward_tuple

            flow_tracker.update(
                is_forward=is_forward,
                pkt_len=pkt_len,
                timestamp=now,
                fin_or_rst=fin_or_rst,
                tls_meta=tls_meta,
                tcp_flags=tcp_flag_value
            )

        except Exception as e:
            self.capture_errors += 1
            logger.debug(f"Error parsing packet frame: {e}")

    def _sniffer_loop(self, iface: Optional[str]):
        """
        Background sniffer thread execution using Scapy.
        Sets store=False to guarantee zero packet payload memory retention.
        """
        try:
            sniff(
                iface=iface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda p: self.stop_event.is_set()
            )
        except Exception as e:
            self.capture_errors += 1
            self.error_message = str(e)
            self.state = "ERROR"
            logger.error(f"Live capture thread failure: {e}")

    async def _sweep_flows_loop(self):
        """
        Periodic async sweeper task checking for finalized flows (FIN/RST, idle timeout).
        Finalized flows are emitted to the callback and evicted from active_flows.
        """
        while self.state == "CAPTURING":
            await asyncio.sleep(1.0)
            for flow_dict in self.drain_finalized(time.time()):
                await self._deliver(flow_dict)

    def drain_finalized(self, now: float, force: bool = False) -> List[Dict[str, Any]]:
        """
        Removes and returns finished flows: those rotated out by a new packet, those closed by
        FIN/RST (offline semantics: no later packet can join them), idle ones, and segments cut at
        max_duration (flagged live_flow_split). force=True drains everything (stop()).
        """
        with self._lock:
            done = list(self._closed)
            self._closed.clear()
            for key, flow in list(self.active_flows.items()):
                if force or flow.is_finalized(now=now, idle_timeout=self.idle_timeout, max_duration=self.max_duration):
                    if not force and not flow.has_fin_rst and (now - flow.last_seen) < self.idle_timeout:
                        flow.split = True                         # cut at max_duration while still active
                        self._split_last_seen[key] = flow.last_seen
                    done.append(self.active_flows.pop(key))
        self.finalized_flows_count += len(done)
        return [flow.to_flow_dict() for flow in done]

    async def _deliver(self, flow_dict: Dict[str, Any]) -> None:
        if not self.callback:
            return
        try:
            if asyncio.iscoroutinefunction(self.callback):
                await self.callback(flow_dict)
            else:
                self.callback(flow_dict)
        except Exception as cb_err:
            logger.error(f"Error in live flow callback: {cb_err}")

    async def start(self, interface: Optional[str] = None, callback: Optional[Callable] = None):
        """
        Starts live packet capture on specified interface.
        """
        cap = detect_live_capture_capability()
        if not cap["available"]:
            self.state = "CAPTURE_UNAVAILABLE"
            self.error_message = cap["error"]
            logger.warning(f"Live capture start failed: {self.error_message}")
            return

        if self.state == "CAPTURING":
            logger.info("LiveCaptureSource is already CAPTURING.")
            return

        self.selected_interface = interface or (cap["interfaces"][0]["id"] if cap["interfaces"] else None)
        self.callback = callback
        self.state = "CAPTURING"
        self.packets_observed = 0
        self.active_flows.clear()
        self._closed.clear()
        self._split_last_seen.clear()
        self.finalized_flows_count = 0
        self.capture_errors = 0
        self.error_message = None
        self.start_time = time.time()
        self.stop_event.clear()

        logger.info(f"Starting LiveCaptureSource on interface='{self.selected_interface}'")

        # Launch background sniffer thread
        self.capture_thread = threading.Thread(
            target=self._sniffer_loop,
            args=(self.selected_interface,),
            daemon=True
        )
        self.capture_thread.start()

        # Launch async flow sweeper loop
        if self.sweep_task is None or self.sweep_task.done():
            self.sweep_task = asyncio.create_task(self._sweep_flows_loop())

    async def stop(self):
        """
        Stops live capture cleanly and flushes remaining active flows.
        """
        if self.state in ["STOPPED", "CAPTURE_UNAVAILABLE"]:
            return

        self.state = "STOPPED"
        self.stop_event.set()
        logger.info(f"Stopping LiveCaptureSource on interface='{self.selected_interface}'")

        if self.sweep_task and not self.sweep_task.done():
            self.sweep_task.cancel()

        # Flush any remaining active flows to callback
        for flow_dict in self.drain_finalized(time.time(), force=True):
            await self._deliver(flow_dict)

    def get_status(self) -> Dict[str, Any]:
        elapsed = round(time.time() - self.start_time, 2) if (self.start_time and self.state == "CAPTURING") else 0.0
        return {
            "status": self.state,
            "mode": "LIVE",
            "selected_interface": self.selected_interface,
            "packets_observed": self.packets_observed,
            "active_flows": len(self.active_flows),
            "finalized_flows": self.finalized_flows_count,
            "capture_errors": self.capture_errors,
            "error_message": self.error_message,
            "elapsed_seconds": elapsed
        }
