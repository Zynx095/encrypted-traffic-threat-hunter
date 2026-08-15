"""
Phase 6 Step 4: Deterministic Bidirectional Flow Reconstruction
"""
import socket
import hashlib
from typing import Dict, List, Any, Tuple
import logging

import dpkt

logger = logging.getLogger(__name__)

# PENDING_PILOT_VALIDATION: Default idle timeout configuration
DEFAULT_FLOW_IDLE_TIMEOUT = 120.0

class Flow:
    def __init__(self, pcap_sha256: str, canonical_key: Tuple, instance: int, first_packet_ts: float, first_src_ep: Tuple):
        self.pcap_sha256 = pcap_sha256
        self.canonical_key = canonical_key
        self.instance = instance
        self.flow_id = self._generate_flow_id()

        self.start_time = first_packet_ts
        self.end_time = first_packet_ts
        self.forward_ep = first_src_ep
        self.reverse_ep = canonical_key[1] if canonical_key[0] == first_src_ep else canonical_key[0]

        self.packet_count = 0
        self.forward_packet_count = 0
        self.reverse_packet_count = 0
        self.byte_count = 0
        self.forward_byte_count = 0
        self.reverse_byte_count = 0

        self.packet_lengths = []
        self.forward_packet_lengths = []
        self.reverse_packet_lengths = []

        self.relative_times = []
        self.forward_relative_times = []
        self.reverse_relative_times = []

        self.direction_sequence = []
        self.tcp_flags_sequence = []

        # TLS association: 1 for TLS candidate, 0 for not
        self.tls_candidate_sequence = []

        # State
        self.closed_by_termination = False

    def _generate_flow_id(self) -> str:
        key_str = f"{self.pcap_sha256}_{self.canonical_key}_{self.instance}"
        return hashlib.sha256(key_str.encode()).hexdigest()

    def add_packet(self, ts: float, src_ep: Tuple, ip_len: int, tcp_flags: int, is_tls_candidate: bool):
        self.packet_count += 1
        self.byte_count += ip_len
        self.end_time = max(self.end_time, ts)

        rel_time = ts - self.start_time
        if rel_time < 0: rel_time = 0.0 # Safety

        self.packet_lengths.append(ip_len)
        self.relative_times.append(rel_time)
        self.tcp_flags_sequence.append(tcp_flags)
        self.tls_candidate_sequence.append(1 if is_tls_candidate else 0)

        if src_ep == self.forward_ep:
            direction = 1 # FORWARD
            self.forward_packet_count += 1
            self.forward_byte_count += ip_len
            self.forward_packet_lengths.append(ip_len)
            self.forward_relative_times.append(rel_time)
        else:
            direction = -1 # REVERSE
            self.reverse_packet_count += 1
            self.reverse_byte_count += ip_len
            self.reverse_packet_lengths.append(ip_len)
            self.reverse_relative_times.append(rel_time)

        self.direction_sequence.append(direction)

        # If TCP FIN or RST, mark flow as closed (to start new instance on next packet)
        if tcp_flags != -1:
            if tcp_flags & dpkt.tcp.TH_FIN or tcp_flags & dpkt.tcp.TH_RST:
                self.closed_by_termination = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "flow_instance": self.instance,
            "protocol": self.canonical_key[2],
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.end_time - self.start_time,
            "packet_count": self.packet_count,
            "forward_packet_count": self.forward_packet_count,
            "reverse_packet_count": self.reverse_packet_count,
            "byte_count": self.byte_count,
            "forward_byte_count": self.forward_byte_count,
            "reverse_byte_count": self.reverse_byte_count,
            "forward_endpoint": f"{self.forward_ep[0]}:{self.forward_ep[1]}",
            "reverse_endpoint": f"{self.reverse_ep[0]}:{self.reverse_ep[1]}",
            "packet_lengths": self.packet_lengths,
            "direction_sequence": self.direction_sequence,
            "relative_times": self.relative_times,
            "tcp_flags": self.tcp_flags_sequence,
            "tls_candidate_sequence": self.tls_candidate_sequence
        }

class FlowReconstructor:
    def __init__(self, pcap_sha256: str, idle_timeout: float = DEFAULT_FLOW_IDLE_TIMEOUT):
        self.pcap_sha256 = pcap_sha256
        self.idle_timeout = idle_timeout
        self.active_flows = {} # canonical_key -> Flow
        self.completed_flows = []
        self.instances = {} # canonical_key -> current instance count

    def flush_flow(self, key):
        if key in self.active_flows:
            self.completed_flows.append(self.active_flows[key].to_dict())
            del self.active_flows[key]

    def flush_all(self):
        for key in list(self.active_flows.keys()):
            self.flush_flow(key)

    def process_packet(self, ts: float, buf: bytes):
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
        except:
            # Fallback for Linux SLL / RAW
            try:
                ip = dpkt.sll.SLL(buf).data
                if not isinstance(ip, dpkt.ip.IP) and not isinstance(ip, dpkt.ip6.IP6):
                    ip = dpkt.ip.IP(buf) # Try raw
            except:
                return

        if not isinstance(ip, dpkt.ip.IP) and not isinstance(ip, dpkt.ip6.IP6):
            return

        try:
            if isinstance(ip, dpkt.ip.IP):
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
            else:
                src_ip = socket.inet_ntop(socket.AF_INET6, ip.src)
                dst_ip = socket.inet_ntop(socket.AF_INET6, ip.dst)
        except:
            return

        ip_len = len(ip)

        if isinstance(ip.data, dpkt.tcp.TCP):
            proto = "TCP"
            transport = ip.data
            tcp_flags = transport.flags
            is_tls_candidate = False
            if len(transport.data) >= 5 and transport.data[0] == 22:
                is_tls_candidate = True
        elif isinstance(ip.data, dpkt.udp.UDP):
            proto = "UDP"
            transport = ip.data
            tcp_flags = -1
            is_tls_candidate = False
        else:
            return # Only TCP and UDP reconstructed for now

        src_ep = (src_ip, transport.sport)
        dst_ep = (dst_ip, transport.dport)

        ep_min = min(src_ep, dst_ep)
        ep_max = max(src_ep, dst_ep)
        canonical_key = (ep_min, ep_max, proto)

        # Retrieve or create flow
        flow = self.active_flows.get(canonical_key)

        # Check boundaries (timeout or closed by termination)
        if flow is not None:
            if (ts - flow.end_time) > self.idle_timeout or flow.closed_by_termination:
                self.flush_flow(canonical_key)
                flow = None

        if flow is None:
            instance = self.instances.get(canonical_key, 0) + 1
            self.instances[canonical_key] = instance
            flow = Flow(self.pcap_sha256, canonical_key, instance, ts, src_ep)
            self.active_flows[canonical_key] = flow

        flow.add_packet(ts, src_ep, ip_len, tcp_flags, is_tls_candidate)
