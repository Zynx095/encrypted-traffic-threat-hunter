"""
Phase 6 Step 4 & 5: Deterministic Bidirectional Flow Reconstruction and TLS Fingerprinting
"""
import socket
import hashlib
from typing import Dict, List, Any, Tuple
import logging

import dpkt
from pipeline.tls_fingerprinting import (
    parse_client_hello,
    parse_server_hello,
    generate_ja3,
    generate_ja3s,
    generate_ja4
)

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
        
        # TLS Fingerprinting State
        self.tls_candidate_sequence = []
        self.client_hello_present = False
        self.server_hello_present = False
        self.ja3_string = None
        self.ja3_hash = None
        self.ja3s_string = None
        self.ja3s_hash = None
        self.ja4 = None
        self.tls_version = None
        self.tls_record_version = None
        self.sni_present = False
        self.alpn = None
        
        # State
        self.closed_by_termination = False

    def _generate_flow_id(self) -> str:
        key_str = f"{self.pcap_sha256}_{self.canonical_key}_{self.instance}"
        return hashlib.sha256(key_str.encode()).hexdigest()

    def process_tls_payload(self, payload: bytes):
        if len(payload) < 6: return
        
        if payload[0] == 22: # Handshake
            handshake_type = payload[5]
            
            # Policy: Take the first valid ClientHello
            if handshake_type == 1 and not self.client_hello_present:
                ch_data = parse_client_hello(payload)
                if not ch_data.get("error"):
                    self.client_hello_present = True
                    self.tls_record_version = ch_data["record_version"]
                    self.sni_present = ch_data["sni_present"]
                    self.alpn = ch_data["alpn_str"]
                    
                    self.tls_version = 1.3 if ch_data["has_supported_versions"] else 1.2
                    
                    self.ja3_string, self.ja3_hash = generate_ja3(ch_data)
                    self.ja4 = generate_ja4(ch_data)
            
            # Policy: Take the first valid ServerHello
            elif handshake_type == 2 and not self.server_hello_present:
                sh_data = parse_server_hello(payload)
                if not sh_data.get("error"):
                    self.server_hello_present = True
                    self.ja3s_string, self.ja3s_hash = generate_ja3s(sh_data)

    def add_packet(self, ts: float, src_ep: Tuple, ip_len: int, tcp_flags: int, payload: bytes):
        self.packet_count += 1
        self.byte_count += ip_len
        self.end_time = max(self.end_time, ts)
        
        rel_time = ts - self.start_time
        if rel_time < 0: rel_time = 0.0 # Safety
        
        self.packet_lengths.append(ip_len)
        self.relative_times.append(rel_time)
        self.tcp_flags_sequence.append(tcp_flags)
        
        is_tls = False
        if len(payload) >= 5 and payload[0] == 22:
            is_tls = True
            self.process_tls_payload(payload)
            
        self.tls_candidate_sequence.append(1 if is_tls else 0)
        
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
        
        # If TCP FIN or RST, mark flow as closed
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
            "tls_candidate_sequence": self.tls_candidate_sequence,
            "clienthello_present": self.client_hello_present,
            "serverhello_present": self.server_hello_present,
            "ja3_string": self.ja3_string,
            "ja3_hash": self.ja3_hash,
            "ja3s_string": self.ja3s_string,
            "ja3s_hash": self.ja3s_hash,
            "ja4": self.ja4,
            "tls_version": self.tls_version,
            "tls_record_version": self.tls_record_version,
            "sni_present": self.sni_present,
            "alpn": self.alpn
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
            payload = transport.data
        elif isinstance(ip.data, dpkt.udp.UDP):
            proto = "UDP"
            transport = ip.data
            tcp_flags = -1
            payload = transport.data
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

        flow.add_packet(ts, src_ep, ip_len, tcp_flags, payload)
