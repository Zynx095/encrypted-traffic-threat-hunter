import unittest
import dpkt
from pipeline.flow_reconstruction import FlowReconstructor, DEFAULT_FLOW_IDLE_TIMEOUT
import socket

def build_eth_ip_tcp(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b""):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    tcp.data = payload
    ip = dpkt.ip.IP(src=socket.inet_aton(src_ip), dst=socket.inet_aton(dst_ip), p=dpkt.ip.IP_PROTO_TCP)
    ip.data = tcp
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP)
    eth.data = ip
    return bytes(eth)

def build_eth_ip_udp(src_ip, dst_ip, sport, dport, payload=b""):
    udp = dpkt.udp.UDP(sport=sport, dport=dport)
    udp.data = payload
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(src=socket.inet_aton(src_ip), dst=socket.inet_aton(dst_ip), p=dpkt.ip.IP_PROTO_UDP)
    ip.data = udp
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP)
    eth.data = ip
    return bytes(eth)

class TestFlowReconstruction(unittest.TestCase):

    def test_test1_and_test2(self):
        # A -> B forms one flow, B -> A is reverse
        reconstructor = FlowReconstructor("hash1")

        # Packet 1: A -> B
        pkt1 = build_eth_ip_tcp("192.168.1.1", "10.0.0.1", 12345, 443, 1000, 0, dpkt.tcp.TH_SYN)
        reconstructor.process_packet(1.0, pkt1)

        # Packet 2: B -> A
        pkt2 = build_eth_ip_tcp("10.0.0.1", "192.168.1.1", 443, 12345, 2000, 1001, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
        reconstructor.process_packet(1.1, pkt2)

        reconstructor.flush_all()
        flows = reconstructor.completed_flows
        self.assertEqual(len(flows), 1)
        f = flows[0]
        self.assertEqual(f["packet_count"], 2)
        self.assertEqual(f["forward_packet_count"], 1)
        self.assertEqual(f["reverse_packet_count"], 1)
        self.assertEqual(f["direction_sequence"], [1, -1])

    def test_different_ports_produce_separate_flows(self):
        reconstructor = FlowReconstructor("hash1")

        # Flow 1
        pkt1 = build_eth_ip_tcp("192.168.1.1", "10.0.0.1", 12345, 443, 1000, 0, dpkt.tcp.TH_SYN)
        reconstructor.process_packet(1.0, pkt1)

        # Flow 2
        pkt2 = build_eth_ip_tcp("192.168.1.1", "10.0.0.1", 12346, 443, 3000, 0, dpkt.tcp.TH_SYN)
        reconstructor.process_packet(1.2, pkt2)

        reconstructor.flush_all()
        flows = reconstructor.completed_flows
        self.assertEqual(len(flows), 2)

    def test_idle_timeout_creates_new_instance(self):
        reconstructor = FlowReconstructor("hash1")

        # Pkt 1
        pkt1 = build_eth_ip_tcp("192.168.1.1", "10.0.0.1", 12345, 443, 1000, 0, dpkt.tcp.TH_ACK)
        reconstructor.process_packet(1.0, pkt1)

        # Pkt 2 (after timeout)
        pkt2 = build_eth_ip_tcp("192.168.1.1", "10.0.0.1", 12345, 443, 1000, 0, dpkt.tcp.TH_ACK)
        reconstructor.process_packet(1.0 + DEFAULT_FLOW_IDLE_TIMEOUT + 1.0, pkt2)

        reconstructor.flush_all()
        flows = reconstructor.completed_flows
        self.assertEqual(len(flows), 2)
        self.assertEqual(flows[0]["flow_instance"], 1)
        self.assertEqual(flows[1]["flow_instance"], 2)

    def test_tcp_fin_closes_flow(self):
        reconstructor = FlowReconstructor("hash1")

        pkt1 = build_eth_ip_tcp("192.168.1.1", "10.0.0.1", 12345, 443, 1000, 0, dpkt.tcp.TH_ACK)
        reconstructor.process_packet(1.0, pkt1)

        # FIN
        pkt2 = build_eth_ip_tcp("192.168.1.1", "10.0.0.1", 12345, 443, 1000, 0, dpkt.tcp.TH_FIN)
        reconstructor.process_packet(2.0, pkt2)

        # Next packet should be new flow instance
        pkt3 = build_eth_ip_tcp("192.168.1.1", "10.0.0.1", 12345, 443, 1000, 0, dpkt.tcp.TH_SYN)
        reconstructor.process_packet(3.0, pkt3)

        reconstructor.flush_all()
        flows = reconstructor.completed_flows
        self.assertEqual(len(flows), 2)
        self.assertEqual(flows[0]["packet_count"], 2)
        self.assertEqual(flows[1]["packet_count"], 1)

    def test_tcp_rst_closes_flow(self):
        reconstructor = FlowReconstructor("hash1")

        pkt1 = build_eth_ip_tcp("192.168.1.1", "10.0.0.1", 12345, 443, 1000, 0, dpkt.tcp.TH_RST)
        reconstructor.process_packet(1.0, pkt1)

        pkt2 = build_eth_ip_tcp("192.168.1.1", "10.0.0.1", 12345, 443, 1000, 0, dpkt.tcp.TH_SYN)
        reconstructor.process_packet(2.0, pkt2)

        reconstructor.flush_all()
        self.assertEqual(len(reconstructor.completed_flows), 2)

    def test_udp_flow_splits_after_timeout(self):
        reconstructor = FlowReconstructor("hash1")

        pkt1 = build_eth_ip_udp("192.168.1.1", "10.0.0.1", 53, 53)
        reconstructor.process_packet(1.0, pkt1)

        pkt2 = build_eth_ip_udp("192.168.1.1", "10.0.0.1", 53, 53)
        reconstructor.process_packet(1.0 + DEFAULT_FLOW_IDLE_TIMEOUT + 1.0, pkt2)

        reconstructor.flush_all()
        self.assertEqual(len(reconstructor.completed_flows), 2)

    def test_packet_count_and_byte_count_invariants(self):
        reconstructor = FlowReconstructor("hash1")

        pkt1 = build_eth_ip_tcp("192.168.1.1", "10.0.0.1", 12345, 443, 1000, 0, dpkt.tcp.TH_SYN)
        reconstructor.process_packet(1.0, pkt1)

        pkt2 = build_eth_ip_tcp("10.0.0.1", "192.168.1.1", 443, 12345, 2000, 1001, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
        reconstructor.process_packet(1.1, pkt2)

        reconstructor.flush_all()
        f = reconstructor.completed_flows[0]

        self.assertEqual(f["packet_count"], f["forward_packet_count"] + f["reverse_packet_count"])
        self.assertEqual(f["byte_count"], f["forward_byte_count"] + f["reverse_byte_count"])
        self.assertEqual(f["packet_count"], len(f["direction_sequence"]))
        self.assertEqual(f["packet_count"], len(f["packet_lengths"]))
        self.assertEqual(f["packet_count"], len(f["relative_times"]))

    def test_same_timestamps_preserve_ordering(self):
        reconstructor = FlowReconstructor("hash1")

        pkt1 = build_eth_ip_tcp("192.168.1.1", "10.0.0.1", 12345, 443, 1000, 0, dpkt.tcp.TH_SYN)
        reconstructor.process_packet(1.0, pkt1)

        # Second packet has EXACTLY same timestamp
        pkt2 = build_eth_ip_tcp("10.0.0.1", "192.168.1.1", 443, 12345, 2000, 1001, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
        reconstructor.process_packet(1.0, pkt2)

        reconstructor.flush_all()
        f = reconstructor.completed_flows[0]

        self.assertEqual(f["relative_times"], [0.0, 0.0])
        self.assertEqual(f["direction_sequence"], [1, -1])

if __name__ == '__main__':
    unittest.main()
