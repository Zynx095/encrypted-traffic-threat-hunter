import unittest
import numpy as np
from pipeline.feature_extraction import (
    extract_flow_level_features,
    extract_packet_length_features,
    extract_iat_features,
    extract_burst_features,
    extract_tls_features,
    build_feature_record,
    BURST_IDLE_THRESHOLD
)

class TestFeatureExtraction(unittest.TestCase):
    
    def setUp(self):
        self.base_flow = {
            "flow_id": "test_hash",
            "dataset_id": "DS-008",
            "source_file": "test.pcap",
            "duration": 5.0,
            "packet_count": 4,
            "forward_packet_count": 2,
            "reverse_packet_count": 2,
            "byte_count": 400,
            "forward_byte_count": 200,
            "reverse_byte_count": 200,
            "packet_lengths": [100, 100, 100, 100],
            "direction_sequence": [1, -1, 1, -1],
            "relative_times": [0.0, 1.0, 3.0, 5.0],
            "tcp_flags": [2, 18, 16, 17],
            "tls_candidate_sequence": [0, 0, 1, 1],
            "clienthello_present": True,
            "serverhello_present": True,
            "tls_version": 1.3,
            "ja3_string": "test_ja3",
            "ja3_hash": "hash_ja3",
            "ja3s_string": "test_ja3s",
            "ja3s_hash": "hash_ja3s",
            "ja4": "t13d000000_123_456",
            "sni_present": True,
            "alpn": "h2"
        }

    def test_empty_flow(self):
        empty_flow = {"packet_count": 0, "duration": 0.0}
        rec = build_feature_record(empty_flow)
        # Should handle zeros gracefully, NaN for division
        self.assertTrue(np.isnan(rec["packets_per_second"]))
        self.assertTrue(np.isnan(rec["packet_length_mean"]))
        self.assertTrue(np.isnan(rec["iat_mean"]))
        self.assertEqual(rec["number_of_bursts"], 0)

    def test_single_packet_flow(self):
        single_flow = {
            "packet_count": 1,
            "duration": 0.0,
            "packet_lengths": [100],
            "direction_sequence": [1],
            "relative_times": [0.0]
        }
        rec = build_feature_record(single_flow)
        self.assertTrue(np.isnan(rec["packets_per_second"])) # division by zero
        self.assertEqual(rec["packet_length_mean"], 100.0)
        self.assertTrue(np.isnan(rec["iat_mean"])) # no IAT for single packet

    def test_forward_only_flow(self):
        fwd_flow = {
            "packet_count": 2,
            "duration": 1.0,
            "packet_lengths": [100, 150],
            "direction_sequence": [1, 1],
            "relative_times": [0.0, 1.0]
        }
        rec = build_feature_record(fwd_flow)
        self.assertEqual(rec["fwd_packet_length_mean"], 125.0)
        self.assertTrue(np.isnan(rec["rev_packet_length_mean"]))
        self.assertEqual(rec["fwd_iat_mean"], 1.0)
        self.assertTrue(np.isnan(rec["rev_iat_mean"]))

    def test_bidirectional_flow(self):
        rec = build_feature_record(self.base_flow)
        self.assertEqual(rec["packet_length_mean"], 100.0)
        self.assertEqual(rec["iat_mean"], 5.0 / 3.0) # diffs: 1.0, 2.0, 2.0 -> mean is 5.0/3.0
        
    def test_zero_duration_division(self):
        # Already covered in single packet, but explicit check
        flow = {"packet_count": 10, "duration": 0.0}
        rec = extract_flow_level_features(flow)
        self.assertTrue(np.isnan(rec["packets_per_second"]))

    def test_constant_packet_lengths(self):
        rec = build_feature_record(self.base_flow)
        self.assertEqual(rec["packet_length_std"], 0.0)

    def test_variable_packet_lengths(self):
        flow = {"packet_lengths": [100, 200, 300], "direction_sequence": [1, 1, 1]}
        rec = extract_packet_length_features(flow)
        self.assertTrue(rec["packet_length_std"] > 0)

    def test_constant_iat(self):
        flow = {"relative_times": [0.0, 1.0, 2.0, 3.0], "direction_sequence": [1, 1, 1, 1]}
        rec = extract_iat_features(flow)
        self.assertAlmostEqual(rec["iat_std"], 0.0)

    def test_variable_iat(self):
        flow = {"relative_times": [0.0, 1.0, 3.0, 6.0], "direction_sequence": [1, 1, 1, 1]}
        rec = extract_iat_features(flow)
        self.assertTrue(rec["iat_std"] > 0)

    def test_missing_iat_sequence(self):
        rec = extract_iat_features({})
        self.assertTrue(np.isnan(rec["iat_mean"]))

    def test_burst_features(self):
        # times: diffs are 1.0, 2.0(burst threshold), 2.0
        rec = extract_burst_features(self.base_flow)
        self.assertEqual(rec["number_of_bursts"], 3) # threshold is 1.0
        self.assertEqual(rec["idle_gap_count"], 2)

    def test_tls_features(self):
        rec = build_feature_record(self.base_flow)
        self.assertTrue(rec["clienthello_present"])
        self.assertEqual(rec["tls_version"], 1.3)
        self.assertEqual(rec["ja4"], "t13d000000_123_456")
        self.assertEqual(rec["alpn_value"], "h2")
        self.assertTrue(rec["sni_present"])

    def test_missing_tls_handshake(self):
        rec = build_feature_record({"dataset_id": "DS-008"})
        self.assertFalse(rec["clienthello_present"])
        self.assertIsNone(rec["ja4"])

    def test_label_preservation(self):
        rec_mal = build_feature_record({"dataset_id": "DS-008"})
        self.assertEqual(rec_mal["label"], "MALICIOUS")
        
        rec_benign = build_feature_record({"dataset_id": "DS-004"})
        self.assertEqual(rec_benign["label"], "BENIGN_VALIDATION")
        
        rec_unknown = build_feature_record({"dataset_id": "UNKNOWN"})
        self.assertEqual(rec_unknown["label"], "UNKNOWN")

    def test_leakage_validation(self):
        # Verify no IPs, ports, absolute timestamps
        rec = build_feature_record(self.base_flow)
        keys = list(rec.keys())
        for k in keys:
            self.assertNotIn("ip", k.lower())
            self.assertNotIn("port", k.lower())
            self.assertNotIn("timestamp", k.lower())
            self.assertNotEqual(k, "sni") # we have sni_present, not raw string
            
    def test_deterministic_output(self):
        rec1 = build_feature_record(self.base_flow)
        rec2 = build_feature_record(self.base_flow)
        self.assertEqual(rec1, rec2)

if __name__ == '__main__':
    unittest.main()
