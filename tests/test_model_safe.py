import unittest
import pandas as pd
import numpy as np
from pipeline.model_safe_generator import generate_model_safe_split

class TestModelSafeGenerator(unittest.TestCase):

    def setUp(self):
        # Create a dummy dataframe resembling the output of Step 6
        self.df = pd.DataFrame({
            "flow_id": ["hash1", "hash2", "hash3", "hash1"], # deliberate duplicate
            "dataset_id": ["DS-008", "DS-008", "DS-004", "DS-008"],
            "source_file": ["f1.pcap", "f2.pcap", "f3.pcap", "f1.pcap"],
            "label": ["MALICIOUS", "MALICIOUS", "BENIGN_VALIDATION", "MALICIOUS"],
            "flow_duration": [1.0, 2.0, 3.0, 1.0],
            "src_ip": ["1.2.3.4", "2.3.4.5", "3.4.5.6", "1.2.3.4"], # forbidden
            "dst_port": [443, 80, 443, 443], # forbidden
            "capture_time": [1000, 2000, 3000, 1000], # forbidden
            "absolute_timestamp": [1, 2, 3, 1], # forbidden
            "sni_domain": ["evil.com", "bad.com", "good.com", "evil.com"], # forbidden
            "sni_present": [True, True, False, True], # safe
            "ja3_hash": ["a", "b", "c", "a"], # safe
            "packets_per_second": [10.0, 5.0, 2.0, 10.0], # safe whitelist
            "sequence_packet_lengths": [[100], [200], [300], [100]] # safe
        })

    def test_split_and_manifest(self):
        ms_df, prov_df, manifest = generate_model_safe_split(self.df)

        # 1. Provenance Check
        prov_cols = prov_df.columns
        self.assertIn("flow_id", prov_cols)
        self.assertIn("dataset_id", prov_cols)
        self.assertIn("source_file", prov_cols)
        self.assertIn("label", prov_cols)
        self.assertIn("model_safe_index", prov_cols)

        # 2. Forbidden Columns Removed from Model Safe
        ms_cols = ms_df.columns
        self.assertNotIn("flow_id", ms_cols)
        self.assertNotIn("dataset_id", ms_cols)
        self.assertNotIn("source_file", ms_cols)
        self.assertNotIn("src_ip", ms_cols)
        self.assertNotIn("dst_port", ms_cols)
        self.assertNotIn("capture_time", ms_cols)
        self.assertNotIn("absolute_timestamp", ms_cols)
        self.assertNotIn("sni_domain", ms_cols)

        # 3. Safe Columns Retained
        self.assertIn("model_safe_index", ms_cols)
        self.assertIn("label", ms_cols)
        self.assertIn("flow_duration", ms_cols)
        self.assertIn("sni_present", ms_cols)
        self.assertIn("ja3_hash", ms_cols)
        self.assertIn("packets_per_second", ms_cols)
        self.assertIn("sequence_packet_lengths", ms_cols)

        # 4. Label Preservation
        self.assertEqual(list(ms_df["label"]), ["MALICIOUS", "MALICIOUS", "BENIGN_VALIDATION", "MALICIOUS"])

        # 5. Duplicate Check
        # Rows 0 and 3 are identical in features
        self.assertEqual(manifest["duplicate_count"], 2) # Both instances are flagged by keep=False

        # 6. Row counts match
        self.assertEqual(len(ms_df), 4)
        self.assertEqual(len(prov_df), 4)

if __name__ == '__main__':
    unittest.main()
