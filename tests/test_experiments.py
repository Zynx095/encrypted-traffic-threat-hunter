import unittest
import pandas as pd
from pipeline.experimental_dataset_constructor import ExperimentConstructor

class TestExperiments(unittest.TestCase):

    def setUp(self):
        # Create dummy df resembling step 7 output
        self.ms_df = pd.DataFrame({
            "model_safe_index": [0, 1, 2, 3],
            "label": ["MALICIOUS", "BENIGN_VALIDATION", "MALICIOUS", "BENIGN_VALIDATION"],
            "flow_duration": [1.0, 2.0, 3.0, 4.0],
            "tls_version": [1.2, 1.3, None, 1.3],
            "clienthello_present": [True, True, False, True],
            "ja3_hash": ["a", "b", None, "c"],
            "ja3s_hash": ["x", "y", None, "z"],
            "ja4": ["t12", "t13", None, "t13"],
            "sequence_packet_lengths": [[100], [200], [300], [400]]
        })

        self.prov_df = pd.DataFrame({
            "model_safe_index": [0, 1, 2, 3],
            "source_file": ["f1", "f2", "f3", "f4"],
            "dataset_id": ["d1", "d2", "d1", "d2"],
            "flow_id": ["x", "y", "z", "w"]
        })

        self.constructor = ExperimentConstructor(self.ms_df, self.prov_df, random_state=42)

    def test_experiment_A(self):
        tr, te = self.constructor.generate_experiment_A()
        cols = tr.columns
        self.assertIn("flow_duration", cols)
        self.assertIn("tls_version", cols)
        self.assertIn("sequence_packet_lengths", cols)
        self.assertNotIn("ja3_hash", cols)
        self.assertNotIn("ja4", cols)
        self.assertNotIn("ja3s_hash", cols)
        self.assertNotIn("source_file", cols)

    def test_experiment_B(self):
        tr, te = self.constructor.generate_experiment_B()
        cols = tr.columns
        self.assertIn("ja3_hash", cols)
        self.assertNotIn("flow_duration", cols)
        self.assertNotIn("ja4", cols)
        self.assertNotIn("ja3s_hash", cols)
        self.assertNotIn("sequence_packet_lengths", cols)

        # Missing values dropped
        self.assertEqual(len(tr) + len(te), 3) # row 2 drops

    def test_experiment_C(self):
        tr, te = self.constructor.generate_experiment_C()
        cols = tr.columns
        self.assertIn("ja4", cols)
        self.assertNotIn("ja3_hash", cols)
        self.assertNotIn("flow_duration", cols)

        self.assertEqual(len(tr) + len(te), 3)

    def test_experiment_D(self):
        tr, te = self.constructor.generate_experiment_D()
        cols = tr.columns
        self.assertIn("ja3_hash", cols)
        self.assertIn("flow_duration", cols)
        self.assertNotIn("ja4", cols)

        self.assertEqual(len(tr) + len(te), 3)

    def test_experiment_E(self):
        tr, te = self.constructor.generate_experiment_E()
        cols = tr.columns
        self.assertIn("ja4", cols)
        self.assertIn("flow_duration", cols)
        self.assertNotIn("ja3_hash", cols)

        self.assertEqual(len(tr) + len(te), 3)

    def test_duplicate_analysis(self):
        # Insert a duplicate
        ms2 = self.ms_df.copy()
        ms2.loc[4] = ms2.loc[0]
        ms2.at[4, 'model_safe_index'] = 4

        prov2 = self.prov_df.copy()
        prov2.loc[4] = prov2.loc[0]
        prov2.at[4, 'model_safe_index'] = 4

        cons = ExperimentConstructor(ms2, prov2, random_state=42)
        stats = cons.analyze_duplicates()
        self.assertEqual(stats["exact_duplicate_count"], 2) # Both rows are in the duplicate set
        self.assertEqual(stats["duplicate_groups"], 1)

if __name__ == '__main__':
    unittest.main()
