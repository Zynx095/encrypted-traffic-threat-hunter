"""
Tests for Phase 6 Step 2 ingestion logic.
"""
import os
import unittest
from pathlib import Path
import tempfile
import struct

from pipeline.hashing import compute_sha256
from pipeline.pcap_validator import validate_pcap
from pipeline.adapters.ds008 import DS008Adapter
from pipeline.adapters.ds004 import DS004Adapter

class TestIngestion(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        
    def tearDown(self):
        self.temp_dir.cleanup()
        
    def test_hashing(self):
        test_file = self.temp_path / "test.txt"
        test_file.write_text("ETTH Test")
        hash_val = compute_sha256(test_file)
        self.assertEqual(hash_val, "08ad064d6bad07775b95f0f0b13e57a22f86c5f1ff3e5e9911a93b78f7093d79")
        
    def test_pcap_validator_invalid_file(self):
        missing = self.temp_path / "missing.pcap"
        res = validate_pcap(missing)
        self.assertEqual(res.status, "INVALID")
        
    def test_pcap_validator_unsupported_pcapng(self):
        pcapng = self.temp_path / "test.pcapng"
        with open(pcapng, "wb") as f:
            f.write(b'\x0a\x0d\x0d\x0a' + b'\x00' * 20)
        res = validate_pcap(pcapng)
        self.assertEqual(res.status, "UNSUPPORTED")
        self.assertEqual(res.format, "pcapng")
        
    def test_pcap_validator_empty_pcap(self):
        pcap = self.temp_path / "test.pcap"
        with open(pcap, "wb") as f:
            f.write(b'\xd4\xc3\xb2\xa1')
            f.write(struct.pack('<H', 2))
            f.write(struct.pack('<H', 4))
            f.write(struct.pack('<I', 0))
            f.write(struct.pack('<I', 0))
            f.write(struct.pack('<I', 65535))
            f.write(struct.pack('<I', 1))
        res = validate_pcap(pcap)
        self.assertEqual(res.status, "INVALID")
        self.assertTrue("empty" in res.reason.lower())
        
    def test_ds008_metadata_extraction(self):
        adapter = DS008Adapter()
        dummy_file = self.temp_path / "2024-03-14-AsyncRAT-and-XWorm-infection-traffic.pcap"
        meta = adapter.extract_metadata(dummy_file)
        self.assertEqual(meta["family"], "AsyncRAT-and-XWorm")
        self.assertEqual(meta["capture_date"], "2024-03-14")
        
        norm = adapter.normalize_metadata(meta)
        self.assertEqual(norm["label_normalized"], "MALICIOUS")
        self.assertEqual(norm["malware_family"], "AsyncRAT-and-XWorm")

    def test_ds004_metadata_extraction(self):
        adapter = DS004Adapter()
        dummy_file = self.temp_path / "sample.pcap"
        meta = adapter.extract_metadata(dummy_file)
        norm = adapter.normalize_metadata(meta)
        self.assertEqual(norm["label_normalized"], "BENIGN_VALIDATION")

if __name__ == "__main__":
    unittest.main()
