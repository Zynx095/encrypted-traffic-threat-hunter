import unittest
from pipeline.tls_fingerprinting import (
    parse_client_hello,
    parse_server_hello,
    generate_ja3,
    generate_ja3s,
    generate_ja4,
    is_grease
)

class TestTLSFingerprinting(unittest.TestCase):
    
    def test_is_grease(self):
        self.assertTrue(is_grease(0x0a0a))
        self.assertTrue(is_grease(0x1a1a))
        self.assertTrue(is_grease(0xfafa))
        self.assertFalse(is_grease(0x0a0b))
        self.assertFalse(is_grease(0x1301))
        
    def test_parse_client_hello_basic(self):
        payload = bytearray([
            22, 3, 1, 0, 47,
            1, 0, 0, 43,
            3, 3
        ] + [0]*32 + [
            0,
            0, 2, 0xc0, 0x2b,
            1, 0,
            0, 0
        ])
        
        res = parse_client_hello(bytes(payload))
        self.assertIsNone(res["error"])
        self.assertEqual(res["record_version"], 0x0301)
        self.assertEqual(res["client_version"], 0x0303)
        self.assertEqual(res["ciphers"], [0xc02b])
        self.assertEqual(res["extensions"], [])
        
    def test_parse_server_hello_basic(self):
        payload = bytearray([
            22, 3, 3, 0, 45,
            2, 0, 0, 41,
            3, 3
        ] + [0]*32 + [
            0,
            0xc0, 0x2b,
            0,
            0, 0
        ])
        
        res = parse_server_hello(bytes(payload))
        self.assertIsNone(res["error"])
        self.assertEqual(res["server_version"], 0x0303)
        self.assertEqual(res["cipher_suite"], 0xc02b)
        self.assertEqual(res["extensions"], [])

    def test_ja3_generation(self):
        ch_data = {
            "client_version": 771,
            "ciphers": [49195, 49199],
            "extensions": [0, 10, 11],
            "supported_groups": [23, 24],
            "ec_point_formats": [0],
            "error": None
        }
        ja3_string, ja3_hash = generate_ja3(ch_data)
        self.assertEqual(ja3_string, "771,49195-49199,0-10-11,23-24,0")
        
        # Test GREASE filtering
        ch_data_grease = {
            "client_version": 771,
            "ciphers": [0x1a1a, 49195],
            "extensions": [0x2a2a, 0],
            "supported_groups": [0x3a3a, 23],
            "ec_point_formats": [0],
            "error": None
        }
        ja3_str_grease, _ = generate_ja3(ch_data_grease)
        self.assertEqual(ja3_str_grease, "771,49195,0,23,0")

    def test_ja4_generation(self):
        ch_data = {
            "has_supported_versions": True, # TLS 1.3
            "sni_present": True,
            "alpn_str": "h2",
            "ciphers": [0x1301, 0x1302, 0x1a1a], # GREASE cipher
            "extensions": [0, 16, 43, 0x2a2a], # GREASE ext
            "sig_algs": [0x0403, 0x0804, 0x3a3a], # GREASE sig
            "error": None
        }
        
        ja4 = generate_ja4(ch_data)
        # Part A: t 13 d 02 03 h2 => t13d0203h2
        self.assertTrue(ja4.startswith("t13d0203h2_"))

    def test_malformed_reject(self):
        payload = b"\x15\x03\x01\x00\x02\x02\x46" + b"\x00"*40 # Pad to pass len check
        res = parse_client_hello(payload)
        self.assertEqual(res["error"], "not_handshake")

if __name__ == '__main__':
    unittest.main()
