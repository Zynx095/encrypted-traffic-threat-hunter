"""
Tests for Phase 6 Step 3 protocol validation logic.
"""
import unittest
import struct
from step3_analysis import parse_tls_extensions

class TestStep3Analysis(unittest.TestCase):
    def test_parse_tls_extensions(self):
        # Create a synthetic TLS extensions block
        # SNI (0), ALPN (16), supported_versions (43) with TLS 1.3

        exts = bytearray()
        # SNI (type 0, len 0 for simplicity)
        exts.extend(struct.pack('>HH', 0, 0))
        # ALPN (type 16, len 0)
        exts.extend(struct.pack('>HH', 16, 0))
        # Supported versions (type 43, len 3)
        exts.extend(struct.pack('>HH', 43, 3))
        exts.extend(b'\x02\x03\x04') # len 2, TLS 1.3 (0x0304)

        sni, alpn, sv, ext_cnt, has_tls13 = parse_tls_extensions(exts)
        self.assertTrue(sni)
        self.assertTrue(alpn)
        self.assertTrue(sv)
        self.assertTrue(has_tls13)
        self.assertEqual(ext_cnt, 3)

    def test_parse_tls_extensions_no_tls13(self):
        exts = bytearray()
        exts.extend(struct.pack('>HH', 43, 3))
        exts.extend(b'\x02\x03\x03') # len 2, TLS 1.2 (0x0303)

        sni, alpn, sv, ext_cnt, has_tls13 = parse_tls_extensions(exts)
        self.assertTrue(sv)
        self.assertFalse(has_tls13)
        self.assertEqual(ext_cnt, 1)

    def test_parse_tls_extensions_grease(self):
        exts = bytearray()
        # GREASE (type 0x1A1A)
        exts.extend(struct.pack('>HH', 0x1A1A, 0))

        sni, alpn, sv, ext_cnt, has_tls13 = parse_tls_extensions(exts)
        self.assertEqual(ext_cnt, 0) # GREASE ignored

if __name__ == '__main__':
    unittest.main()
