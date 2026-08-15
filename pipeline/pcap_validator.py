"""
Basic PCAP validation for Phase 6 pipeline.
"""
import dpkt
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

@dataclass
class ValidationResult:
    status: str
    format: str
    packet_count: Optional[int]
    reason: str

def validate_pcap(filepath: Path) -> ValidationResult:
    if not filepath.exists():
        return ValidationResult("INVALID", "unknown", None, "File does not exist")
    if not filepath.is_file():
        return ValidationResult("INVALID", "unknown", None, "Not a file")
    try:
        with open(filepath, 'rb') as f:
            magic = f.read(4)
            if magic == b'\x0a\x0d\x0d\x0a':
                return ValidationResult("UNSUPPORTED", "pcapng", None, "pcapng is not supported by dpkt currently")
            if magic not in (b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x4d\x3c\xb2\xa1'):
                return ValidationResult("INVALID", "unknown", None, "Invalid magic bytes")
            f.seek(0)
            try:
                pcap = dpkt.pcap.Reader(f)
                packet_count = 0
                for ts, buf in pcap:
                    packet_count += 1
                if packet_count == 0:
                    return ValidationResult("INVALID", "pcap", 0, "File is empty (no packets)")
                return ValidationResult("VALID", "pcap", packet_count, "OK")
            except Exception as e:
                return ValidationResult("INVALID", "pcap", None, f"Parser failed: {str(e)}")
    except Exception as e:
        return ValidationResult("INVALID", "unknown", None, f"File read error: {str(e)}")
