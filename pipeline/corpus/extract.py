"""
Safe extraction of PCAP members from (optionally ZipCrypto-protected) source archives.

Safety rules:
  * the source archive is opened read-only and is never modified;
  * only members whose basename ends in .pcap / .pcapng are ever read;
    executables, documents and e-mails inside malware archives are skipped;
  * member paths are reduced to their basename, so no path traversal is possible;
  * output is written to a temporary file and atomically renamed only after the
    SHA-256 matches the expected value (when an expected value is known);
  * an existing output is never overwritten with different content.
"""
from __future__ import annotations

import hashlib
import os
import zipfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

PCAP_SUFFIXES = (".pcap", ".pcapng")
_CHUNK = 1 << 20


@dataclass
class ExtractionResult:
    archive: str
    member: str
    output: Optional[str]
    status: str            # EXTRACTED | ALREADY_PRESENT | CHECKSUM_MISMATCH | MEMBER_NOT_FOUND | NOT_PCAP | ERROR
    sha256: Optional[str]
    expected_sha256: Optional[str]
    size_bytes: Optional[int]
    detail: str = ""

    def to_dict(self):
        return asdict(self)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(_CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def mta_password(post_date: str) -> bytes:
    """MTA convention documented in phase-6.5-step-2: infected_YYYYMMDD of the blog-post date."""
    digits = post_date.replace("-", "")
    if len(digits) != 8 or not digits.isdigit():
        raise ValueError(f"Invalid MTA post date '{post_date}'")
    return f"infected_{digits}".encode()


def extract_member(archive: Path, member: str, dest_dir: Path, password: Optional[bytes],
                   expected_sha256: Optional[str]) -> ExtractionResult:
    archive = Path(archive)
    base = Path(member).name
    if not base.lower().endswith(PCAP_SUFFIXES):
        return ExtractionResult(str(archive), member, None, "NOT_PCAP", None, expected_sha256, None,
                                "Refusing to extract a non-PCAP member.")
    expected = (expected_sha256 or "").lower() or None
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    out = dest_dir / base

    if out.exists():
        digest = sha256_file(out)
        if expected and digest != expected:
            return ExtractionResult(str(archive), member, str(out), "CHECKSUM_MISMATCH", digest, expected,
                                    out.stat().st_size, "Existing output differs from expected checksum; left untouched.")
        return ExtractionResult(str(archive), member, str(out), "ALREADY_PRESENT", digest, expected, out.stat().st_size)

    try:
        with zipfile.ZipFile(archive, "r") as zf:
            names = zf.namelist()
            match = [n for n in names if n == member or Path(n).name == base]
            if not match:
                return ExtractionResult(str(archive), member, None, "MEMBER_NOT_FOUND", None, expected, None,
                                        f"Archive members: {[Path(n).name for n in names]}")
            info = zf.getinfo(match[0])
            tmp = out.with_suffix(out.suffix + ".partial")
            h = hashlib.sha256()
            with zf.open(info, "r", pwd=password) as src, open(tmp, "wb") as dst:
                for block in iter(lambda: src.read(_CHUNK), b""):
                    h.update(block)
                    dst.write(block)
            digest = h.hexdigest()
            if expected and digest != expected:
                tmp.unlink(missing_ok=True)
                return ExtractionResult(str(archive), member, None, "CHECKSUM_MISMATCH", digest, expected,
                                        info.file_size, "Extracted bytes do not match the recorded checksum; discarded.")
            os.replace(tmp, out)
            return ExtractionResult(str(archive), member, str(out), "EXTRACTED", digest, expected, info.file_size)
    except (RuntimeError, zipfile.BadZipFile, OSError, ValueError) as exc:
        return ExtractionResult(str(archive), member, None, "ERROR", None, expected, None, f"{type(exc).__name__}: {exc}")
