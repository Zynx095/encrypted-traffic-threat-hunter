"""Fetch the FoxIO JA4 reference captures pinned in data/reference/foxio_ja4/vectors.json.

    python -m pipeline.fetch_foxio_ja4_vectors

Each file is downloaded from the pinned FoxIO commit and kept only if its SHA-256 matches the
manifest. Files land in data/reference/foxio_ja4/pcap/ (git-ignored).
"""
from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REF_DIR = ROOT / "data" / "reference" / "foxio_ja4"
MANIFEST = REF_DIR / "vectors.json"
PCAP_DIR = REF_DIR / "pcap"


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    base = f"https://raw.githubusercontent.com/FoxIO-LLC/ja4/{manifest['commit']}/pcap/"
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    bad = 0
    for name, digest in manifest["pcap_sha256"].items():
        target = PCAP_DIR / name
        if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == digest:
            continue
        data = urllib.request.urlopen(base + name, timeout=60).read()
        if hashlib.sha256(data).hexdigest() != digest:
            print(f"SHA-256 mismatch, not saved: {name}")
            bad += 1
            continue
        target.write_bytes(data)
        print(f"fetched {name}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
