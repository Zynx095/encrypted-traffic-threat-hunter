"""Reference-vector support for JA4 conformance testing.

Reads a pcap/pcapng file, reassembles the client-to-server byte stream of every TCP connection
(ordered by sequence number, duplicates and overlaps dropped), and returns the first complete
TLS ClientHello of each connection as a single TLS record. Used only to check
``pipeline.tls_fingerprinting.generate_ja4_foxio`` against FoxIO's published outputs; it is not
part of the corpus or live pipeline.
"""
from __future__ import annotations

import socket
from typing import Dict, Optional, Tuple

import dpkt

Key = Tuple[str, int, str, int]


def _ip_str(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6 if len(raw) == 16 else socket.AF_INET, raw)


def _reader(fh):
    head = fh.read(4)
    fh.seek(0)
    return dpkt.pcapng.Reader(fh) if head == b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(fh)


def _ip_layer(buf: bytes, linktype: int):
    if linktype == dpkt.pcap.DLT_RAW or linktype == 101:
        return dpkt.ip.IP(buf) if buf and buf[0] >> 4 == 4 else dpkt.ip6.IP6(buf)
    if linktype == dpkt.pcap.DLT_LINUX_SLL:
        return dpkt.sll.SLL(buf).data
    if linktype == dpkt.pcap.DLT_NULL or linktype == dpkt.pcap.DLT_LOOP:
        return dpkt.loopback.Loopback(buf).data
    return dpkt.ethernet.Ethernet(buf).data


def clienthello_from_stream(stream: bytes) -> Optional[bytes]:
    """Return the first ClientHello in a reassembled stream as one TLS record, or None.

    A handshake message fragmented over several TLS records is joined. Incomplete data gives None.
    """
    body = b""
    pos = 0
    while pos + 5 <= len(stream):
        ctype, rlen = stream[pos], int.from_bytes(stream[pos + 3:pos + 5], "big")
        if ctype != 22 or pos + 5 + rlen > len(stream):
            return None
        body += stream[pos + 5:pos + 5 + rlen]
        pos += 5 + rlen
        if len(body) >= 4:
            if body[0] != 1:
                return None
            need = 4 + int.from_bytes(body[1:4], "big")
            if len(body) >= need:
                msg = body[:need]
                return b"\x16" + stream[1:3] + len(msg).to_bytes(2, "big") + msg
    return None


def extract_tcp_clienthellos(path: str) -> Dict[Key, bytes]:
    """Map (client ip, client port, server ip, server port) -> first ClientHello record."""
    segs: Dict[Key, Dict[int, bytes]] = {}
    with open(path, "rb") as fh:
        rd = _reader(fh)
        linktype = rd.datalink()
        for _, buf in rd:
            try:
                ip = _ip_layer(buf, linktype)
            except Exception:
                continue
            tcp = getattr(ip, "data", None)
            if not isinstance(tcp, dpkt.tcp.TCP) or not tcp.data:
                continue
            key = (_ip_str(ip.src), tcp.sport, _ip_str(ip.dst), tcp.dport)
            segs.setdefault(key, {}).setdefault(tcp.seq, bytes(tcp.data))
    out: Dict[Key, bytes] = {}
    for key, by_seq in segs.items():
        ordered = sorted(by_seq.items())
        start = next((s for s, p in ordered if p[0] == 22), None)
        if start is None:
            continue
        stream, nxt = b"", start
        for seq, data in ordered:
            if seq < start:
                continue
            if seq > nxt:
                break
            stream += data[nxt - seq:]
            nxt = max(nxt, seq + len(data))
        rec = clienthello_from_stream(stream)
        if rec:
            out[key] = rec
    return out
