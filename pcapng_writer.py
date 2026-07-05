#!/usr/bin/env python3
"""
Minimal pcapng writer with per-packet comment support.
Wireshark reads pcapng "opt_comment" (option code 1) on Enhanced Packet Blocks
and shows them in the packet details ("Packet comments") and lets you filter
with `frame.comment`. scapy's wrpcap only writes legacy pcap (no comments), so
we emit pcapng ourselves.
We read raw frames from the input via scapy (bytes + link type) and re-emit them
as EPBs, attaching a comment option to chosen frames.
"""
import struct
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_IDB = 0x00000001
PCAPNG_EPB = 0x00000006
BYTE_ORDER_MAGIC = 0x1A2B3C4D
OPT_COMMENT = 1
OPT_ENDOFOPT = 0
def _pad4(b):
    return b + b"\x00" * ((-len(b)) % 4)

def _option(code, value):
    return struct.pack("<HH", code, len(value)) + _pad4(value)

def _block(btype, body):
    body = _pad4(body)
    total = 12 + len(body)
    return (struct.pack("<II", btype, total) + body + struct.pack("<I", total))

def _shb():
    body = struct.pack("<IHHq", BYTE_ORDER_MAGIC, 1, 0, -1)
    return _block(PCAPNG_SHB, body)

def _idb(linktype, snaplen=0):
    body = struct.pack("<HHI", linktype, 0, snaplen)
    return _block(PCAPNG_IDB, body)

def _epb(pkt_bytes, ts_usec, comment=None):
    ts_high = (ts_usec >> 32) & 0xFFFFFFFF
    ts_low = ts_usec & 0xFFFFFFFF
    caplen = len(pkt_bytes)
    fixed = struct.pack("<IIIII", 0, ts_high, ts_low, caplen, caplen)
    body = fixed + _pad4(pkt_bytes)
    if comment:
        if isinstance(comment, str):
            comment = comment.encode("utf-8")
        body += _option(OPT_COMMENT, comment) + struct.pack("<HH", OPT_ENDOFOPT, 0)
    return _block(PCAPNG_EPB, body)

def write_pcapng_with_comments(in_pcap, out_pcapng, comment_by_frame,
                               capture_comment=None):
    """
    in_pcap: source capture (any scapy-readable format)
    out_pcapng: destination pcapng path
    comment_by_frame: {frame_number(1-based): comment str}
    """
    from scapy.all import PcapReader
    linktype = 1
    frames = []
    with PcapReader(in_pcap) as pr:
        lt = getattr(pr, "linktype", None)
        if isinstance(lt, int):
            linktype = lt
        for pkt in pr:
            raw = bytes(pkt)
            t = float(pkt.time)
            ts_usec = int(round(t * 1_000_000))
            frames.append((raw, ts_usec))
    shb = _shb()
    if capture_comment:
        body = struct.pack("<IHHq", BYTE_ORDER_MAGIC, 1, 0, -1)
        body += _option(OPT_COMMENT, capture_comment.encode("utf-8"))
        body += struct.pack("<HH", OPT_ENDOFOPT, 0)
        shb = _block(PCAPNG_SHB, body)
    out = [shb, _idb(linktype)]
    for idx, (raw, ts_usec) in enumerate(frames, start=1):
        out.append(_epb(raw, ts_usec, comment_by_frame.get(idx)))
    with open(out_pcapng, "wb") as fh:
        fh.write(b"".join(out))
    return len(frames)
