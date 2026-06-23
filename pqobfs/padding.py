"""Handshake padding normalization and TCP segmentation (paper Section V-B, Table V).

Defense 2: pad every handshake message to a fixed cover size ``LCOVER`` so the
on-the-wire size -- and therefore the TCP segment profile -- is identical for all
ML-KEM parameter sets, collapsing the size fingerprint (Surface 2).
"""

from __future__ import annotations

import os

LCOVER = 4096  # fixed cover size from the paper (Section V-B)
MTU = 1500
TCP_HDR = 40  # TCP + IP header overhead
TCP_PAYLOAD = MTU - TCP_HDR  # 1460 bytes of payload per full segment


def normalize_message(msg: bytes, lcover: int = LCOVER) -> bytes:
    """Pad ``msg`` to exactly ``lcover`` bytes. Raise if it does not fit."""
    if len(msg) > lcover:
        raise ValueError(f"message of {len(msg)} bytes exceeds cover size {lcover}")
    return msg + os.urandom(lcover - len(msg))


def tcp_segments(msg_len: int, mtu: int = MTU) -> list[int]:
    """TCP segment payload sizes for a message of ``msg_len`` bytes.

    Each full segment carries ``mtu - TCP_HDR`` payload bytes; the final segment
    carries the remainder.
    """
    payload = mtu - TCP_HDR
    if msg_len <= 0:
        return []
    full, rem = divmod(msg_len, payload)
    segs = [payload] * full
    if rem:
        segs.append(rem)
    return segs


def segment_profile(msg, mtu: int = MTU) -> dict:
    """Segment count and sizes for a message (bytes or an integer length)."""
    msg_len = msg if isinstance(msg, int) else len(msg)
    segs = tcp_segments(msg_len, mtu)
    return {
        "length": msg_len,
        "num_segments": len(segs),
        "segments": segs,
    }
