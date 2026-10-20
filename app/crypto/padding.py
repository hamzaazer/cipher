"""Padding to a fixed bucket set (padmé-style length prefix).

Wire format before encryption::

    uint32_be length || payload || zero padding
    total length is exactly one of 128, 512, 2048, 8192

Decryption rejects lengths outside the bucket set, a prefix larger than the
bucket, trailing non-zero bytes, and payloads above the maximum size.
"""

from __future__ import annotations

import struct

from crypto.constants import PAD_BUCKETS


class PaddingError(ValueError):
    pass


def padded_size(n: int) -> int:
    need = n + 4
    for bucket in PAD_BUCKETS:
        if need <= bucket:
            return bucket
    raise PaddingError("message too large")


def pad(plaintext: bytes) -> bytes:
    size = padded_size(len(plaintext))
    return struct.pack(">I", len(plaintext)) + plaintext + b"\x00" * (size - 4 - len(plaintext))


def unpad(padded: bytes) -> bytes:
    if len(padded) not in PAD_BUCKETS:
        raise PaddingError("invalid padded length")
    (length,) = struct.unpack(">I", padded[:4])
    if length > len(padded) - 4:
        raise PaddingError("invalid length prefix")
    body = padded[4 : 4 + length]
    trailer = padded[4 + length :]
    if any(trailer):
        raise PaddingError("non-zero padding")
    return body
