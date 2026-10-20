"""Per-message symmetric ratchet (§5.2 fallback).

Each direction has an independent HMAC-SHA256 chain seeded from the pairing
secret::

    root      = HKDF(conv_seed, "cipher/msg-ratchet/v1", 64)
    chain_A2B = root[:32]      # initiator -> responder
    chain_B2A = root[32:]      # responder -> initiator
    mk        = HMAC(chain, 0x01)
    chain'    = HMAC(chain, 0x02)

A message key is used once and then discarded.  Deleting the old chain state
gives *forward secrecy for messages already sent*; it does **not** give
post-compromise security, because an attacker who obtains the current chain
key can derive all future message keys until the peer re-pairs.

Why not a Noise transport session: the relay is store-and-forward.  A Noise
transport nonce is strictly sequential, so a single expired, lost or
out-of-order mailbox item permanently desynchronises the session.  Noise XX
also requires both peers online for three flights.  Cipher instead uses the
brief's per-message ratchet, with the same ChaCha20-Poly1305 construction and
the conversation secret derived from the pairing exchange.  This limitation is
displayed in the Security screen and documented in docs/threat-model.md.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass

from crypto.constants import (
    CTRL_INFO,
    MAX_SKIP,
    PAD_BUCKETS,
    RATCHET_INFO,
)
from crypto.padding import pad, unpad
from crypto.primitives import aead_decrypt, aead_encrypt, hkdf


class RatchetError(ValueError):
    pass


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


@dataclass(frozen=True)
class ChainState:
    key: bytes
    index: int

    def advance(self) -> tuple[bytes, "ChainState"]:
        if len(self.key) != 32:
            raise RatchetError("invalid chain key")
        message_key = _hmac(self.key, b"\x01")
        next_key = _hmac(self.key, b"\x02")
        return message_key, ChainState(next_key, self.index + 1)

    def serialize(self) -> bytes:
        return self.key + struct.pack(">Q", self.index)

    @classmethod
    def deserialize(cls, raw: bytes) -> "ChainState":
        if len(raw) != 40:
            raise RatchetError("invalid chain state")
        return cls(key=raw[:32], index=struct.unpack(">Q", raw[32:])[0])


@dataclass(frozen=True)
class Chains:
    send: ChainState
    recv: ChainState


def initial_chains(conv_seed: bytes, role: str) -> Chains:
    if role not in {"A", "B"}:
        raise RatchetError("role must be A or B")
    root = hkdf(conv_seed, RATCHET_INFO, 64)
    a2b, b2a = root[:32], root[32:]
    if role == "A":
        return Chains(send=ChainState(a2b, 0), recv=ChainState(b2a, 0))
    return Chains(send=ChainState(b2a, 0), recv=ChainState(a2b, 0))


def _aad(mailbox_id: bytes, sender_role: str, counter: int) -> bytes:
    return mailbox_id + (b"\x00" if sender_role == "A" else b"\x01") + struct.pack(">Q", counter)


def seal(
    chain: ChainState,
    sender_role: str,
    mailbox_id: bytes,
    plaintext: bytes,
) -> tuple[bytes, ChainState]:
    if len(mailbox_id) != 16:
        raise RatchetError("mailbox id must be 16 bytes")
    counter = chain.index
    message_key, next_chain = chain.advance()
    padded = pad(plaintext)
    # Counter in the first four nonce bytes lets the receiver derive the right
    # message key without an extra header; the remaining 8 bytes are random so
    # nonces are unique even if a peer restores an old database snapshot.
    nonce = struct.pack(">I", counter) + os.urandom(8)
    ciphertext = aead_encrypt(
        message_key, nonce, padded, _aad(mailbox_id, sender_role, counter)
    )
    return mailbox_id + nonce + ciphertext, next_chain


def open_envelope(
    chain: ChainState,
    sender_role: str,
    mailbox_id: bytes,
    envelope: bytes,
) -> tuple[bytes, ChainState, int]:
    if len(envelope) < 16 + 12 + 16 + PAD_BUCKETS[0]:
        raise RatchetError("envelope too short")
    if envelope[:16] != mailbox_id:
        raise RatchetError("mailbox id mismatch")
    nonce = envelope[16:28]
    ciphertext = envelope[28:]
    counter = struct.unpack(">I", nonce[:4])[0]
    if counter < chain.index:
        raise RatchetError("replayed or already consumed message")
    if counter - chain.index > MAX_SKIP:
        raise RatchetError("counter gap too large")
    # Derive forward, deleting intermediate keys (lost messages stay lost).
    current = chain
    while current.index < counter:
        _, current = current.advance()
    message_key, next_chain = current.advance()
    padded = aead_decrypt(
        message_key, nonce, ciphertext, _aad(mailbox_id, sender_role, counter)
    )
    return unpad(padded), next_chain, counter


def is_control(envelope: bytes) -> bool:
    return len(envelope) >= 16 and len(envelope) > 16 and envelope[16] == 0xFF


def seal_control(conv_seed: bytes, mailbox_id: bytes, payload: bytes) -> bytes:
    if len(mailbox_id) != 16:
        raise RatchetError("mailbox id must be 16 bytes")
    key = hkdf(conv_seed, CTRL_INFO, 32)
    nonce = b"\xff" + os.urandom(11)
    aad = b"ctrl" + mailbox_id
    return mailbox_id + nonce + aead_encrypt(key, nonce, payload, aad)


def open_control(conv_seed: bytes, envelope: bytes) -> bytes:
    if not is_control(envelope):
        raise RatchetError("not a control envelope")
    if len(envelope) < 16 + 12 + 16:
        raise RatchetError("control envelope too short")
    mailbox_id = envelope[:16]
    nonce = envelope[16:28]
    key = hkdf(conv_seed, CTRL_INFO, 32)
    return aead_decrypt(key, nonce, envelope[28:], b"ctrl" + mailbox_id)
