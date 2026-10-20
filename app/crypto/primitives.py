"""Authenticated ciphers and KDF helpers.

All AEAD, KDF, key agreement and signature verification primitives come from
the vetted ``cryptography`` package.  Nothing in this module implements a
cipher, a MAC or a KDF by hand.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto.constants import KEK_INFO

HASH = hashlib.sha256
TAG_BYTES = 16


def hkdf(ikm: bytes, info: bytes, length: int, salt: bytes = b"") -> bytes:
    """RFC 5869 HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt or None,
        info=info,
    ).derive(ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand, used where the spec fixes the extract step."""
    if length > 255 * HASH().digest_size:
        raise ValueError("hkdf: too much output")
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), HASH).digest()
        out += t
        counter += 1
    return out[:length]


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, HASH).digest()


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:  # never leak which check failed
        raise ValueError("decryption failed") from exc


def new_x25519() -> Tuple[X25519PrivateKey, bytes]:
    priv = X25519PrivateKey.generate()
    return priv, public_bytes(priv)


def public_bytes(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def x25519(private_key: X25519PrivateKey, peer_public: bytes) -> bytes:
    if len(peer_public) != 32:
        raise ValueError("x25519: peer public key must be 32 bytes")
    shared = private_key.exchange(X25519PublicKey.from_public_bytes(peer_public))
    if shared == b"\x00" * 32:
        raise ValueError("x25519: low-order point")
    return shared


def fingerprint(pubkey: bytes) -> bytes:
    """Stable key id: SHA-256 of the identity public key."""
    return hashlib.sha256(pubkey).digest()


def kek_from_signature(signature: bytes) -> bytes:
    """Derive the master KEK from a *deterministic* identity signature.

    Native storage uses RSA PKCS#1 v1.5 (deterministic).  File storage uses
    Ed25519 (deterministic).  The signature never leaves the device and is
    never persisted.
    """
    if len(signature) < 32:
        raise ValueError("signature too short")
    return hkdf(signature, KEK_INFO, 32)


def random_bytes(n: int) -> bytes:
    return os.urandom(n)
