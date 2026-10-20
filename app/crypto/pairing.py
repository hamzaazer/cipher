"""Pairing protocol (§5.1).

B creates a 16-byte secret ``S`` and an ephemeral X25519 key, publishes
``id = SHA-256(S)`` and ``eph_b``.  A scans ``S`` (QR or base32), generates
``eph_a``, fetches ``eph_b``, and both derive::

    dh  = X25519(eph_priv, peer_eph_pub)
    prk = HMAC-SHA256(S, dh)
    okm = HKDF-Expand(prk, "cipher/pair/v1", 64)
    k_enc, k_mac = okm[:32], okm[32:]
    conv_seed = HKDF(k_enc, "cipher/conv/v1", 32)
    SAS = int(HKDF(k_enc, "cipher/sas/v1", 8).hex(), 16) % 1_000_000

Pair payloads are single-use AEAD ciphertexts with fixed nonces ("A"/"B") and
AAD ``pair/v1``.  The fixed nonce is safe because ``k_enc`` is used exactly
once for each direction.  The relay never learns ``S`` and therefore cannot
derive ``k_enc`` or MITM the exchange.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import unquote

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from crypto.constants import (
    CONV_INFO,
    HS_MBX_INFO,
    INVITE_MAGIC,
    INVITE_TTL_SECONDS,
    PAIR_AAD,
    PAIR_INFO,
    PAIR_NONCE_A,
    PAIR_NONCE_B,
    SAS_INFO,
)
from crypto.primitives import (
    aead_decrypt,
    aead_encrypt,
    hkdf,
    hkdf_expand,
    new_x25519,
    public_bytes,
    x25519,
)


class PairingError(ValueError):
    pass


@dataclass(frozen=True)
class PairKeys:
    k_enc: bytes
    k_mac: bytes
    conv_seed: bytes
    sas: str


@dataclass
class Invite:
    """Responder-side (B) one-time invite."""

    secret: bytes
    id: bytes
    eph_private: X25519PrivateKey
    eph_public: bytes
    created_at: int
    expires_at: int

    @property
    def ttl_remaining(self) -> int:
        return max(0, self.expires_at - int(time.time()))


@dataclass(frozen=True)
class ScannedInvite:
    """Initiator-side (A) view of the invite."""

    secret: bytes
    id: bytes


def create_invite(now: Optional[int] = None, ttl: int = INVITE_TTL_SECONDS) -> Invite:
    if not 1 <= ttl <= 120:
        raise PairingError("invite TTL must be 1..120 seconds")
    now = int(time.time()) if now is None else now
    secret = secrets.token_bytes(16)
    invite_id = hashlib.sha256(secret).digest()
    eph_priv, eph_pub = new_x25519()
    return Invite(
        secret=secret,
        id=invite_id,
        eph_private=eph_priv,
        eph_public=eph_pub,
        created_at=now,
        expires_at=now + ttl,
    )


def derive(secret: bytes, my_eph_private: X25519PrivateKey, peer_eph_public: bytes) -> PairKeys:
    if len(secret) != 16:
        raise PairingError("invite secret must be 16 bytes")
    dh = x25519(my_eph_private, peer_eph_public)  # rejects low-order points
    prk = hmac.new(secret, dh, hashlib.sha256).digest()
    okm = hkdf_expand(prk, PAIR_INFO, 64)
    k_enc, k_mac = okm[:32], okm[32:]
    conv_seed = hkdf(k_enc, CONV_INFO, 32)
    sas_value = int(hkdf(k_enc, SAS_INFO, 8).hex(), 16) % 1_000_000
    return PairKeys(k_enc=k_enc, k_mac=k_mac, conv_seed=conv_seed, sas=f"{sas_value:06d}")


def initiator_keys(scanned: ScannedInvite, eph_private: X25519PrivateKey, eph_b_public: bytes) -> PairKeys:
    if hashlib.sha256(scanned.secret).digest() != scanned.id:
        raise PairingError("invite id does not match secret")
    return derive(scanned.secret, eph_private, eph_b_public)


def responder_keys(invite: Invite, eph_a_public: bytes, now: Optional[int] = None) -> PairKeys:
    now = int(time.time()) if now is None else now
    if now > invite.expires_at:
        raise PairingError("invite expired")
    return derive(invite.secret, invite.eph_private, eph_a_public)


def pair_payload_a(keys: PairKeys, identity_public: bytes, eph_a_public: bytes) -> bytes:
    return aead_encrypt(
        keys.k_enc,
        PAIR_NONCE_A,
        identity_public + eph_a_public,
        PAIR_AAD,
    )


def pair_payload_b(keys: PairKeys, identity_public: bytes, eph_b_public: bytes) -> bytes:
    return aead_encrypt(
        keys.k_enc,
        PAIR_NONCE_B,
        identity_public + eph_b_public,
        PAIR_AAD,
    )


def open_payload(keys: PairKeys, payload: bytes, direction: str) -> bytes:
    """Return ``identity_public || eph_public``; reject anything malformed."""
    if direction not in {"A", "B"}:
        raise PairingError("direction must be A or B")
    nonce = PAIR_NONCE_A if direction == "A" else PAIR_NONCE_B
    try:
        body = aead_decrypt(keys.k_enc, nonce, payload, PAIR_AAD)
    except ValueError as exc:
        raise PairingError("pair payload authentication failed") from exc
    if len(body) < 33:
        raise PairingError("pair payload too short")
    return body


def split_payload(body: bytes) -> tuple[bytes, bytes]:
    if len(body) < 33:
        raise PairingError("malformed pair payload")
    return body[:-32], body[-32:]


def sas_matches(a: str, b: str) -> bool:
    return len(a) == 6 and len(b) == 6 and hmac.compare_digest(a.encode(), b.encode())


# ---------------------------------------------------------------------------
# Relay handshake
# ---------------------------------------------------------------------------

# The invite is a single relay record addressed by SHA-256(S), so the manual
# base32 secret alone is enough to find it.  Its payload is public: the
# responder's ephemeral X25519 key.  The initiator's reply carries its own
# ephemeral key in the clear (it is public) followed by the AEAD pair payload;
# the responder needs the ephemeral key before it can derive the pair keys.
#
# Handshake mailbox ids are derived from S, so the relay cannot correlate them
# with any conversation mailbox.  They are only used while the 120 s invite is
# alive; pair envelopes use a short relay TTL.


def handshake_mailbox(secret: bytes) -> bytes:
    if len(secret) != 16:
        raise PairingError("invite secret must be 16 bytes")
    return hkdf(secret, HS_MBX_INFO, 16)


def invite_payload(eph_public: bytes) -> bytes:
    if len(eph_public) != 32:
        raise PairingError("ephemeral public key must be 32 bytes")
    return INVITE_MAGIC + eph_public


def parse_invite_payload(payload: bytes) -> bytes:
    if len(payload) != 4 + 32 or not payload.startswith(INVITE_MAGIC):
        raise PairingError("malformed invite payload")
    return payload[4:]


def handshake_envelope_a(keys: PairKeys, identity_public: bytes, eph_a_public: bytes) -> bytes:
    """Initiator -> responder: public ephemeral key || pair payload A."""
    if len(eph_a_public) != 32:
        raise PairingError("ephemeral public key must be 32 bytes")
    return eph_a_public + pair_payload_a(keys, identity_public, eph_a_public)


def open_handshake_envelope_a(
    secret: bytes,
    my_eph_private: X25519PrivateKey,
    envelope: bytes,
) -> tuple[PairKeys, bytes, bytes]:
    """Responder side: derive keys from the initiator's public ephemeral key,
    then authenticate and open the payload.  Returns (keys, identity, eph_a)."""
    if len(envelope) < 32 + 16:
        raise PairingError("handshake envelope too short")
    eph_a_public = envelope[:32]
    keys = derive(secret, my_eph_private, eph_a_public)
    body = open_payload(keys, envelope[32:], "A")
    identity_public, embedded_eph = split_payload(body)
    if not hmac.compare_digest(embedded_eph, eph_a_public):
        raise PairingError("handshake ephemeral key mismatch")
    return keys, identity_public, eph_a_public


# ---------------------------------------------------------------------------
# Out-of-band encoding
# ---------------------------------------------------------------------------

_B32 = base64.b32encode
_B64URL = base64.urlsafe_b64encode


def secret_base32(secret: bytes) -> str:
    raw = _B32(secret).decode().rstrip("=")
    return "-".join(raw[i : i + 4] for i in range(0, len(raw), 4))


def parse_secret_base32(text: str) -> bytes:
    raw = "".join(ch for ch in text.upper() if ch.isalnum())
    raw = raw.replace("0", "O").replace("1", "I")
    padding = "=" * (-len(raw) % 8)
    try:
        secret = base64.b32decode(raw + padding)
    except Exception as exc:
        raise PairingError("invalid base32 secret") from exc
    if len(secret) != 16:
        raise PairingError("manual secret must decode to 16 bytes")
    return secret


def scanned_from_secret(secret: bytes) -> ScannedInvite:
    if len(secret) != 16:
        raise PairingError("secret must be 16 bytes")
    return ScannedInvite(secret=secret, id=hashlib.sha256(secret).digest())


def invite_uri(invite: Invite) -> str:
    """QR payload.  Contains the one-time secret, so it is equivalent to the
    invite itself and must never be screenshotted or shared after pairing."""
    ident = _B64URL(invite.id).decode().rstrip("=")
    secret = _B64URL(invite.secret).decode().rstrip("=")
    return f"cipher://pair/v1/{ident}/{secret}"


def parse_invite_uri(uri: str) -> ScannedInvite:
    uri = uri.strip()
    prefix = "cipher://pair/v1/"
    if not uri.startswith(prefix):
        raise PairingError("not a Cipher pairing code")
    rest = unquote(uri[len(prefix) :])
    parts = rest.split("/")
    if len(parts) != 2:
        raise PairingError("malformed pairing code")
    try:
        invite_id = base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4))
        secret = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
    except Exception as exc:
        raise PairingError("malformed pairing code") from exc
    if len(invite_id) != 32 or len(secret) != 16:
        raise PairingError("malformed pairing code")
    if hashlib.sha256(secret).digest() != invite_id:
        raise PairingError("pairing code id does not match secret")
    return ScannedInvite(secret=secret, id=invite_id)


@dataclass(frozen=True)
class InitiatorEphemeral:
    private: X25519PrivateKey
    public: bytes


def new_initiator_ephemeral() -> InitiatorEphemeral:
    private, public = new_x25519()
    return InitiatorEphemeral(private=private, public=public)


def ephemeral_public(private: X25519PrivateKey) -> bytes:
    return public_bytes(private)
