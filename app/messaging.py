"""Pairing and messaging service.

This module joins the crypto primitives, local storage and the pinned relay
client into the operations the UI needs.  It deliberately contains no screen
code and no logging: bodies, keys and plaintext conversation identifiers never
leave this layer except as ciphertext on the relay.

Pairing (C-006):

1. B creates a 16-byte secret ``S`` and an X25519 ephemeral key, then stores
   ``SHA-256(S)`` -> ``CPV1 || eph_b`` on the relay (120 s TTL).
2. A reads ``S`` from the QR code or the manual base32 string, derives the same
   invite id, redeems the invite (atomic one-time delete), and derives the pair
   keys with its own ephemeral key.
3. A deposits ``eph_a || AEAD(k_enc, identity_a || eph_a)`` in a handshake
   mailbox derived from ``S``.  B opens it, derives the same keys, and replies
   with ``AEAD(k_enc, identity_b || eph_b)``.
4. Both compare the 6-digit SAS out of band.  Only then does each side create
   the local conversation.  Aborting purges the handshake mailbox and revokes
   an unredeemed invite.
"""

from __future__ import annotations

import hmac
import threading
import time
from dataclasses import dataclass
from typing import Optional

from crypto.constants import INVITE_TTL_SECONDS, MAX_MESSAGE_BYTES
from crypto.mailbox import mailbox_id, mailbox_ids
from crypto.pairing import (
    Invite,
    PairKeys,
    PairingError,
    ScannedInvite,
    create_invite,
    derive,
    handshake_envelope_a,
    handshake_mailbox,
    invite_payload,
    invite_uri,
    new_initiator_ephemeral,
    open_handshake_envelope_a,
    open_payload,
    pair_payload_b,
    parse_invite_payload,
    parse_invite_uri,
    parse_secret_base32,
    responder_keys,
    scanned_from_secret,
    secret_base32,
    split_payload,
)
from crypto.primitives import fingerprint
from crypto.ratchet import (
    Chains,
    RatchetError,
    initial_chains,
    is_control,
    open_control,
    open_envelope,
    seal,
)
from identity import Identity
from relay_client import Envelope, RelayClient, RelayError
from storage.store import CipherStore, ConversationRow, MessageRow, StorageError


class MessagingError(RuntimeError):
    pass


class NotPaired(MessagingError):
    pass


class ConversationExpired(MessagingError):
    pass


@dataclass(frozen=True)
class PendingPair:
    """Result of a completed handshake, before the user confirms the SAS."""

    role: str
    sas: str
    peer_key_id: bytes
    peer_identity_public: bytes
    conv_seed: bytes
    secret: bytes


@dataclass
class InviteSession:
    invite: Invite
    uri: str
    base32: str
    pending: Optional[PendingPair] = None
    cancelled: bool = False


@dataclass
class JoinSession:
    scanned: ScannedInvite
    keys: PairKeys
    expected_peer_eph: bytes
    mailbox: bytes
    own_envelope_id: str
    expires_at: int
    pending: Optional[PendingPair] = None
    cancelled: bool = False


def parse_pairing_input(text: str) -> ScannedInvite:
    text = (text or "").strip()
    if text.lower().startswith("cipher://"):
        return parse_invite_uri(text)
    return scanned_from_secret(parse_secret_base32(text))


class MessagingService:
    def __init__(
        self,
        store: CipherStore,
        identity: Identity,
        relay: RelayClient,
        *,
        clock=time.time,
    ) -> None:
        self.store = store
        self.identity = identity
        self.relay = relay
        self._clock = clock
        self._lock = threading.RLock()

    # -- pairing ---------------------------------------------------------

    def start_invite(self) -> InviteSession:
        invite = create_invite(now=int(self._clock()), ttl=INVITE_TTL_SECONDS)
        self.relay.create_invite(
            invite.id, invite_payload(invite.eph_public)
        )
        return InviteSession(
            invite=invite,
            uri=invite_uri(invite),
            base32=secret_base32(invite.secret),
        )

    def poll_responder(self, session: InviteSession) -> Optional[PendingPair]:
        """B side: look for A's handshake and reply once."""
        if session.pending is not None:
            return session.pending
        if session.cancelled:
            return None
        if int(self._clock()) > session.invite.expires_at:
            raise PairingError("invite expired")

        mailbox = handshake_mailbox(session.invite.secret)
        try:
            envelopes = self.relay.drain(mailbox.hex())
        except RelayError:
            return None
        for envelope in envelopes:
            try:
                keys, peer_identity, _ = open_handshake_envelope_a(
                    session.invite.secret,
                    session.invite.eph_private,
                    envelope.payload,
                )
            except (PairingError, ValueError):
                # Garbage or an attacker's envelope: leave it for the relay's
                # TTL sweep instead of acknowledging it.
                continue
            reply = pair_payload_b(
                keys, self.identity.public_key, session.invite.eph_public
            )
            try:
                self.relay.deposit(
                    mailbox.hex(), reply, ttl=INVITE_TTL_SECONDS
                )
                self.relay.ack(mailbox.hex(), envelope.envelope_id)
            except RelayError as exc:
                raise MessagingError("relay rejected the pairing reply") from exc
            session.pending = PendingPair(
                role="B",
                sas=keys.sas,
                peer_key_id=fingerprint(peer_identity),
                peer_identity_public=peer_identity,
                conv_seed=keys.conv_seed,
                secret=session.invite.secret,
            )
            return session.pending
        return None

    def join(self, text: str) -> JoinSession:
        """A side: redeem the invite and send the first handshake payload."""
        scanned = parse_pairing_input(text)
        try:
            payload = self.relay.redeem_invite(scanned.id.hex())
        except RelayError as exc:
            raise MessagingError("invite is invalid, expired or already used") from exc
        try:
            expected_peer_eph = parse_invite_payload(payload)
        except PairingError as exc:
            raise MessagingError("invite payload is malformed") from exc

        ephemeral = new_initiator_ephemeral()
        keys = derive(scanned.secret, ephemeral.private, expected_peer_eph)
        mailbox = handshake_mailbox(scanned.secret)
        envelope = handshake_envelope_a(
            keys, self.identity.public_key, ephemeral.public
        )
        try:
            envelope_id = self.relay.deposit(
                mailbox.hex(), envelope, ttl=INVITE_TTL_SECONDS
            )
        except RelayError as exc:
            raise MessagingError("relay rejected the handshake") from exc
        return JoinSession(
            scanned=scanned,
            keys=keys,
            expected_peer_eph=expected_peer_eph,
            mailbox=mailbox,
            own_envelope_id=envelope_id,
            expires_at=int(self._clock()) + INVITE_TTL_SECONDS,
        )

    def poll_joiner(self, session: JoinSession) -> Optional[PendingPair]:
        if session.pending is not None:
            return session.pending
        if session.cancelled:
            return None
        if int(self._clock()) > session.expires_at:
            raise PairingError("pairing timed out")
        try:
            envelopes = self.relay.drain(session.mailbox.hex())
        except RelayError:
            return None
        for envelope in envelopes:
            if envelope.envelope_id == session.own_envelope_id:
                continue
            try:
                body = open_payload(session.keys, envelope.payload, "B")
            except (PairingError, ValueError):
                continue
            peer_identity, eph_b = split_payload(body)
            if not hmac.compare_digest(eph_b, session.expected_peer_eph):
                # The relay cannot derive k_enc, but a wrong ephemeral here
                # still means the handshake is not the one we started.
                continue
            try:
                self.relay.ack(session.mailbox.hex(), envelope.envelope_id)
                self.relay.ack(session.mailbox.hex(), session.own_envelope_id)
            except RelayError:
                pass
            session.pending = PendingPair(
                role="A",
                sas=session.keys.sas,
                peer_key_id=fingerprint(peer_identity),
                peer_identity_public=peer_identity,
                conv_seed=session.keys.conv_seed,
                secret=session.scanned.secret,
            )
            return session.pending
        return None

    def cancel_pairing(self, session: InviteSession | JoinSession) -> None:
        """Abort: revoke an unredeemed invite and purge the handshake queue."""
        session.cancelled = True
        session.pending = None
        if isinstance(session, InviteSession):
            try:
                self.relay.revoke_invite(session.invite.id.hex())
            except RelayError:
                pass
            secret = session.invite.secret
        else:
            secret = session.scanned.secret
        try:
            self.relay.purge(handshake_mailbox(secret).hex())
        except RelayError:
            pass

    def complete_pairing(self, pending: PendingPair) -> ConversationRow:
        """Create the local conversation after the user confirms the SAS."""
        with self._lock:
            existing = self.store.conv_by_peer(pending.peer_key_id)
            if existing is not None:
                # Re-pairing with the same identity is a rekey.  The old
                # conversation is crypto-shredded instead of silently reused.
                self._purge_remote(existing.conv_id)
                self.store.shred_conv(existing.conv_id)
            conv = self.store.create_conv(
                peer_key_id=pending.peer_key_id,
                conv_secret=pending.conv_seed,
                role=pending.role,
                sas=pending.sas,
                now=int(self._clock()),
            )
            self.store.save_ratchet(
                conv.conv_id, initial_chains(pending.conv_seed, pending.role)
            )
            return conv

    # -- conversations ---------------------------------------------------

    def conversations(self) -> list[ConversationRow]:
        return self.store.list_convs(now=int(self._clock()))

    def messages(self, conv_id: bytes) -> list[MessageRow]:
        return self.store.messages(conv_id, now=int(self._clock()))

    def _active(self, conv_id: bytes) -> ConversationRow:
        conv = self.store.get_conv(conv_id)
        if conv.expires_at <= int(self._clock()):
            raise ConversationExpired("conversation expired")
        return conv

    def _chains(self, conv: ConversationRow, secret: bytes) -> Chains:
        chains = self.store.load_ratchet(conv.conv_id)
        return chains or initial_chains(secret, conv.role)

    def send(self, conv_id: bytes, text: str) -> MessageRow:
        body = (text or "").encode("utf-8")
        if not body:
            raise MessagingError("empty message")
        if len(body) > MAX_MESSAGE_BYTES:
            raise MessagingError("message is too long")
        with self._lock:
            conv = self._active(conv_id)
            secret = self.store.conv_secret(conv_id)
            chains = self._chains(conv, secret)
            mailbox = mailbox_id(secret, conv.role, _day(self._clock()))
            envelope, next_send = seal(
                chains.send, conv.role, mailbox, body
            )
            counter = chains.send.index
            try:
                self.relay.deposit(mailbox.hex(), envelope)
            except RelayError as exc:
                raise MessagingError("message was not accepted by the relay") from exc
            # Persist the advanced chain before the local row: if the process
            # dies in between the message is lost, never replayed.
            self.store.save_ratchet(
                conv_id, Chains(send=next_send, recv=chains.recv)
            )
            return self.store.add_message(
                conv_id,
                direction=1,
                plaintext=body,
                counter=counter,
                mailbox_id=mailbox,
                sent_at=int(self._clock()),
            )

    def drain(self, conv_id: bytes) -> int:
        """Fetch and authenticate every available envelope for one chat."""
        received = 0
        with self._lock:
            conv = self._active(conv_id)
            secret = self.store.conv_secret(conv_id)
            chains = self._chains(conv, secret)
            peer_role = "B" if conv.role == "A" else "A"
            for mailbox in mailbox_ids(secret, peer_role, self._clock()):
                try:
                    envelopes = self.relay.drain(mailbox.hex())
                except RelayError:
                    continue
                for envelope in envelopes:
                    got = self._open_one(conv, secret, chains, mailbox, envelope)
                    if got is None:
                        continue
                    chains, added = got
                    if added:
                        received += 1
        return received

    def _open_one(
        self,
        conv: ConversationRow,
        secret: bytes,
        chains: Chains,
        mailbox: bytes,
        envelope: Envelope,
    ) -> Optional[tuple[Chains, bool]]:
        payload = envelope.payload
        if is_control(payload):
            try:
                open_control(secret, payload)
            except ValueError:
                return None
            try:
                self.relay.ack(mailbox.hex(), envelope.envelope_id)
            except RelayError:
                pass
            return chains, False

        peer_role = "B" if conv.role == "A" else "A"
        try:
            plaintext, next_recv, counter = open_envelope(
                chains.recv, peer_role, mailbox, payload
            )
        except (RatchetError, ValueError):
            # Leave the envelope for the TTL sweep; it may be a delayed
            # message from the other day's mailbox or a tampered item.
            return None
        advanced = Chains(send=chains.send, recv=next_recv)
        # Persist first, then store: a crash can drop a message but cannot
        # make the same counter decrypt twice.
        self.store.save_ratchet(conv.conv_id, advanced)
        try:
            self.store.add_message(
                conv.conv_id,
                direction=0,
                plaintext=plaintext,
                counter=counter,
                mailbox_id=mailbox,
                sent_at=int(self._clock()),
            )
        except StorageError:
            return None
        try:
            self.relay.ack(mailbox.hex(), envelope.envelope_id)
        except RelayError:
            pass
        return advanced, True

    def drain_all(self) -> int:
        total = 0
        for conv in self.conversations():
            try:
                total += self.drain(conv.conv_id)
            except (MessagingError, StorageError):
                continue
        return total

    # -- deletion --------------------------------------------------------

    def _purge_remote(self, conv_id: bytes) -> None:
        try:
            secret = self.store.conv_secret(conv_id)
        except StorageError:
            return
        for role in ("A", "B"):
            for mailbox in mailbox_ids(secret, role, self._clock()):
                try:
                    self.relay.purge(mailbox.hex())
                except RelayError:
                    # Local shredding is authoritative; the relay copy is
                    # unreadable after the secret is gone and expires anyway.
                    pass

    def delete_conversation(self, conv_id: bytes) -> None:
        with self._lock:
            self._purge_remote(conv_id)
            self.store.shred_conv(conv_id)

    def expire(self) -> tuple[int, int]:
        return self.store.expire(now=int(self._clock()))

    def wipe_all(self) -> None:
        with self._lock:
            for conv in self.conversations():
                self._purge_remote(conv.conv_id)
            self.store.wipe()
            self.identity.backend.destroy()

    def fingerprint_text(self) -> str:
        raw = self.identity.key_id
        text = raw.hex().upper()
        return " ".join(text[i : i + 4] for i in range(0, len(text), 4))


def _day(now: float) -> int:
    return int(now // 86_400)
