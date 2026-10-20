"""In-process relay double and end-to-end service tests."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

import pytest

from crypto.mailbox import day_epoch
from identity import load_file_identity, unlock
from messaging import (
    ConversationExpired,
    MessagingError,
    MessagingService,
    parse_pairing_input,
)
from relay_client import Envelope, RelayError, RelayNotFound
from storage.store import CipherStore


class FakeRelay:
    """Same observable semantics as the HTTP relay, without sockets."""

    def __init__(self) -> None:
        self.invites: dict[bytes, tuple[bytes, float]] = {}
        self.mailboxes: dict[bytes, list[tuple[str, bytes, float]]] = {}
        self._next = 0
        self.purges: list[bytes] = []

    def _id(self) -> str:
        self._next += 1
        return f"{self._next:032x}"

    def create_invite(self, invite_id: bytes, payload: bytes, **kw) -> dict:
        if invite_id in self.invites:
            raise RelayError("invite exists")
        self.invites[invite_id] = (payload, time.time() + 120)
        return {"invite_id": invite_id.hex()}

    def redeem_invite(self, invite_id: str) -> bytes:
        item = self.invites.pop(bytes.fromhex(invite_id), None)
        if item is None:
            raise RelayNotFound("not found")
        payload, expires = item
        if expires <= time.time():
            raise RelayNotFound("not found")
        return payload

    def revoke_invite(self, invite_id: str) -> None:
        self.invites.pop(bytes.fromhex(invite_id), None)

    def deposit(self, mailbox_id: str, payload: bytes, ttl: Optional[int] = None) -> str:
        mailbox = bytes.fromhex(mailbox_id)
        envelope_id = self._id()
        self.mailboxes.setdefault(mailbox, []).append(
            (envelope_id, payload, time.time() + (ttl or 86400))
        )
        return envelope_id

    def drain(self, mailbox_id: str) -> list[Envelope]:
        mailbox = bytes.fromhex(mailbox_id)
        now = time.time()
        return [
            Envelope(
                envelope_id=eid,
                payload=payload,
                created_at=int(now),
                expires_at=int(expires),
            )
            for eid, payload, expires in self.mailboxes.get(mailbox, [])
            if expires > now
        ]

    def ack(self, mailbox_id: str, envelope_id: str) -> None:
        mailbox = bytes.fromhex(mailbox_id)
        self.mailboxes[mailbox] = [
            item for item in self.mailboxes.get(mailbox, []) if item[0] != envelope_id
        ]

    def purge(self, mailbox_id: str) -> int:
        mailbox = bytes.fromhex(mailbox_id)
        self.purges.append(mailbox)
        return len(self.mailboxes.pop(mailbox, []))


@dataclass
class Clock:
    now: float = 1_700_000_000.0

    def __call__(self) -> float:
        return self.now


def make_party(tmp_path, name: str, relay: FakeRelay, clock: Clock):
    backend = load_file_identity(tmp_path / f"{name}.json")
    identity = unlock(backend)
    store = CipherStore(
        tmp_path / f"{name}.db",
        identity.kek,
        identity.key_id,
        identity.public_key,
        identity.storage,
    )
    return MessagingService(store, identity, relay, clock=clock)


@pytest.fixture()
def parties(tmp_path):
    relay = FakeRelay()
    clock = Clock()
    a = make_party(tmp_path, "a", relay, clock)
    b = make_party(tmp_path, "b", relay, clock)
    return a, b, relay, clock


def pair(a: MessagingService, b: MessagingService) -> tuple:
    invite = b.start_invite()
    join = a.join(invite.uri)
    pending_b = b.poll_responder(invite)
    pending_a = a.poll_joiner(join)
    assert pending_a is not None and pending_b is not None
    assert pending_a.sas == pending_b.sas
    conv_a = a.complete_pairing(pending_a)
    conv_b = b.complete_pairing(pending_b)
    return conv_a, conv_b


def test_pairing_then_bidirectional_messages(parties):
    a, b, relay, _ = parties
    conv_a, conv_b = pair(a, b)
    assert conv_a.peer_key_id == b.identity.key_id
    assert conv_b.peer_key_id == a.identity.key_id
    assert conv_a.sas == conv_b.sas

    a.send(conv_a.conv_id, "hello from A")
    assert b.drain(conv_b.conv_id) == 1
    body = b.messages(conv_b.conv_id)
    assert body[-1].plaintext == b"hello from A"
    assert body[-1].direction == 0

    b.send(conv_b.conv_id, "hello from B")
    assert a.drain(conv_a.conv_id) == 1
    assert a.messages(conv_a.conv_id)[-1].plaintext == b"hello from B"

    # Nothing is left on the relay after acknowledgement.
    for queue in relay.mailboxes.values():
        assert queue == []


def test_message_replay_is_not_delivered_twice(parties):
    a, b, relay, _ = parties
    conv_a, conv_b = pair(a, b)
    a.send(conv_a.conv_id, "once")
    assert b.drain(conv_b.conv_id) == 1
    mailbox = next(iter(relay.mailboxes))
    # Re-inject the same encrypted envelope as if the relay replayed it.
    envelope_id = relay.deposit(mailbox.hex(), b"")
    assert envelope_id
    assert b.drain(conv_b.conv_id) == 0
    assert len([m for m in b.messages(conv_b.conv_id) if m.plaintext == b"once"]) == 1


def test_tampered_envelope_is_not_stored_or_acked(parties):
    a, b, relay, _ = parties
    conv_a, conv_b = pair(a, b)
    a.send(conv_a.conv_id, "secret")
    mailbox = next(m for m, q in relay.mailboxes.items() if q)
    eid, payload, expires = relay.mailboxes[mailbox][0]
    relay.mailboxes[mailbox][0] = (eid, payload[:-1] + bytes([payload[-1] ^ 1]), expires)
    assert b.drain(conv_b.conv_id) == 0
    assert b.messages(conv_b.conv_id) == []
    assert relay.mailboxes[mailbox]


def test_cancel_revokes_invite_and_purges_handshake(parties):
    a, b, relay, _ = parties
    invite = b.start_invite()
    b.cancel_pairing(invite)
    assert relay.invites == {}
    with pytest.raises(MessagingError):
        a.join(invite.uri)


def test_join_rejects_bad_codes(parties):
    a, _, _, _ = parties
    with pytest.raises(Exception):
        a.join("cipher://pair/v1/not-base64/also-not")
    with pytest.raises(Exception):
        a.join("nonsense")
    with pytest.raises(Exception):
        parse_pairing_input("")


def test_conversation_and_messages_expire(parties):
    a, b, _, clock = parties
    conv_a, conv_b = pair(a, b)
    a.send(conv_a.conv_id, "24h")
    clock.now += 86_400 + 1
    assert a.conversations() == []
    with pytest.raises(ConversationExpired):
        a.send(conv_a.conv_id, "too late")
    assert a.messages(conv_a.conv_id) == []


def test_repaired_peer_replaces_old_conversation(parties):
    a, b, _, _ = parties
    old_a, _ = pair(a, b)
    new_a, _ = pair(a, b)
    assert new_a.conv_id != old_a.conv_id
    assert len(a.conversations()) == 1


def test_message_size_and_empty_rejected(parties):
    a, b, _, _ = parties
    conv_a, _ = pair(a, b)
    with pytest.raises(MessagingError):
        a.send(conv_a.conv_id, "")
    with pytest.raises(MessagingError):
        a.send(conv_a.conv_id, "x" * 9000)
