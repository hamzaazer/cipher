import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from crypto.mailbox import mailbox_id
from crypto.padding import PaddingError, pad, unpad
from crypto.pairing import (
    PairingError,
    create_invite,
    derive,
    handshake_envelope_a,
    handshake_mailbox,
    invite_payload,
    invite_uri,
    new_initiator_ephemeral,
    open_handshake_envelope_a,
    open_payload,
    pair_payload_a,
    pair_payload_b,
    parse_invite_payload,
    parse_invite_uri,
    parse_secret_base32,
    responder_keys,
    sas_matches,
    scanned_from_secret,
    secret_base32,
    split_payload,
)
from crypto.primitives import public_bytes
from crypto.ratchet import (
    ChainState,
    RatchetError,
    initial_chains,
    is_control,
    open_control,
    open_envelope,
    seal,
    seal_control,
)

VECTORS = Path(__file__).resolve().parents[1] / "protocol" / "vectors"


def test_pairing_roundtrip_and_sas():
    invite = create_invite()
    scanned = scanned_from_secret(invite.secret)
    a_eph = new_initiator_ephemeral()
    a_keys = derive(scanned.secret, a_eph.private, invite.eph_public)
    b_keys = derive(invite.secret, invite.eph_private, a_eph.public)
    assert a_keys == b_keys
    assert sas_matches(a_keys.sas, b_keys.sas)
    assert len(a_keys.conv_seed) == 32
    assert a_keys.k_enc != a_keys.k_mac

    id_a, id_b = b"\x01" * 32, b"\x02" * 32
    body_a = open_payload(a_keys, pair_payload_a(a_keys, id_a, a_eph.public), "A")
    assert split_payload(body_a) == (id_a, a_eph.public)
    body_b = open_payload(b_keys, pair_payload_b(b_keys, id_b, invite.eph_public), "B")
    assert split_payload(body_b) == (id_b, invite.eph_public)


def test_pairing_is_bound_to_secret():
    invite = create_invite()
    a_eph = new_initiator_ephemeral()
    wrong = bytes(16)
    keys = derive(wrong, a_eph.private, invite.eph_public)
    real = derive(invite.secret, invite.eph_private, a_eph.public)
    assert keys.conv_seed != real.conv_seed
    assert keys.sas != real.sas
    with pytest.raises(PairingError):
        open_payload(real, pair_payload_a(keys, b"\x01" * 32, a_eph.public), "A")


def test_pair_payload_tamper_rejected():
    invite = create_invite()
    a_eph = new_initiator_ephemeral()
    keys = derive(invite.secret, invite.eph_private, a_eph.public)
    payload = bytearray(pair_payload_a(keys, b"\x01" * 32, a_eph.public))
    payload[-1] ^= 1
    with pytest.raises(PairingError):
        open_payload(keys, bytes(payload), "A")


def test_expired_invite_rejected():
    invite = create_invite(now=1000, ttl=120)
    assert invite.ttl_remaining >= 0
    with pytest.raises(PairingError):
        responder_keys(invite, b"\x03" * 32, now=5000)


def test_invite_ttl_capped():
    with pytest.raises(PairingError):
        create_invite(ttl=121)
    with pytest.raises(PairingError):
        create_invite(ttl=0)


def test_qr_uri_roundtrip_and_manual_entry():
    invite = create_invite()
    scanned = parse_invite_uri(invite_uri(invite))
    assert scanned.secret == invite.secret
    assert scanned.id == invite.id
    manual = parse_secret_base32(secret_base32(invite.secret))
    assert manual == invite.secret
    assert scanned_from_secret(manual).id == invite.id


def test_manual_entry_accepts_lowercase_and_spaces():
    secret = bytes(range(16))
    text = secret_base32(secret).lower().replace("-", " ")
    assert parse_secret_base32(text) == secret


def test_vectors_pairing():
    v = json.loads((VECTORS / "pairing.json").read_text())
    a = X25519PrivateKey.from_private_bytes(bytes.fromhex(v["eph_a_private"]))
    b = X25519PrivateKey.from_private_bytes(bytes.fromhex(v["eph_b_private"]))
    assert public_bytes(a).hex() == v["eph_a_public"]
    assert public_bytes(b).hex() == v["eph_b_public"]
    keys = derive(bytes.fromhex(v["secret"]), a, bytes.fromhex(v["eph_b_public"]))
    assert keys.k_enc.hex() == v["k_enc"]
    assert keys.k_mac.hex() == v["k_mac"]
    assert keys.conv_seed.hex() == v["conv_seed"]
    assert keys.sas == v["sas"]
    payload = pair_payload_a(keys, bytes.fromhex(v["identity_a"]), public_bytes(a))
    assert payload.hex() == v["payload_a"]
    assert open_payload(keys, payload, "A") == bytes.fromhex(v["identity_a"]) + public_bytes(a)


def test_vectors_padding():
    v = json.loads((VECTORS / "padding.json").read_text())
    for item in v["vectors"]:
        plain = bytes.fromhex(item["plaintext"])
        padded = pad(plain)
        assert padded.hex() == item["padded"]
        assert len(padded) == item["padded_len"]
        assert unpad(padded) == plain


def test_vectors_mailbox():
    v = json.loads((VECTORS / "mailbox.json").read_text())
    secret = bytes.fromhex(v["conv_secret"])
    assert mailbox_id(secret, "A", v["day_epoch"]).hex() == v["mailbox_id_a"]
    assert mailbox_id(secret, "B", v["day_epoch"]).hex() == v["mailbox_id_b"]
    assert (
        mailbox_id(secret, "A", v["day_epoch"] + 1).hex()
        == v["mailbox_id_a_next_day"]
    )
    assert v["mailbox_id_a"] != v["mailbox_id_b"]
    assert v["mailbox_id_a"] != v["mailbox_id_a_next_day"]


def test_handshake_mailbox_and_invite_payload():
    invite = create_invite()
    a_eph = new_initiator_ephemeral()
    b_keys = derive(invite.secret, invite.eph_private, a_eph.public)
    a_keys = derive(invite.secret, a_eph.private, invite.eph_public)
    envelope = handshake_envelope_a(a_keys, b"\x07" * 32, a_eph.public)
    keys, identity, eph_a = open_handshake_envelope_a(
        invite.secret, invite.eph_private, envelope
    )
    assert keys == b_keys
    assert identity == b"\x07" * 32
    assert eph_a == a_eph.public
    assert handshake_mailbox(invite.secret) != handshake_mailbox(bytes(16))
    assert len(handshake_mailbox(invite.secret)) == 16
    payload = invite_payload(invite.eph_public)
    assert parse_invite_payload(payload) == invite.eph_public
    with pytest.raises(PairingError):
        parse_invite_payload(payload[:-1])


def test_vectors_ratchet():
    v = json.loads((VECTORS / "ratchet.json").read_text())
    chain = ChainState(bytes.fromhex(v["chain_key"]), v["index"])
    mk, nxt = chain.advance()
    assert mk.hex() == v["message_key"]
    assert nxt.key.hex() == v["next_chain_key"]
    assert nxt.index == v["next_index"]


def test_padding_rejects_bad_input():
    with pytest.raises(PaddingError):
        unpad(b"\x00" * 100)
    p = bytearray(pad(b"hello"))
    p[-1] = 1
    with pytest.raises(PaddingError):
        unpad(bytes(p))
    p = bytearray(pad(b"hello"))
    p[:4] = (9000).to_bytes(4, "big")
    with pytest.raises(PaddingError):
        unpad(bytes(p))
    with pytest.raises(PaddingError):
        pad(b"x" * 9000)


def test_ratchet_messages_both_directions():
    seed = bytes(range(32))
    a = initial_chains(seed, "A")
    b = initial_chains(seed, "B")
    env, a_send = seal(a.send, "A", b"\x10" * 16, b"hello")
    pt, b_recv, counter = open_envelope(b.recv, "A", b"\x10" * 16, env)
    assert pt == b"hello" and counter == 0
    env2, a_send = seal(a_send, "A", b"\x10" * 16, b"second")
    pt2, b_recv, counter = open_envelope(b_recv, "A", b"\x10" * 16, env2)
    assert pt2 == b"second" and counter == 1

    env3, b_send = seal(b.send, "B", b"\x10" * 16, b"reply")
    pt3, a_recv, _ = open_envelope(a.recv, "B", b"\x10" * 16, env3)
    assert pt3 == b"reply"


def test_ratchet_tamper_wrong_mailbox_and_replay():
    seed = bytes(range(32))
    a = initial_chains(seed, "A")
    b = initial_chains(seed, "B")
    env, _ = seal(a.send, "A", b"\x11" * 16, b"secret")
    tampered = bytearray(env)
    tampered[-1] ^= 1
    with pytest.raises(ValueError):
        open_envelope(b.recv, "A", b"\x11" * 16, bytes(tampered))
    with pytest.raises(RatchetError):
        open_envelope(b.recv, "A", b"\x12" * 16, env)
    pt, b_recv, _ = open_envelope(b.recv, "A", b"\x11" * 16, env)
    assert pt == b"secret"
    with pytest.raises(RatchetError):
        open_envelope(b_recv, "A", b"\x11" * 16, env)


def test_ratchet_gap_derives_forward():
    seed = bytes(range(32))
    a = initial_chains(seed, "A")
    b = initial_chains(seed, "B")
    _, a_send = seal(a.send, "A", b"\x21" * 16, b"lost")
    env, _ = seal(a_send, "A", b"\x21" * 16, b"arrives")
    pt, b_recv, counter = open_envelope(b.recv, "A", b"\x21" * 16, env)
    assert pt == b"arrives" and counter == 1


def test_control_envelope_does_not_touch_message_chain():
    seed = bytes(range(32))
    mbx = b"\x31" * 16
    env = seal_control(seed, mbx, b"\x01")
    assert is_control(env)
    assert open_control(seed, env) == b"\x01"
    other = seal_control(bytes(32), mbx, b"\x01")
    with pytest.raises(ValueError):
        open_control(seed, other)


def test_chains_are_separate_per_direction():
    seed = bytes(range(32))
    a = initial_chains(seed, "A")
    b = initial_chains(seed, "B")
    assert a.send.key == b.recv.key
    assert a.recv.key == b.send.key
    assert a.send.key != a.recv.key
