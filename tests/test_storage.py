import os
import sqlite3
from pathlib import Path

import pytest

from crypto.ratchet import initial_chains
from identity import IdentityError, load_file_identity, load_identity, unlock
from storage import CipherStore, IdentityMismatch, StorageError


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("CIPHER_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CIPHER_TEST_PROFILE", "1")
    monkeypatch.setenv("CIPHER_TTL_SECONDS", "60")
    return tmp_path


def make_store(tmp_path, identity, name="test.db"):
    return CipherStore(
        tmp_path / name,
        identity.kek,
        identity.key_id,
        identity.public_key,
        identity.storage,
    )


def test_file_identity_is_stable_and_destroyable(env):
    path = env / "identity.json"
    first = load_file_identity(path)
    pub = first.public_key
    second = load_file_identity(path)
    assert second.public_key == pub
    id1 = unlock(first)
    id2 = unlock(second)
    assert id1.kek == id2.kek
    assert id1.key_id == id2.key_id
    assert first.sign(b"x") == second.sign(b"x")
    first.destroy()
    assert not path.exists()
    third = load_file_identity(path)
    assert third.public_key != pub


def test_load_identity_falls_back_to_file(env, monkeypatch):
    import identity as identity_module

    monkeypatch.setattr(identity_module, "native_available", lambda: False)
    backend = load_identity()
    assert backend.storage == "file"
    assert unlock(backend).storage == "file"


def test_message_roundtrip(env):
    ident = unlock(load_file_identity(env / "identity.json"))
    store = make_store(env, ident)
    conv = store.create_conv(b"\x01" * 32, bytes(range(32)), "A", "123456")
    row = store.add_message(conv.conv_id, 1, b"hello world", 0, b"\x02" * 16)
    assert row.plaintext == b"hello world"
    got = store.messages(conv.conv_id)
    assert len(got) == 1
    assert got[0].plaintext == b"hello world"
    store.close()


def test_shred_is_crypto_shredding(env):
    ident = unlock(load_file_identity(env / "identity.json"))
    store = make_store(env, ident)
    conv = store.create_conv(b"\x01" * 32, bytes(range(32)), "A", "123456")
    row = store.add_message(conv.conv_id, 1, b"top secret", 0, b"\x02" * 16)
    store.shred_message(row.msg_id)
    assert store.messages(conv.conv_id) == []
    raw = store.path.read_bytes()
    assert b"top secret" not in raw
    store.close()


def test_conversation_shred_removes_key(env):
    ident = unlock(load_file_identity(env / "identity.json"))
    store = make_store(env, ident)
    conv = store.create_conv(b"\x01" * 32, bytes(range(32)), "B", "654321")
    store.add_message(conv.conv_id, 0, b"hi", 0, b"\x03" * 16)
    store.shred_conv(conv.conv_id)
    with pytest.raises(StorageError):
        store.conv_secret(conv.conv_id)
    assert store.messages(conv.conv_id) == []
    assert store.list_convs() == []
    store.close()


def test_expiry_wipes_messages_and_conversations(env):
    ident = unlock(load_file_identity(env / "identity.json"))
    store = make_store(env, ident)
    conv = store.create_conv(b"\x01" * 32, bytes(range(32)), "A", "111111", now=1000, ttl=10)
    store.add_message(conv.conv_id, 1, b"ephemeral", 0, None, sent_at=1000, ttl=10)
    assert len(store.messages(conv.conv_id, now=1005)) == 1
    convs, msgs = store.expire(now=1011)
    assert convs == 1
    assert store.messages(conv.conv_id) == []
    assert store.list_convs(now=1011) == []
    store.close()


def test_ratchet_state_persists_encrypted(env):
    ident = unlock(load_file_identity(env / "identity.json"))
    store = make_store(env, ident)
    conv = store.create_conv(b"\x01" * 32, bytes(range(32)), "A", "222222")
    chains = initial_chains(bytes(range(32)), "A")
    store.save_ratchet(conv.conv_id, chains)
    loaded = store.load_ratchet(conv.conv_id)
    assert loaded == chains
    raw = store.path.read_bytes()
    assert chains.send.key not in raw
    store.close()


def test_identity_mismatch_rejected(env):
    id1 = unlock(load_file_identity(env / "identity.json"))
    store = make_store(env, id1, "one.db")
    store.close()
    id2 = unlock(load_file_identity(env / "identity2.json"))
    with pytest.raises(IdentityMismatch):
        make_store(env, id2, "one.db")


def test_wipe_removes_identity_binding(env):
    ident = unlock(load_file_identity(env / "identity.json"))
    store = make_store(env, ident)
    conv = store.create_conv(b"\x01" * 32, bytes(range(32)), "A", "333333")
    store.add_message(conv.conv_id, 1, b"secret", 0, None)
    store.wipe()
    assert store.list_convs() == []
    with pytest.raises(StorageError):
        store.identity
    store.close()
