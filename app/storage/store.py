"""SQLite storage with per-record AEAD and crypto-shredding.

Every sensitive record is encrypted at the application layer:

* the conversation secret with the master KEK derived from the identity key;
* each message body with a fresh per-message DEK (AES-256-GCM);
* each DEK with the conversation secret;
* ratchet state with the master KEK.

Deletion is crypto-shredding: the DEK and ciphertext columns are overwritten
with zeros before the row is removed, and SQLite runs with ``secure_delete``.
Nothing in the database is decryptable without the identity key.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import ttl_seconds
from crypto.constants import WRAP_INFO
from crypto.padding import pad, unpad
from crypto.primitives import hkdf
from crypto.ratchet import ChainState, Chains


class StorageError(RuntimeError):
    pass


class IdentityMismatch(StorageError):
    pass


def _seal(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    iv = os.urandom(12)
    return AESGCM(key).encrypt(iv, plaintext, aad), iv


def _open(key: bytes, ciphertext: bytes, iv: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(iv, ciphertext, aad)
    except Exception as exc:
        raise StorageError("record authentication failed") from exc


@dataclass(frozen=True)
class ConversationRow:
    conv_id: bytes
    peer_key_id: bytes
    role: str
    sas: str
    created_at: int
    expires_at: int
    last_day: Optional[int]


@dataclass(frozen=True)
class MessageRow:
    msg_id: bytes
    conv_id: bytes
    direction: int
    plaintext: bytes
    sent_at: int
    expires_at: int
    counter: int


SCHEMA = """
CREATE TABLE IF NOT EXISTS identity (
  key_id        BLOB PRIMARY KEY,
  pubkey        BLOB NOT NULL,
  storage       TEXT NOT NULL,
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS conv (
  conv_id       BLOB PRIMARY KEY,
  peer_key_id   BLOB NOT NULL,
  conv_key_enc  BLOB NOT NULL,
  conv_key_iv   BLOB NOT NULL,
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  role          TEXT NOT NULL,
  sas           TEXT NOT NULL,
  ratchet_enc   BLOB,
  ratchet_iv    BLOB,
  last_day      INTEGER
);

CREATE TABLE IF NOT EXISTS msg (
  msg_id        BLOB PRIMARY KEY,
  conv_id       BLOB NOT NULL,
  direction     INTEGER NOT NULL,
  ct            BLOB NOT NULL,
  ct_iv         BLOB NOT NULL,
  dek_enc       BLOB NOT NULL,
  dek_iv        BLOB NOT NULL,
  sent_at       INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  counter       INTEGER NOT NULL,
  mailbox_id    BLOB,
  UNIQUE (conv_id, direction, counter)
);

CREATE INDEX IF NOT EXISTS msg_expiry ON msg (expires_at);
CREATE INDEX IF NOT EXISTS msg_conv ON msg (conv_id, sent_at);
CREATE INDEX IF NOT EXISTS conv_expiry ON conv (expires_at);
"""


class CipherStore:
    def __init__(self, path: Path | str, kek: bytes, identity_key_id: bytes, identity_pub: bytes, storage_mode: str) -> None:
        self.path = Path(path)
        self._kek = kek
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.execute("PRAGMA secure_delete=ON")
            self._db.execute("PRAGMA journal_mode=DELETE")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.executescript(SCHEMA)
            self._bind_identity(identity_key_id, identity_pub, storage_mode)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # -- identity ---------------------------------------------------------
    def _bind_identity(self, key_id: bytes, pubkey: bytes, storage_mode: str) -> None:
        row = self._db.execute("SELECT key_id, storage FROM identity LIMIT 1").fetchone()
        if row is None:
            self._db.execute(
                "INSERT INTO identity (key_id, pubkey, storage, created_at) VALUES (?,?,?,?)",
                (key_id, pubkey, storage_mode, int(time.time())),
            )
            return
        if bytes(row["key_id"]) != key_id:
            raise IdentityMismatch("database belongs to a different identity")

    @property
    def identity(self) -> tuple[bytes, bytes, str, int]:
        row = self._db.execute("SELECT * FROM identity LIMIT 1").fetchone()
        if row is None:
            raise StorageError("no identity")
        return bytes(row["key_id"]), bytes(row["pubkey"]), str(row["storage"]), int(row["created_at"])

    # -- conversations ----------------------------------------------------
    def create_conv(
        self,
        peer_key_id: bytes,
        conv_secret: bytes,
        role: str,
        sas: str,
        now: Optional[int] = None,
        ttl: Optional[int] = None,
    ) -> ConversationRow:
        now = int(time.time()) if now is None else now
        ttl = ttl_seconds() if ttl is None else ttl
        conv_id = secrets.token_bytes(16)
        enc, iv = _seal(self._kek, conv_secret, b"conv:" + conv_id)
        with self._lock:
            self._db.execute(
                "INSERT INTO conv (conv_id, peer_key_id, conv_key_enc, conv_key_iv,"
                " created_at, expires_at, role, sas) VALUES (?,?,?,?,?,?,?,?)",
                (conv_id, peer_key_id, enc, iv, now, now + ttl, role, sas),
            )
        return ConversationRow(conv_id, peer_key_id, role, sas, now, now + ttl, None)

    def conv_secret(self, conv_id: bytes) -> bytes:
        row = self._db.execute(
            "SELECT conv_key_enc, conv_key_iv FROM conv WHERE conv_id=?", (conv_id,)
        ).fetchone()
        if row is None:
            raise StorageError("conversation not found")
        return _open(self._kek, bytes(row["conv_key_enc"]), bytes(row["conv_key_iv"]), b"conv:" + conv_id)

    def get_conv(self, conv_id: bytes) -> ConversationRow:
        row = self._db.execute("SELECT * FROM conv WHERE conv_id=?", (conv_id,)).fetchone()
        if row is None:
            raise StorageError("conversation not found")
        return self._conv_row(row)

    def list_convs(self, now: Optional[int] = None) -> list[ConversationRow]:
        now = int(time.time()) if now is None else now
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM conv WHERE expires_at > ? ORDER BY created_at DESC", (now,)
            ).fetchall()
        return [self._conv_row(r) for r in rows]

    def conv_by_peer(self, peer_key_id: bytes) -> Optional[ConversationRow]:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM conv WHERE peer_key_id=? ORDER BY created_at DESC LIMIT 1",
                (peer_key_id,),
            ).fetchone()
        return self._conv_row(row) if row is not None else None

    def _conv_row(self, row: sqlite3.Row) -> ConversationRow:
        return ConversationRow(
            conv_id=bytes(row["conv_id"]),
            peer_key_id=bytes(row["peer_key_id"]),
            role=str(row["role"]),
            sas=str(row["sas"]),
            created_at=int(row["created_at"]),
            expires_at=int(row["expires_at"]),
            last_day=int(row["last_day"]) if row["last_day"] is not None else None,
        )

    # -- ratchet state ----------------------------------------------------
    def save_ratchet(self, conv_id: bytes, chains: Chains) -> None:
        raw = chains.send.serialize() + chains.recv.serialize()
        enc, iv = _seal(self._kek, raw, b"ratchet:" + conv_id)
        with self._lock:
            self._db.execute(
                "UPDATE conv SET ratchet_enc=?, ratchet_iv=? WHERE conv_id=?",
                (enc, iv, conv_id),
            )

    def load_ratchet(self, conv_id: bytes) -> Optional[Chains]:
        row = self._db.execute(
            "SELECT ratchet_enc, ratchet_iv FROM conv WHERE conv_id=?", (conv_id,)
        ).fetchone()
        if row is None or row["ratchet_enc"] is None:
            return None
        raw = _open(self._kek, bytes(row["ratchet_enc"]), bytes(row["ratchet_iv"]), b"ratchet:" + conv_id)
        if len(raw) != 80:
            raise StorageError("invalid ratchet state")
        return Chains(ChainState.deserialize(raw[:40]), ChainState.deserialize(raw[40:]))

    def set_last_day(self, conv_id: bytes, day: int) -> None:
        with self._lock:
            self._db.execute("UPDATE conv SET last_day=? WHERE conv_id=?", (day, conv_id))

    # -- messages ---------------------------------------------------------
    def add_message(
        self,
        conv_id: bytes,
        direction: int,
        plaintext: bytes,
        counter: int,
        mailbox_id: Optional[bytes],
        sent_at: Optional[int] = None,
        ttl: Optional[int] = None,
    ) -> MessageRow:
        sent_at = int(time.time()) if sent_at is None else sent_at
        ttl = ttl_seconds() if ttl is None else ttl
        msg_id = secrets.token_bytes(16)
        conv_key = self.conv_secret(conv_id)
        wrap_key = hkdf(conv_key, WRAP_INFO, 32)
        dek = secrets.token_bytes(32)
        ct, ct_iv = _seal(dek, pad(plaintext), b"msg:" + msg_id)
        dek_enc, dek_iv = _seal(wrap_key, dek, b"dek:" + msg_id)
        with self._lock:
            self._db.execute(
                "INSERT INTO msg (msg_id, conv_id, direction, ct, ct_iv, dek_enc, dek_iv,"
                " sent_at, expires_at, counter, mailbox_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    msg_id,
                    conv_id,
                    direction,
                    ct,
                    ct_iv,
                    dek_enc,
                    dek_iv,
                    sent_at,
                    sent_at + ttl,
                    counter,
                    mailbox_id,
                ),
            )
        return MessageRow(msg_id, conv_id, direction, plaintext, sent_at, sent_at + ttl, counter)

    def messages(self, conv_id: bytes, now: Optional[int] = None) -> list[MessageRow]:
        now = int(time.time()) if now is None else now
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM msg WHERE conv_id=? AND expires_at>? ORDER BY sent_at ASC",
                (conv_id, now),
            ).fetchall()
        return [self._message_row(r) for r in rows]

    def _message_row(self, row: sqlite3.Row) -> MessageRow:
        msg_id = bytes(row["msg_id"])
        conv_key = self.conv_secret(bytes(row["conv_id"]))
        wrap_key = hkdf(conv_key, WRAP_INFO, 32)
        dek = _open(wrap_key, bytes(row["dek_enc"]), bytes(row["dek_iv"]), b"dek:" + msg_id)
        padded = _open(dek, bytes(row["ct"]), bytes(row["ct_iv"]), b"msg:" + msg_id)
        return MessageRow(
            msg_id=msg_id,
            conv_id=bytes(row["conv_id"]),
            direction=int(row["direction"]),
            plaintext=unpad(padded),
            sent_at=int(row["sent_at"]),
            expires_at=int(row["expires_at"]),
            counter=int(row["counter"]),
        )

    # -- shredding --------------------------------------------------------
    def shred_message(self, msg_id: bytes) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE msg SET dek_enc=zeroblob(length(dek_enc)), ct=zeroblob(length(ct)),"
                " dek_iv=zeroblob(length(dek_iv)), ct_iv=zeroblob(length(ct_iv)) WHERE msg_id=?",
                (msg_id,),
            )
            self._db.execute("DELETE FROM msg WHERE msg_id=?", (msg_id,))

    def shred_conv(self, conv_id: bytes) -> None:
        with self._lock:
            rows = self._db.execute("SELECT msg_id FROM msg WHERE conv_id=?", (conv_id,)).fetchall()
            for row in rows:
                self.shred_message(bytes(row["msg_id"]))
            self._db.execute(
                "UPDATE conv SET conv_key_enc=zeroblob(length(conv_key_enc)),"
                " conv_key_iv=zeroblob(length(conv_key_iv)), ratchet_enc=NULL, ratchet_iv=NULL"
                " WHERE conv_id=?",
                (conv_id,),
            )
            self._db.execute("DELETE FROM conv WHERE conv_id=?", (conv_id,))

    def expire(self, now: Optional[int] = None) -> tuple[int, int]:
        now = int(time.time()) if now is None else now
        expired_msgs = 0
        expired_convs = 0
        with self._lock:
            for row in self._db.execute("SELECT conv_id FROM conv WHERE expires_at<=?", (now,)).fetchall():
                self.shred_conv(bytes(row["conv_id"]))
                expired_convs += 1
            for row in self._db.execute("SELECT msg_id FROM msg WHERE expires_at<=?", (now,)).fetchall():
                self.shred_message(bytes(row["msg_id"]))
                expired_msgs += 1
        return expired_convs, expired_msgs

    def wipe(self) -> None:
        """Destroy every row, then vacuum so the freed pages are rewritten."""
        with self._lock:
            for table in ("msg", "conv", "identity"):
                self._db.execute(f"DELETE FROM {table}")
            self._db.execute("VACUUM")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def close(self) -> None:
        with self._lock:
            self._db.close()
