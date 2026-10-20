"""Relay persistence.

Two implementations:

* :class:`PostgresStore` is used by the Docker deployment.  It stores only
  opaque ids, opaque payloads and expiry timestamps.
* :class:`MemoryStore` is used by the test suite.  It has the same semantics,
  including atomic one-time invite redemption.

No method logs content, ids or peer addresses.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Optional, Protocol

try:  # imported only when a Postgres URL is actually used
    import psycopg
except Exception:  # pragma: no cover
    psycopg = None  # type: ignore[assignment]


@dataclass(frozen=True)
class Invite:
    payload: bytes
    expires_at: int


@dataclass(frozen=True)
class Envelope:
    envelope_id: bytes
    payload: bytes
    created_at: int
    expires_at: int


class RelayStore(Protocol):
    def redeem_invite(self, invite_id: bytes, now: int) -> Optional[Invite]: ...

    def put_invite(self, invite_id: bytes, payload: bytes, now: int, expires_at: int) -> None: ...

    def delete_invite(self, invite_id: bytes) -> bool: ...

    def put_envelope(
        self,
        envelope_id: bytes,
        mailbox_id: bytes,
        payload: bytes,
        now: int,
        expires_at: int,
    ) -> None: ...

    def list_envelopes(self, mailbox_id: bytes, now: int) -> list[Envelope]: ...

    def count_envelopes(self, mailbox_id: bytes, now: int) -> int: ...

    def delete_envelope(self, mailbox_id: bytes, envelope_id: bytes) -> bool: ...

    def delete_mailbox(self, mailbox_id: bytes) -> int: ...

    def sweep(self, now: int) -> tuple[int, int]: ...


SCHEMA = """
CREATE TABLE IF NOT EXISTS invites (
    invite_id  BYTEA PRIMARY KEY,
    payload    BYTEA NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS envelopes (
    envelope_id BYTEA PRIMARY KEY,
    mailbox_id  BYTEA NOT NULL,
    payload     BYTEA NOT NULL,
    created_at  BIGINT NOT NULL,
    expires_at  BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS envelopes_mailbox_idx
    ON envelopes (mailbox_id, created_at);
CREATE INDEX IF NOT EXISTS envelopes_expiry_idx
    ON envelopes (expires_at);
CREATE INDEX IF NOT EXISTS invites_expiry_idx
    ON invites (expires_at);
"""


class PostgresStore:
    """Small, synchronous store.  Run endpoints in the threadpool."""

    def __init__(self, database_url: str) -> None:
        if psycopg is None:
            raise RuntimeError("psycopg is required for the Postgres store")
        self.database_url = database_url
        self._schema_ready = False
        self._schema_lock = threading.Lock()

    def _connect(self):
        return psycopg.connect(self.database_url, autocommit=True)

    def _ensure_schema(self, conn) -> None:
        if self._schema_ready:
            return
        with self._schema_lock:
            if not self._schema_ready:
                with conn.cursor() as cur:
                    cur.execute(SCHEMA)
                self._schema_ready = True

    def put_invite(self, invite_id: bytes, payload: bytes, now: int, expires_at: int) -> None:
        with self._connect() as conn:
            self._ensure_schema(conn)
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO invites (invite_id, payload, created_at, expires_at)"
                    " VALUES (%s, %s, %s, %s)",
                    (invite_id, payload, now, expires_at),
                )

    def redeem_invite(self, invite_id: bytes, now: int) -> Optional[Invite]:
        with self._connect() as conn:
            self._ensure_schema(conn)
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM invites WHERE invite_id = %s AND expires_at > %s"
                    " RETURNING payload, expires_at",
                    (invite_id, now),
                )
                row = cur.fetchone()
        return Invite(payload=bytes(row[0]), expires_at=int(row[1])) if row else None

    def delete_invite(self, invite_id: bytes) -> bool:
        with self._connect() as conn:
            self._ensure_schema(conn)
            with conn.cursor() as cur:
                cur.execute("DELETE FROM invites WHERE invite_id = %s", (invite_id,))
                return cur.rowcount > 0

    def put_envelope(
        self,
        envelope_id: bytes,
        mailbox_id: bytes,
        payload: bytes,
        now: int,
        expires_at: int,
    ) -> None:
        with self._connect() as conn:
            self._ensure_schema(conn)
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO envelopes"
                    " (envelope_id, mailbox_id, payload, created_at, expires_at)"
                    " VALUES (%s, %s, %s, %s, %s)",
                    (envelope_id, mailbox_id, payload, now, expires_at),
                )

    def list_envelopes(self, mailbox_id: bytes, now: int) -> list[Envelope]:
        with self._connect() as conn:
            self._ensure_schema(conn)
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT envelope_id, payload, created_at, expires_at"
                    " FROM envelopes WHERE mailbox_id = %s AND expires_at > %s"
                    " ORDER BY created_at ASC",
                    (mailbox_id, now),
                )
                rows = cur.fetchall()
        return [
            Envelope(
                envelope_id=bytes(row[0]),
                payload=bytes(row[1]),
                created_at=int(row[2]),
                expires_at=int(row[3]),
            )
            for row in rows
        ]

    def count_envelopes(self, mailbox_id: bytes, now: int) -> int:
        with self._connect() as conn:
            self._ensure_schema(conn)
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM envelopes"
                    " WHERE mailbox_id = %s AND expires_at > %s",
                    (mailbox_id, now),
                )
                row = cur.fetchone()
        return int(row[0]) if row else 0

    def delete_envelope(self, mailbox_id: bytes, envelope_id: bytes) -> bool:
        with self._connect() as conn:
            self._ensure_schema(conn)
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM envelopes WHERE envelope_id = %s AND mailbox_id = %s",
                    (envelope_id, mailbox_id),
                )
                return cur.rowcount > 0

    def delete_mailbox(self, mailbox_id: bytes) -> int:
        with self._connect() as conn:
            self._ensure_schema(conn)
            with conn.cursor() as cur:
                cur.execute("DELETE FROM envelopes WHERE mailbox_id = %s", (mailbox_id,))
                return int(cur.rowcount)

    def sweep(self, now: int) -> tuple[int, int]:
        with self._connect() as conn:
            self._ensure_schema(conn)
            with conn.cursor() as cur:
                cur.execute("DELETE FROM invites WHERE expires_at <= %s", (now,))
                invites = int(cur.rowcount)
                cur.execute("DELETE FROM envelopes WHERE expires_at <= %s", (now,))
                envelopes = int(cur.rowcount)
        return invites, envelopes


class MemoryStore:
    """Thread-safe in-memory store with the production semantics."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._invites: dict[bytes, tuple[bytes, int]] = {}
        self._envelopes: dict[bytes, tuple[bytes, bytes, int, int]] = {}

    def put_invite(self, invite_id: bytes, payload: bytes, now: int, expires_at: int) -> None:
        with self._lock:
            if invite_id in self._invites:
                raise ValueError("invite already exists")
            self._invites[invite_id] = (payload, expires_at)

    def redeem_invite(self, invite_id: bytes, now: int) -> Optional[Invite]:
        with self._lock:
            item = self._invites.pop(invite_id, None)
        if item is None:
            return None
        payload, expires_at = item
        return Invite(payload=payload, expires_at=expires_at) if expires_at > now else None

    def delete_invite(self, invite_id: bytes) -> bool:
        with self._lock:
            return self._invites.pop(invite_id, None) is not None

    def put_envelope(
        self,
        envelope_id: bytes,
        mailbox_id: bytes,
        payload: bytes,
        now: int,
        expires_at: int,
    ) -> None:
        with self._lock:
            self._envelopes[envelope_id] = (mailbox_id, payload, now, expires_at)

    def list_envelopes(self, mailbox_id: bytes, now: int) -> list[Envelope]:
        with self._lock:
            rows = [
                (eid, payload, created, expires)
                for eid, (mbx, payload, created, expires) in self._envelopes.items()
                if mbx == mailbox_id and expires > now
            ]
        rows.sort(key=lambda row: row[2])
        return [
            Envelope(envelope_id=eid, payload=payload, created_at=created, expires_at=expires)
            for eid, payload, created, expires in rows
        ]

    def count_envelopes(self, mailbox_id: bytes, now: int) -> int:
        with self._lock:
            return sum(
                1
                for mbx, _, _, expires in self._envelopes.values()
                if mbx == mailbox_id and expires > now
            )

    def delete_envelope(self, mailbox_id: bytes, envelope_id: bytes) -> bool:
        with self._lock:
            item = self._envelopes.get(envelope_id)
            if item is None or item[0] != mailbox_id:
                return False
            del self._envelopes[envelope_id]
            return True

    def delete_mailbox(self, mailbox_id: bytes) -> int:
        with self._lock:
            ids = [eid for eid, (mbx, _, _, _) in self._envelopes.items() if mbx == mailbox_id]
            for eid in ids:
                del self._envelopes[eid]
        return len(ids)

    def sweep(self, now: int) -> tuple[int, int]:
        with self._lock:
            invites = [iid for iid, (_, expires) in self._invites.items() if expires <= now]
            for iid in invites:
                del self._invites[iid]
            envelopes = [
                eid for eid, (_, _, _, expires) in self._envelopes.items() if expires <= now
            ]
            for eid in envelopes:
                del self._envelopes[eid]
        return len(invites), len(envelopes)
