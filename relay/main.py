"""Cipher relay - blind store-and-forward service.

The relay only ever sees opaque mailbox ids, opaque payloads and expiry times.
It has no accounts, no content logs, no request logging and no backups of
message content.

Invites are one-time: ``GET /v1/invite/{id}`` atomically deletes the row before
returning it, so two devices racing for the same invite cannot both pair.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import secrets
import time
from contextlib import asynccontextmanager
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from integrity import IntegrityUnavailable, Verifier, make_verifier
from ratelimit import SlidingWindowLimiter
from settings import Settings, get_settings
from store import PostgresStore, RelayStore

_SECURITY_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


class InviteRequest(BaseModel):
    # Client-supplied SHA-256(S), hex.  The client must be able to derive the
    # invite id from the out-of-band secret alone; the relay never learns S.
    invite_id: str
    payload: str
    integrity_token: Optional[str] = None
    integrity_nonce: Optional[str] = None


class EnvelopeRequest(BaseModel):
    payload: str
    # Optional short TTL, used by the pairing handshake.  Bounded by the
    # deployment's normal envelope TTL.
    ttl: Optional[int] = None


def _now() -> int:
    return int(time.time())


def _b64(value: str, max_bytes: int) -> bytes:
    if not isinstance(value, str) or not value:
        raise HTTPException(status_code=400, detail="invalid_payload")
    # Reject obviously oversized input before allocating the decode buffer.
    if len(value) > (max_bytes * 4 // 3) + 16:
        raise HTTPException(status_code=413, detail="payload_too_large")
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=400, detail="invalid_payload") from exc
    if not data:
        raise HTTPException(status_code=400, detail="invalid_payload")
    if len(data) > max_bytes:
        raise HTTPException(status_code=413, detail="payload_too_large")
    return data


def _id(value: str, length: int = 16) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="not_found") from exc
    if len(raw) != length:
        raise HTTPException(status_code=404, detail="not_found")
    return raw


def _new_id() -> bytes:
    return secrets.token_bytes(16)


def _hex(value: bytes) -> str:
    return value.hex()


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def create_app(
    settings: Settings | None = None,
    store: RelayStore | None = None,
    integrity: Verifier | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    relay_store = store or PostgresStore(settings.database_url)
    verifier = integrity if integrity is not None else make_verifier(
        settings.play_integrity_required,
        settings.play_integrity_package,
        settings.play_integrity_credentials,
    )
    limiter = SlidingWindowLimiter(
        settings.invite_rate_limit, settings.invite_rate_window_seconds
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        task: Optional[asyncio.Task[Any]] = None
        if settings.sweeper_interval_seconds > 0:
            task = asyncio.create_task(
                _sweeper(relay_store, settings.sweeper_interval_seconds)
            )
        yield
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    app = FastAPI(
        title="Cipher Relay",
        version="0.3.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.store = relay_store
    app.state.integrity = verifier

    @app.middleware("http")
    async def guard(request: Request, call_next):
        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                if int(declared) > settings.max_request_bytes:
                    response = JSONResponse(
                        status_code=413, content={"detail": "request_too_large"}
                    )
                    response.headers.update(_SECURITY_HEADERS)
                    return response
            except ValueError:
                response = JSONResponse(
                    status_code=400, content={"detail": "invalid_content_length"}
                )
                response.headers.update(_SECURITY_HEADERS)
                return response
        response = await call_next(request)
        response.headers.update(_SECURITY_HEADERS)
        return response

    @app.get("/healthz")
    async def healthz() -> dict[str, object]:
        return {
            "status": "ok",
            "service": "cipher-relay",
            "time": _now(),
        }

    @app.post("/v1/invite", status_code=201)
    def create_invite(body: InviteRequest, request: Request) -> dict[str, Any]:
        if not limiter.allow(_client_key(request)):
            raise HTTPException(status_code=429, detail="rate_limited")
        if settings.play_integrity_required:
            if verifier is None:
                raise HTTPException(status_code=503, detail="integrity_not_configured")
            try:
                ok = verifier.verify(
                    body.integrity_token or "", body.integrity_nonce or ""
                )
            except IntegrityUnavailable:
                raise HTTPException(status_code=503, detail="integrity_unavailable")
            if not ok:
                raise HTTPException(status_code=403, detail="integrity_failed")

        payload = _b64(body.payload, settings.max_invite_bytes)
        invite_id = _id(body.invite_id, 32)
        expires_at = _now() + settings.invite_ttl_seconds
        try:
            relay_store.put_invite(invite_id, payload, _now(), expires_at)
        except Exception as exc:
            # Never log the id.  A duplicate means another client already
            # registered this secret-derived address; do not overwrite it.
            if exc.__class__.__name__ in {"UniqueViolation", "ValueError"}:
                raise HTTPException(status_code=409, detail="invite_exists") from exc
            raise
        return {
            "invite_id": _hex(invite_id),
            "expires_at": expires_at,
            "ttl": settings.invite_ttl_seconds,
        }

    @app.get("/v1/invite/{invite_id}")
    def redeem_invite(invite_id: str) -> dict[str, Any]:
        record = relay_store.redeem_invite(_id(invite_id, 32), _now())
        if record is None:
            raise HTTPException(status_code=404, detail="not_found")
        return {
            "payload": base64.b64encode(record.payload).decode("ascii"),
            "expires_at": record.expires_at,
        }

    @app.delete("/v1/invite/{invite_id}", status_code=204)
    def revoke_invite(invite_id: str) -> Response:
        relay_store.delete_invite(_id(invite_id, 32))
        # Always 204: whether the invite existed is not observable.
        return Response(status_code=204)

    @app.post("/v1/mailbox/{mailbox_id}", status_code=201)
    def deposit(mailbox_id: str, body: EnvelopeRequest) -> dict[str, Any]:
        mailbox = _id(mailbox_id)
        payload = _b64(body.payload, settings.max_payload_bytes)
        ttl = settings.ttl_seconds
        if body.ttl is not None:
            if body.ttl < 1 or body.ttl > settings.ttl_seconds:
                raise HTTPException(status_code=400, detail="invalid_ttl")
            ttl = body.ttl
        now = _now()
        if relay_store.count_envelopes(mailbox, now) >= settings.max_envelopes_per_mailbox:
            raise HTTPException(status_code=429, detail="mailbox_full")
        envelope_id = _new_id()
        expires_at = now + ttl
        relay_store.put_envelope(envelope_id, mailbox, payload, now, expires_at)
        return {"envelope_id": _hex(envelope_id), "expires_at": expires_at}

    @app.get("/v1/mailbox/{mailbox_id}")
    def drain(mailbox_id: str) -> dict[str, Any]:
        rows = relay_store.list_envelopes(_id(mailbox_id), _now())
        return {
            "now": _now(),
            "envelopes": [
                {
                    "envelope_id": _hex(row.envelope_id),
                    "payload": base64.b64encode(row.payload).decode("ascii"),
                    "created_at": row.created_at,
                    "expires_at": row.expires_at,
                }
                for row in rows
            ],
        }

    @app.delete("/v1/mailbox/{mailbox_id}/{envelope_id}", status_code=204)
    def ack(mailbox_id: str, envelope_id: str) -> Response:
        if not relay_store.delete_envelope(_id(mailbox_id), _id(envelope_id)):
            raise HTTPException(status_code=404, detail="not_found")
        return Response(status_code=204)

    @app.delete("/v1/mailbox/{mailbox_id}")
    def purge(mailbox_id: str) -> dict[str, int]:
        return {"deleted": relay_store.delete_mailbox(_id(mailbox_id))}

    return app


async def _sweeper(store: RelayStore, interval: int) -> None:
    while True:
        try:
            await asyncio.to_thread(store.sweep, _now())
        except Exception:
            # Never log payloads or ids.  The next tick retries.
            pass
        await asyncio.sleep(max(1, interval))


app = create_app()
