"""Relay HTTP client with application-layer SPKI pinning.

Android's network security config is not visible to Python.  Every TLS
connection is therefore checked here as well: after the handshake we compute
SHA-256 over the leaf certificate's SubjectPublicKeyInfo and compare it with
the embedded pin set in constant time.  A mismatch closes the connection and
raises; there is no retry-without-pinning path.

Cleartext is refused outside the explicit test profile.  A release build with
no pins configured also refuses to connect (fail closed).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from config import release

MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class RelayError(RuntimeError):
    pass


class PinMismatch(RelayError):
    pass


class RelayNotFound(RelayError):
    pass


class RelayRateLimited(RelayError):
    pass


def spki_sha256(der_certificate: bytes) -> str:
    cert = x509.load_der_x509_certificate(der_certificate)
    spki = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def pin_matches(der_certificate: bytes, pins: tuple[str, ...]) -> bool:
    if not pins:
        return False
    actual = spki_sha256(der_certificate)
    return any(hmac.compare_digest(actual, pin) for pin in pins)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, pins: tuple[str, ...] = (), **kwargs) -> None:
        self._pins = pins
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        super().connect()
        der = self.sock.getpeercert(binary_form=True)
        if not der or not pin_matches(der, self._pins):
            self.close()
            raise PinMismatch("relay certificate does not match the pinned SPKI")


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, pins: tuple[str, ...]) -> None:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        super().__init__(context=context)
        self._pins = pins

    def https_open(self, req):
        def factory(*args, **kwargs):
            return _PinnedHTTPSConnection(*args, pins=self._pins, **kwargs)

        return self.do_open(factory, req, context=self._context)


@dataclass(frozen=True)
class Envelope:
    envelope_id: str
    payload: bytes
    created_at: int
    expires_at: int


class RelayClient:
    def __init__(
        self,
        base_url: str,
        pins: tuple[str, ...],
        *,
        timeout: float = 10.0,
        opener: Optional[Callable[..., Any]] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.pins = pins
        self.timeout = timeout
        self._opener = opener
        if self._opener is None:
            self._opener = self._build_opener()

    def _build_opener(self) -> urllib.request.OpenerDirector:
        if self.base_url.startswith("http://"):
            if release():
                raise PinMismatch("cleartext relay URL is refused in release builds")
            return urllib.request.build_opener()
        if not self.base_url.startswith("https://"):
            raise RelayError("relay URL must use https")
        if not self.pins:
            raise PinMismatch("no relay SPKI pins configured")
        return urllib.request.build_opener(_PinnedHTTPSHandler(self.pins))

    # ---- endpoints -----------------------------------------------------

    def create_invite(
        self,
        invite_id: bytes,
        payload: bytes,
        integrity_token: str = "",
        integrity_nonce: str = "",
    ) -> dict[str, Any]:
        if len(invite_id) != 32:
            raise RelayError("invite id must be 32 bytes")
        body: dict[str, str] = {
            "invite_id": invite_id.hex(),
            "payload": _b64(payload),
        }
        if integrity_token:
            body["integrity_token"] = integrity_token
        if integrity_nonce:
            body["integrity_nonce"] = integrity_nonce
        return self._json("POST", "/v1/invite", body)

    def redeem_invite(self, invite_id: str) -> bytes:
        result = self._json("GET", f"/v1/invite/{invite_id}")
        return _unb64(result["payload"])

    def revoke_invite(self, invite_id: str) -> None:
        self._request("DELETE", f"/v1/invite/{invite_id}")

    def deposit(self, mailbox_id: str, payload: bytes, ttl: Optional[int] = None) -> str:
        body: dict[str, Any] = {"payload": _b64(payload)}
        if ttl is not None:
            body["ttl"] = int(ttl)
        result = self._json("POST", f"/v1/mailbox/{mailbox_id}", body)
        return str(result["envelope_id"])

    def drain(self, mailbox_id: str) -> list[Envelope]:
        result = self._json("GET", f"/v1/mailbox/{mailbox_id}")
        return [
            Envelope(
                envelope_id=str(item["envelope_id"]),
                payload=_unb64(item["payload"]),
                created_at=int(item["created_at"]),
                expires_at=int(item["expires_at"]),
            )
            for item in result.get("envelopes", [])
        ]

    def ack(self, mailbox_id: str, envelope_id: str) -> None:
        self._request("DELETE", f"/v1/mailbox/{mailbox_id}/{envelope_id}")

    def purge(self, mailbox_id: str) -> int:
        result = self._json("DELETE", f"/v1/mailbox/{mailbox_id}")
        return int(result.get("deleted", 0))

    # ---- transport -----------------------------------------------------

    def _json(self, method: str, path: str, body: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        raw = self._request(method, path, body)
        try:
            parsed = json.loads(raw)
        except Exception as exc:
            raise RelayError("relay returned invalid JSON") from exc
        if not isinstance(parsed, dict):
            raise RelayError("relay returned an invalid response")
        return parsed

    def _request(
        self, method: str, path: str, body: Optional[dict[str, Any]] = None
    ) -> bytes:
        data = None
        headers = {"Accept": "application/json", "Cache-Control": "no-store"}
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path, data=data, headers=headers, method=method
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise RelayError("relay response is too large")
                return raw
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise RelayNotFound("not found") from exc
            if exc.code == 429:
                raise RelayRateLimited("rate limited") from exc
            raise RelayError(f"relay returned HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, PinMismatch):
                raise exc.reason
            raise RelayError("relay is unreachable") from exc


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)
