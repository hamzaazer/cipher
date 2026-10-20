"""Play Integrity verification for invite creation.

Only invite creation is gated.  Message deposit and drain must stay available
to existing conversations even if Google's service is unreachable.

If the relay is configured to require Play Integrity but no verifier can be
built (missing credentials or missing ``google-auth``), invite creation fails
closed with 503.  It never silently degrades to "no check".
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Optional, Protocol

try:
    import httpx
except Exception:  # pragma: no cover
    httpx = None  # type: ignore[assignment]


class IntegrityError(RuntimeError):
    pass


class IntegrityUnavailable(IntegrityError):
    pass


class Verifier(Protocol):
    def verify(self, token: str, nonce: str) -> bool: ...


class GooglePlayIntegrity:
    """Verify a standard Play Integrity token for one package."""

    SCOPE = "https://www.googleapis.com/auth/playintegrity"

    def __init__(self, package: str, credentials: str) -> None:
        if httpx is None:
            raise IntegrityUnavailable("httpx is required")
        try:
            from google.auth.transport.requests import AuthorizedSession
            from google.oauth2 import service_account
        except Exception as exc:
            raise IntegrityUnavailable("google-auth is not installed") from exc

        if credentials.strip().startswith("{"):
            info = json.loads(credentials)
            self._credentials = service_account.Credentials.from_service_account_info(
                info, scopes=[self.SCOPE]
            )
        else:
            self._credentials = service_account.Credentials.from_service_account_file(
                credentials, scopes=[self.SCOPE]
            )
        self._session = AuthorizedSession(self._credentials)
        self._package = package
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[bool, float]] = {}

    def verify(self, token: str, nonce: str) -> bool:
        if not token:
            return False
        key = token[-32:] if len(token) > 32 else token
        now = time.time()
        with self._lock:
            cached = self._cache.get(key)
            if cached and cached[1] > now:
                return cached[0]

        url = (
            "https://playintegrity.googleapis.com/v1/"
            f"{self._package}:decodeIntegrityToken"
        )
        try:
            response = self._session.post(
                url, json={"integrity_token": token}, timeout=5
            )
            if response.status_code != 200:
                return False
            payload = response.json().get("tokenPayloadExternal", {})
        except Exception:
            return False

        ok = _valid_payload(payload, self._package, nonce)
        with self._lock:
            if len(self._cache) > 2048:
                self._cache.clear()
            self._cache[key] = (ok, now + 60)
        return ok


def _valid_payload(payload: dict[str, Any], package: str, nonce: str) -> bool:
    request_details = payload.get("requestDetails") or {}
    app_integrity = payload.get("appIntegrity") or {}
    device_integrity = payload.get("deviceIntegrity") or {}

    if request_details.get("requestPackageName") != package:
        return False
    if nonce and request_details.get("nonce") != nonce:
        return False
    if app_integrity.get("appRecognitionVerdict") != "PLAY_RECOGNIZED":
        return False
    verdicts = device_integrity.get("deviceRecognitionVerdict") or []
    return "MEETS_DEVICE_INTEGRITY" in verdicts


def make_verifier(required: bool, package: str, credentials: str) -> Optional[Verifier]:
    if not required:
        return None
    if not credentials.strip():
        return None
    try:
        return GooglePlayIntegrity(package, credentials)
    except Exception:
        return None
