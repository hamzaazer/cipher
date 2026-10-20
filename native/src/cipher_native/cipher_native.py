"""Python side of the Cipher native bridge.

Only three secrets-adjacent operations cross this boundary:

* ``ensureIdentity`` returns the public half of the Keystore key;
* ``sign`` returns a deterministic RSA PKCS#1 v1.5 signature;
* ``destroyIdentity`` deletes the key.

The private key is created and used entirely inside Android Keystore.  The
Dart layer only forwards method calls; it never sees key material.

The control is deliberately tiny.  It is added once to the page and stays
mounted for the lifetime of the app, so the method subscription exists before
any Python call is made.
"""

from __future__ import annotations

import base64
import json
import threading
from typing import Any, Optional

import flet as ft

API_VERSION = 1
METHOD_TIMEOUT_SECONDS = 10

_current: Optional["CipherNative"] = None
_lock = threading.Lock()


class NativeUnavailable(RuntimeError):
    """The Flutter channel did not attach (desktop, old build, plugin error)."""


def bind(control: "CipherNative") -> None:
    global _current
    with _lock:
        _current = control


def unbind(control: "CipherNative") -> None:
    global _current
    with _lock:
        if _current is control:
            _current = None


def _bound() -> "CipherNative":
    with _lock:
        control = _current
    if control is None:
        raise NativeUnavailable("native control is not mounted")
    return control


def available() -> bool:
    try:
        return bool(_bound().status().get("available"))
    except Exception:
        return False


def status() -> dict[str, Any]:
    return _bound().status()


def ensure_identity_key() -> bytes:
    """Return the DER-encoded X.509 public key, creating the key if needed."""
    result = _bound().call("ensureIdentity")
    if not result.get("ok", True):
        raise NativeUnavailable(result.get("reason", "keystore error"))
    try:
        pub = base64.b64decode(result["publicKey"], validate=True)
    except Exception as exc:
        raise NativeUnavailable("native bridge returned a malformed public key") from exc
    if len(pub) < 32:
        raise NativeUnavailable("native bridge returned an empty public key")
    return pub


def sign(data: bytes) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    result = _bound().call(
        "sign", {"data": base64.b64encode(bytes(data)).decode("ascii")}
    )
    if not result.get("ok", True):
        raise NativeUnavailable(result.get("reason", "signing error"))
    try:
        signature = base64.b64decode(result["signature"], validate=True)
    except Exception as exc:
        raise NativeUnavailable("native bridge returned a malformed signature") from exc
    if len(signature) < 32:
        raise NativeUnavailable("native bridge returned an empty signature")
    return signature


def destroy_identity() -> None:
    _bound().call("destroyIdentity")


def set_secure(enabled: bool = True) -> bool:
    result = _bound().call("setSecure", {"enabled": "true" if enabled else "false"})
    return bool(result.get("secure", enabled))


class CipherNative(ft.Control):
    """Invisible control that owns the platform method subscription."""

    def __init__(self) -> None:
        super().__init__()
        self.width = 0
        self.height = 0

    def _get_control_name(self) -> str:
        return "cipher_native"

    def did_mount(self) -> None:
        bind(self)

    def will_unmount(self) -> None:
        unbind(self)

    def call(self, method: str, args: Optional[dict[str, str]] = None) -> dict[str, Any]:
        if self.page is None:
            raise NativeUnavailable("native control is not attached to a page")
        raw = self.invoke_method(
            method,
            args or {},
            wait_for_result=True,
            wait_timeout=METHOD_TIMEOUT_SECONDS,
        )
        if raw is None:
            raise NativeUnavailable("native bridge timed out")
        try:
            payload = json.loads(raw)
        except Exception as exc:
            raise NativeUnavailable("native bridge returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise NativeUnavailable("native bridge returned an invalid payload")
        return payload

    def status(self) -> dict[str, Any]:
        # Never cached: hardware/secure flags can change after key creation or
        # activity reattachment, and the security screen must probe reality.
        result = self.call("status")
        if not result.get("available"):
            raise NativeUnavailable(result.get("reason", "native bridge unavailable"))
        return result
