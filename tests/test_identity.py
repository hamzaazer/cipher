import base64

import pytest

import cipher_native
import identity as identity_module
from cipher_native import cipher_native as bridge
from identity import IdentityError, load_identity, unlock
from ui.security import SecurityState, banner, status_line


PUB = b"\x11" * 91
SIG = b"\x22" * 256


class FakeControl:
    def __init__(self, available: bool = True) -> None:
        self._available = available
        self.calls = []

    def status(self):
        if not self._available:
            return {"available": False, "reason": "plugin_not_registered"}
        return {
            "available": True,
            "ok": True,
            "hardware": True,
            "strongbox": False,
            "secure": True,
            "sdk": 34,
            "identity": True,
        }

    def call(self, method, args=None):
        self.calls.append((method, args or {}))
        if method == "ensureIdentity":
            return {"available": True, "ok": True, "publicKey": base64.b64encode(PUB).decode()}
        if method == "sign":
            assert base64.b64decode(args["data"]) == b"payload"
            return {"available": True, "ok": True, "signature": base64.b64encode(SIG).decode()}
        if method == "destroyIdentity":
            return {"available": True, "ok": True}
        if method == "setSecure":
            return {"available": True, "ok": True, "secure": True}
        raise AssertionError(method)


class FakeNativeModule:
    def available(self):
        return True

    def ensure_identity_key(self):
        return PUB

    def sign(self, data):
        return SIG

    def destroy_identity(self):
        pass


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("CIPHER_DATA_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture(autouse=True)
def clean_binding():
    bridge._current = None
    yield
    bridge._current = None


def test_bridge_roundtrip():
    control = FakeControl()
    cipher_native.bind(control)
    assert cipher_native.available()
    assert cipher_native.ensure_identity_key() == PUB
    assert cipher_native.sign(b"payload") == SIG
    cipher_native.destroy_identity()
    assert cipher_native.set_secure() is True
    assert [c[0] for c in control.calls] == [
        "ensureIdentity",
        "sign",
        "destroyIdentity",
        "setSecure",
    ]


def test_bridge_fails_closed_when_unbound():
    assert not cipher_native.available()
    with pytest.raises(cipher_native.NativeUnavailable):
        cipher_native.ensure_identity_key()


def test_load_identity_prefers_native(env, monkeypatch):
    monkeypatch.setattr(identity_module, "_native_module", lambda: FakeNativeModule())
    backend = load_identity()
    assert backend.storage == "keystore"
    ident = unlock(backend)
    assert ident.storage == "keystore"
    assert len(ident.kek) == 32
    assert backend.public_key == PUB
    assert backend.sign(b"payload") == SIG


def test_native_signature_failure_is_not_silent(env, monkeypatch):
    class Broken(FakeNativeModule):
        def sign(self, data):
            return b""

    monkeypatch.setattr(identity_module, "_native_module", lambda: Broken())
    backend = load_identity()
    with pytest.raises(IdentityError):
        unlock(backend)


def test_degraded_banner_and_status_are_explicit():
    degraded = SecurityState(native=False, secure_screen=False, hardware=False)
    assert banner(degraded) is not None
    assert status_line(degraded) is not None

    class FakeIdentity:
        storage = "file"

    degraded.identity = FakeIdentity()  # type: ignore[assignment]
    control = banner(degraded)
    assert control is not None
    assert "DEGRADED" in control.content.controls[1].value
