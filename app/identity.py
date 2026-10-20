"""Identity backends.

Preferred: the native shim's Android Keystore key.  The private key never
leaves Keystore; Python only receives the public key and signatures.

Fallback: a file-based Ed25519 key in app-private storage.  This is explicitly
*degraded*: it is root-readable and gets no hardware binding.  The app must
surface that fact (see ``ui.security`` and ``ui.shell``), and never claim
Keystore storage when the native channel did not attach.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from crypto.constants import KEK_INFO
from crypto.primitives import fingerprint, kek_from_signature
from paths import identity_path


class IdentityError(RuntimeError):
    pass


class IdentityBackend(Protocol):
    storage: str

    @property
    def public_key(self) -> bytes: ...

    def sign(self, data: bytes) -> bytes: ...

    def destroy(self) -> None: ...


@dataclass
class FileIdentity:
    """Ed25519 key in app-private storage (degraded mode)."""

    path: Path
    _private: Ed25519PrivateKey
    storage: str = "file"

    @property
    def public_key(self) -> bytes:
        return self._private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)

    def destroy(self) -> None:
        try:
            self.path.write_bytes(secrets.token_bytes(256))
            os.chmod(self.path, 0o600)
        finally:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass


def load_file_identity(path: Optional[Path] = None) -> FileIdentity:
    path = path or identity_path()
    if path.exists():
        try:
            raw = json.loads(path.read_text())
            seed = base64.b64decode(raw["seed"])
            if len(seed) != 32:
                raise ValueError("bad seed")
            return FileIdentity(path=path, _private=Ed25519PrivateKey.from_private_bytes(seed))
        except Exception as exc:
            raise IdentityError("identity file is corrupt; no recovery exists") from exc

    seed = secrets.token_bytes(32)
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    payload = {
        "v": 1,
        "storage": "file",
        "seed": base64.b64encode(seed).decode(),
        "pub": base64.b64encode(pub).decode(),
        "created_at": int(time.time()),
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload))
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    return FileIdentity(path=path, _private=priv)


class NativeIdentity:
    """Adapter over the ``cipher_native`` extension.

    The extension is loaded lazily.  Any failure — import error, missing
    platform channel, Keystore error — raises and the caller falls back to a
    file identity with a visible degraded-mode banner.
    """

    storage = "keystore"

    def __init__(self, public_key: bytes) -> None:
        self._public_key = public_key
        self._module = _native_module()

    @property
    def public_key(self) -> bytes:
        return self._public_key

    def sign(self, data: bytes) -> bytes:
        try:
            sig = self._module.sign(data)
        except Exception as exc:
            raise IdentityError("hardware identity signing failed") from exc
        if not isinstance(sig, (bytes, bytearray)) or len(sig) < 32:
            raise IdentityError("hardware identity returned an invalid signature")
        return bytes(sig)

    def destroy(self) -> None:
        self._module.destroy_identity()


def _native_module():
    try:
        import cipher_native  # type: ignore
    except Exception as exc:
        raise IdentityError("native identity extension is not available") from exc
    return cipher_native


def native_available() -> bool:
    try:
        mod = _native_module()
        return bool(mod.available())
    except Exception:
        return False


def load_identity(prefer_native: bool = True) -> IdentityBackend:
    if prefer_native:
        try:
            mod = _native_module()
            if mod.available():
                pub = bytes(mod.ensure_identity_key())
                if len(pub) == 0:
                    raise IdentityError("empty public key")
                return NativeIdentity(pub)
        except Exception:
            # Never silently pretend: the caller records storage='file' and the
            # Security screen shows degraded mode.
            pass
    return load_file_identity()


@dataclass(frozen=True)
class Identity:
    backend: IdentityBackend
    key_id: bytes
    public_key: bytes
    kek: bytes
    created_at: int

    @property
    def storage(self) -> str:
        return self.backend.storage

    @property
    def hardware(self) -> bool:
        return self.storage == "keystore"


def unlock(backend: IdentityBackend) -> Identity:
    """Derive the master KEK from the identity's deterministic signature.

    The signature is not persisted and never crosses the network.  It is the
    identity key's symmetric partner.
    """
    sig = backend.sign(KEK_INFO)
    kek = kek_from_signature(sig)
    return Identity(
        backend=backend,
        key_id=fingerprint(backend.public_key),
        public_key=backend.public_key,
        kek=kek,
        created_at=int(time.time()),
    )
