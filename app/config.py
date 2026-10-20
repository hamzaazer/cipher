"""Runtime configuration.

The release APK has no settings that can weaken the protocol.  The test
profile is read only from the environment, which is not settable in a release
Android build.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from crypto.constants import TTL_SECONDS

_PACKAGED_CONFIG = Path(__file__).with_name("relay_config.json")


def _packaged() -> dict:
    """Optional build-time configuration shipped inside the APK.

    Android app processes do not inherit a shell environment, so a sideloaded
    release build cannot rely on ``CIPHER_RELAY_URL`` being present at launch.
    The build script writes this file into the APK when the variables are set;
    the environment still wins for desktop development and tests.
    """
    try:
        raw = json.loads(_PACKAGED_CONFIG.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except Exception:
        return {}


def test_profile() -> bool:
    # Both flags are required, matching the relay.  A stray flag in a release
    # environment must not be able to shrink the 24 h TTL.
    return (
        os.getenv("CIPHER_TEST_PROFILE", "").strip().lower() in {"1", "true", "yes"}
        and os.getenv("CIPHER_ENV", "release").strip().lower() == "test"
    )


def ttl_seconds() -> int:
    if test_profile():
        return int(os.getenv("CIPHER_TTL_SECONDS", "5"))
    return TTL_SECONDS


def relay_url() -> str:
    # Must be HTTPS in release.  The app-layer client rejects cleartext and
    # unpinned hosts; there is no Android network-security-config fallback.
    return os.getenv("CIPHER_RELAY_URL") or str(
        _packaged().get("url") or "https://relay.cipher.invalid"
    )


def relay_pins() -> tuple[str, ...]:
    """Base64 SHA-256 SPKI pins: primary first, then backup."""
    raw = os.getenv("CIPHER_RELAY_PINS", "")
    if not raw:
        pins = _packaged().get("pins") or []
        if isinstance(pins, str):
            raw = pins
        elif isinstance(pins, list):
            return tuple(str(p).strip() for p in pins if str(p).strip())
    return tuple(p.strip() for p in raw.split(",") if p.strip())


def release() -> bool:
    return os.getenv("CIPHER_ENV", "release").lower() == "release"
