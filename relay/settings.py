"""Relay configuration.  Every value has a conservative production default."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    return int(raw) if raw else default


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_url: str
    ttl_seconds: int
    invite_ttl_seconds: int
    sweeper_interval_seconds: int
    max_payload_bytes: int
    # Play Integrity is enforced server-side before an invite may be created.
    play_integrity_required: bool
    play_integrity_package: str
    play_integrity_credentials: str
    # Test profile shrinks TTLs so the 24 h wipe can be exercised in seconds.
    test_profile: bool
    # Bounds.  Enforced before allocation and again after base64 decoding.
    max_invite_bytes: int = 4096
    max_request_bytes: int = 32 * 1024
    # One mailbox cannot grow without bound if its id leaks.
    max_envelopes_per_mailbox: int = 200
    # Invite allocation is the only endpoint that creates new storage.
    invite_rate_limit: int = 10
    invite_rate_window_seconds: int = 60


@lru_cache
def get_settings() -> Settings:
    # The test profile is opt-in and requires an explicit CIPHER_ENV=test.
    # A release deployment cannot shrink TTLs with a stray environment flag.
    test_profile = _bool("CIPHER_TEST_PROFILE", False) and (
        os.getenv("CIPHER_ENV", "release").strip().lower() == "test"
    )
    default_ttl = 5 if test_profile else 86_400
    return Settings(
        database_url=os.getenv(
            "CIPHER_DATABASE_URL",
            "postgresql://cipher:cipher@localhost:5432/cipher",
        ),
        ttl_seconds=_int("CIPHER_TTL_SECONDS", default_ttl),
        invite_ttl_seconds=_int("CIPHER_INVITE_TTL_SECONDS", 120),
        sweeper_interval_seconds=_int("CIPHER_SWEEPER_INTERVAL_SECONDS", 1 if test_profile else 60),
        max_payload_bytes=_int("CIPHER_MAX_PAYLOAD_BYTES", 12 * 1024),
        # Optional anti-abuse gate.  Off by default: Cipher is sideloaded, and
        # Play Integrity rejects apps that were not installed by Play.  See
        # D-007.  Invite creation is still rate-limited and one-time.
        play_integrity_required=_bool("CIPHER_PLAY_INTEGRITY", False),
        play_integrity_package=os.getenv("CIPHER_PLAY_PACKAGE", "dev.cipher.cipher"),
        play_integrity_credentials=os.getenv("CIPHER_PLAY_CREDENTIALS", ""),
        test_profile=test_profile,
        max_invite_bytes=_int("CIPHER_MAX_INVITE_BYTES", 4096),
        max_request_bytes=_int("CIPHER_MAX_REQUEST_BYTES", 32 * 1024),
        max_envelopes_per_mailbox=_int("CIPHER_MAX_ENVELOPES", 200),
        invite_rate_limit=_int("CIPHER_INVITE_RATE_LIMIT", 10),
        invite_rate_window_seconds=_int("CIPHER_INVITE_RATE_WINDOW_SECONDS", 60),
    )
