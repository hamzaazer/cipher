"""Rotating, direction-separated mailbox identifiers (§5.4).

``mailbox_id = HKDF(conv_secret, "mbx" || role, day_epoch, 16)``

The conversation secret is used as HKDF input keying material, the day epoch
is the HKDF salt, and the role (``A`` or ``B``) is part of the info string.  A
fresh conversation secret is generated at pairing; the relay sees a different
random-looking 16-byte id every UTC day and cannot link two days.  The role
byte is required: both peers must not read their own outbound queue, and the
two directions must not share a mailbox (see D-006).
"""

from __future__ import annotations

import struct
import time

from crypto.constants import MBX_INFO, MBX_SECRET_INFO
from crypto.primitives import hkdf


def day_epoch(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // 86_400)


def mailbox_id(conv_secret: bytes, role: str, day: int | None = None) -> bytes:
    if role not in {"A", "B"}:
        raise ValueError("mailbox role must be A or B")
    day = day_epoch() if day is None else day
    secret = hkdf(conv_secret, MBX_SECRET_INFO, 32)
    return hkdf(secret, MBX_INFO + role.encode("ascii"), 16, salt=struct.pack(">Q", day))


def mailbox_ids(
    conv_secret: bytes, role: str, now: float | None = None
) -> tuple[bytes, bytes]:
    """(yesterday, today) mailboxes for one sender direction.  Draining both
    covers a midnight rollover while the peer was offline; anything older is
    past its 24 h TTL by definition."""
    today = day_epoch(now)
    return (
        mailbox_id(conv_secret, role, today - 1),
        mailbox_id(conv_secret, role, today),
    )


def rollover_due(last_posted_day: int | None, now: float | None = None) -> bool:
    return last_posted_day != day_epoch(now)
