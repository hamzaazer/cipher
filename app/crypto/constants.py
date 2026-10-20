"""Protocol constants.

All labels are versioned.  Changing any label is a protocol break and requires
new test vectors.
"""

from __future__ import annotations

PROTOCOL_VERSION = 1

PAIR_INFO = b"cipher/pair/v1"
CONV_INFO = b"cipher/conv/v1"
SAS_INFO = b"cipher/sas/v1"
KEK_INFO = b"cipher/kek/v1"
MBX_SECRET_INFO = b"cipher/mbx-secret/v1"
MBX_INFO = b"mbx"
HS_MBX_INFO = b"cipher/handshake-mbx/v1"
INVITE_MAGIC = b"CPV1"
WRAP_INFO = b"cipher/conv-wrap/v1"
RATCHET_INFO = b"cipher/msg-ratchet/v1"
CTRL_INFO = b"cipher/ctrl/v1"

PAIR_AAD = b"pair/v1"
PAIR_NONCE_A = b"A" + b"\x00" * 11
PAIR_NONCE_B = b"B" + b"\x00" * 11

TTL_SECONDS = 86_400
INVITE_TTL_SECONDS = 120
MAX_SKIP = 100

PAD_BUCKETS = (128, 512, 2048, 8192)
MAX_MESSAGE_BYTES = PAD_BUCKETS[-1] - 4

CONTROL_ROLLOVER = b"\x01"
