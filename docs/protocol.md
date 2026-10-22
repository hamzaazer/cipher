# Cipher protocol v1

This document describes exactly what the code implements. It is normative for
this repository; where a deployment differs, the deployment is wrong.

All keys are 32 bytes unless stated. All integer encodings are big-endian.
`HKDF` is RFC 5869 with SHA-256; `HMAC` is HMAC-SHA256.

## Roles and state

A conversation has two roles, `A` (initiator/joiner) and `B`
(responder/inviter). Roles are fixed at pairing and decide:

- the direction of each ratchet chain;
- the sender byte in the AEAD associated data;
- the mailbox label (`mbxA` or `mbxB`).

There are no accounts, device identifiers or long-term public keys on the
relay. The only long-term key is the local identity key pair.

## Identity

- Native mode: RSA-2048 in Android Keystore, `SHA256withRSA/PKCS1Padding`.
  The public key is DER SubjectPublicKeyInfo. The private key never leaves the
  Keystore.
- Degraded mode: Ed25519 key in app-private storage.
- Key id: `SHA-256(identity_public_key)`.
- Master KEK: `HKDF(signature("cipher/kek/v1"), "cipher/kek/v1", 32)`.
  PKCS#1 v1.5 and Ed25519 are deterministic, so every launch derives the same
  KEK without storing it. The signature is never persisted or transmitted.

## Pairing (§5.1)

### Invite creation (B)

1. `S = random(16)`.
2. `invite_id = SHA-256(S)` (32 bytes).
3. Generate an ephemeral X25519 key pair `(eph_b_priv, eph_b_pub)`.
4. Publish to the relay at `invite_id`:
   `payload = "CPV1" || eph_b_pub` (36 bytes), TTL 120 s.
5. The out-of-band value is `cipher://pair/v1/<b64url(invite_id)>/<b64url(S)>`.
   The manual form is base32(S), grouped in fours.

The relay never learns `S`, so it cannot derive any key from the invite id.

### Join (A)

1. Parse `S` and check `SHA-256(S) == invite_id`.
2. Redeem the invite. The relay atomically deletes it before returning the
   payload, so a second device gets 404.
3. Parse `eph_b_pub`; reject anything but `CPV1 || 32 bytes`.
4. Generate `(eph_a_priv, eph_a_pub)`.
5. Derive:
   ```
   dh   = X25519(eph_a_priv, eph_b_pub)
   okm  = HKDF-SHA256(ikm = dh, salt = S, info = "cipher/pair/v1", 64)
   k_enc = okm[0:32]      k_mac = okm[32:64]
   conv_seed = HKDF(k_enc, "cipher/conv/v1", 32)
   SAS = int(HKDF(k_enc, "cipher/sas/v1", 8).hex(), 16) mod 1_000_000
   ```
6. Deposit to the handshake mailbox:
   ```
   eph_a_pub || AEAD(k_enc, nonce="A"||0^11,
                     "identity_a || eph_a_pub", aad="pair/v1")
   ```
   The first 32 bytes are public; the responder needs them before it can
   derive `k_enc`. The AEAD still authenticates the payload.

### Reply (B)

B drains the handshake mailbox. It reads `eph_a_pub`, derives the same keys
from `S`, opens the payload with nonce `"A"`, and checks that the embedded
ephemeral key equals the clear-text one. It replies with:

```
AEAD(k_enc, nonce="B"||0^11, "identity_b || eph_b_pub", aad="pair/v1")
```

A verifies that the returned `eph_b_pub` equals the one in the redeemed
invite, then both display the same six-digit SAS.

### SAS and completion

The SAS is a commitment to the shared DH and to `S`. An active relay that
substitutes either ephemeral key cannot derive `k_enc`, so the two devices
display different SAS values. The user must compare out of band and cancel on
a mismatch. Completing locally creates the conversation and initial ratchet.
Nothing is written to the conversation table before confirmation.

Aborting revokes an unredeemed invite and purges the handshake mailbox. Any
undelivered pair envelope expires with its 120 s TTL.

## Message envelope (§5.2/§5.3)

```
offset  size  field
0       16    mailbox_id
16      12    nonce
28      ..    ChaCha20-Poly1305 ciphertext || 16-byte tag
```

`nonce[0:4]` is the sender counter (uint32), `nonce[4:12]` is random. The
random tail keeps nonces unique even if a database snapshot is restored and a
counter is reused; the receiver still rejects the lower counter.

Associated data:

```
mailbox_id || (0x00 if sender_role == "A" else 0x01) || counter(uint64)
```

Plaintext is `pad(utf8_body)`:

```
4-byte big-endian body length || body || zero padding
```

The result is padded up to the next bucket: 128, 512, 2048 or 8192 bytes.
Messages over `8192 - 4` UTF-8 bytes are rejected. Padding is removed only after
the length field is validated, so a tampered length cannot cause a huge
allocation.

Control envelopes (reserved; not emitted by v1) use `nonce[0] == 0xFF`, a key
`HKDF(conv_seed, "cipher/ctrl/v1", 32)`, and AAD `"ctrl" || mailbox_id`. They do
not advance the message chain.

## Message ratchet

```
root       = HKDF(conv_seed, "cipher/msg-ratchet/v1", 64)
chain_A2B  = root[0:32]      chain_B2A = root[32:64]
message_key = HMAC(chain, 0x01)
next_chain  = HMAC(chain, 0x02)
```

`A` sends with `chain_A2B` and receives with `chain_B2A`; `B` is the reverse.
A message key is used once and discarded. The receiver derives forward to the
counter in the envelope, rejecting counters below its state (replay) and gaps
over 100. Skipped keys are not retained, so lost messages stay lost and cannot
be recovered later.

This gives forward secrecy for messages already consumed. It does not give
post-compromise security. See `docs/threat-model.md`.

## Mailbox rotation (§5.4)

```
secret = HKDF(conv_seed, "cipher/mbx-secret/v1", 32)
mailbox(role, day) = HKDF(secret, "mbx" || role, 16, salt = uint64(day))
day = floor(unix_time / 86400)
```

Senders use their own role; receivers drain the peer role for yesterday and
today. Ids are unlinkable across days without `conv_seed`. The role separation
prevents a peer from reading its own outbound queue.

The pairing handshake uses:

```
handshake_mailbox(S) = HKDF(S, "cipher/handshake-mbx/v1", 16)
```

## Relay API

All request and response bodies are JSON. Binary values are strict base64;
ids in paths are lowercase hex. No endpoint logs bodies, ids or client
addresses.

| Method | Path | Meaning |
|---|---|---|
| `GET` | `/healthz` | liveness, no state |
| `POST` | `/v1/invite` | create invite; body `invite_id` (32-byte hex), `payload`, optional integrity fields |
| `GET` | `/v1/invite/{id}` | atomic one-time redeem |
| `DELETE` | `/v1/invite/{id}` | revoke; always 204 |
| `POST` | `/v1/mailbox/{id}` | deposit envelope; optional `ttl` in seconds (1..deployment TTL) |
| `GET` | `/v1/mailbox/{id}` | list non-expired envelopes, oldest first |
| `DELETE` | `/v1/mailbox/{id}/{envelope}` | acknowledge one envelope |
| `DELETE` | `/v1/mailbox/{id}` | purge a mailbox |

Limits: request body 32 KiB, invite payload 4 KiB, envelope payload 12 KiB,
200 envelopes per mailbox, invite creation rate-limited per client address.
Responses carry `Cache-Control: no-store`, `Pragma: no-cache`,
`X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.

## Test vectors

`protocol/vectors/` contains fixed inputs for pairing KDF/SAS/AEAD, padding,
mailbox derivation and the ratchet step. `tests/test_crypto.py` loads them; a
change to any label, bucket or derivation order must update the vectors and
bump the protocol version.

## Explicit non-goals

- No account recovery, password reset or key escrow.
- No multi-device fan-out; one identity, one device.
- No group messaging.
- No metadata anonymity: the relay sees mailbox ids, envelope sizes (buckets),
  timing and client IPs, and can correlate a mailbox that is polled often.
- No post-compromise security.
- No protection against a compromised endpoint while it is unlocked.
