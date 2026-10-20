# Security checklist and Definition of Done

Status values: **PASS** (enforced and tested here), **PARTIAL** (partly
enforced or untested on hardware), **FAIL** (not delivered), **N/A**.

## §7 Security checklist

| # | Requirement | Status | Evidence / limitation |
|---|---|---|---|
| 1 | No accounts, phone numbers or passwords | PASS | `app/identity.py`; no auth code or server account table |
| 2 | No key escrow or recovery path | PASS | `docs/threat-model.md`; `tests/test_identity.py`; wipe destroys identity |
| 3 | End-to-end encryption with vetted primitives | PASS | X25519 + HKDF/HMAC + ChaCha20-Poly1305 from `cryptography`; `app/crypto/` |
| 4 | No hand-rolled cipher, MAC or KDF | PASS | `app/crypto/primitives.py`; only library calls |
| 5 | Per-message keys and forward secrecy for consumed messages | PASS | `app/crypto/ratchet.py`; `tests/test_crypto.py::test_ratchet_*` |
| 6 | Post-compromise security | **FAIL** | Not provided by the symmetric-chain fallback; stated in Security screen, D-004, threat model |
| 7 | One-time pairing invite, 120 s | PASS | `SHA-256(S)` invite, atomic redeem, revoke; relay and messaging tests |
| 8 | Out-of-band SAS | PASS | 6-digit SAS from `k_enc`; both devices display it; completion is explicit |
| 9 | Pairing payload integrity and MITM detection | PASS | AEAD pair payloads + ephemeral-key check; `tests/test_crypto.py`, `tests/test_messaging.py` |
| 10 | Message padding to fixed buckets | PASS | `app/crypto/padding.py`; `tests/test_crypto.py::test_vectors_padding` |
| 11 | Rotating, unlinkable mailbox ids | PASS | Daily HKDF ids; direction labels; `tests/test_crypto.py::test_vectors_mailbox` |
| 12 | Replay and reorder rejection | PASS | Counter in nonce, authenticated AAD; ratchet tests |
| 13 | 24-hour ephemerality and crypto-shredding | PASS | Client TTL, relay TTL/sweeper, zero-overwrite + delete + `secure_delete`; storage tests |
| 14 | Blind relay, no content/account logs | PASS | Only invites/envelopes tables; `--no-access-log`; no logging statements |
| 15 | Relay bounds and abuse resistance | PASS | Size caps, 200 envelopes/mailbox, per-address invite rate limit; relay tests |
| 16 | TLS 1.3 and certificate pinning | PASS | `app/relay_client.py`; fail-closed unpinned release; `tests/test_relay_client.py` |
| 17 | Cleartext forbidden in release | PASS | `RelayClient` refuses `http://` unless `CIPHER_ENV=test` |
| 18 | Hardware-backed identity when available | PARTIAL | Android Keystore RSA-2048, StrongBox attempted; real-device verification is a deployment check |
| 19 | Degraded mode is loud, not silent | PASS | Red banner, Security rows, `ui/security.py`; file identity explicitly labelled |
| 20 | Screenshot block | PARTIAL | `FLAG_SECURE` in Kotlin plugin; release forces it; needs on-device verification |
| 21 | No clipboard copy | PASS | No copy actions; message/SAS `selectable=False`; OS-level capture is out of scope |
| 22 | No plaintext/key logging | PASS | No logging calls in app; relay access log off; error messages are generic |
| 23 | Wipe all data | PASS | Deletes remote mailboxes, shreds local rows, destroys identity; `ui/shell.py::_confirm_wipe` |
| 24 | Per-record encryption at rest | PASS | AES-256-GCM per message DEK, wrapped with conversation key; storage tests |
| 25 | Identity/key separation | PASS | Keystore private key never exported; KEK derived from deterministic signature |
| 26 | Protocol test vectors | PASS | `protocol/vectors/`; `tests/test_crypto.py` |
| 27 | End-to-end pairing/messaging test | PASS | `tests/test_messaging.py` with two identities and a relay double |
| 28 | Documentation of limits | PASS | `docs/threat-model.md`, `docs/protocol.md`, Security screen |
| 29 | No unsupported claims in the UI/README | PASS | Security screen explicitly shows PCS unavailable; degraded mode shows screenshot OFF |
| 30 | QR **scanning** on Android | **FAIL** | v1 displays a QR and accepts the manual secret; the camera scanner is not implemented (D-008) |
| 31 | Independent audit / pentest | **FAIL** | Not performed; no claim of audit |
| 32 | Play Integrity on every invite | **FAIL** (disabled by design) | Incompatible with sideloading; D-007; rate limit + one-time invite remain |

## §10 Definition of Done

| Item | Status | Notes |
|---|---|---|
| Phase 0 shell builds and runs | PASS | `app/build/apk/app-release.apk`, package `dev.cipher.cipher` |
| Phase 1 native identity + `FLAG_SECURE` | PARTIAL | Plugin compiles into the APK; on-device checks documented in `docs/deployment.md` |
| Phase 2 crypto + storage + vectors | PASS | Full suite (see `pytest -q`) |
| Phase 3 blind relay + client | PARTIAL | MemoryStore covered by tests; Postgres store not integration-tested (no Docker locally) |
| Phase 4 six-screen UI + pairing/messaging service | PASS | Onboarding, Conversations, Chat, Pairing, Security, Settings |
| Phase 5 hardening | PASS | TTL sweep, wipe, pinning, bounded relay, no logs, envelope cap |
| Phase 6 release docs + checklist | PASS | This file, protocol, threat model, deployment, decisions |
| Installable APK produced | PASS | `app/build/apk/app-release.apk` (see build log) |
| APK verified on a physical/emulated Android device | PARTIAL | Install/launch and Keystore verification are deployment steps; build output is verified structurally |
| All tests pass | PASS | `67 passed` at the time of writing |
| Every deviation logged | PASS | `docs/decisions.md` D-001..D-008 |
| No claim beyond enforcement | PASS | Explicit FAIL/PARTIAL rows above |

## Explicitly failed or deferred

1. **Post-compromise security** — not provided. Re-pairing is the only remedy.
2. **Camera QR scanning** — not implemented; QR display + manual secret is the
   supported path. This is a deliberate scope cut recorded in D-008.
3. **Play Integrity** — disabled by default because the APK is sideloaded and
   no Google Cloud credentials are part of the deliverable.
4. **Postgres integration test** — no Docker in the build environment; the
   store is implemented and the interface is tested via `MemoryStore`.
5. **Physical-device verification** — structural APK checks pass; Keystore and
   screenshot behaviour must be confirmed on the target device.
6. **Independent security audit** — none.

These are not hidden: they appear in the Security screen, README, threat model
and this checklist.
