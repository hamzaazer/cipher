# Cipher

Ephemeral, end-to-end encrypted 1:1 messenger for Android. A sideloaded Flet
APK plus a blind store-and-forward relay. No accounts, no recovery, 24-hour
crypto-shredding, screenshot blocking, and no copy actions.

**Status: implementation complete for v1, with the limitations listed below
and in `docs/security-checklist.md`.** These are claims about the code in this
repository, not about an audited product.

## What works

- One-time pairing by QR display or typed 16-byte secret, with a 6-digit SAS
  that both people must compare.
- X25519 key agreement, ChaCha20-Poly1305 message encryption, per-message
  ratchet, padded envelopes, daily rotating direction-separated mailboxes.
- Android Keystore identity (RSA-2048, StrongBox attempted) and `FLAG_SECURE`
  through a small native extension; a loud degraded mode with file identity
  when the extension is unavailable.
- Local SQLite with per-record AES-GCM, crypto-shredding on delete/expiry, and
  a 24-hour conversation/message lifetime.
- Blind FastAPI relay with one-time invites, bounded payloads/mailboxes,
  expiry sweeper, no request logging, and an in-memory test store.
- Pinned TLS 1.3 relay client; unpinned or cleartext release connections fail
  closed.

## What is explicitly not provided

- **Post-compromise security.** The symmetric ratchet gives forward secrecy
  for consumed messages only; an attacker with the current chain key can read
  future messages until the peers re-pair. The Security screen says this.
- **Camera QR scanning.** The QR is displayed and the same secret can be typed;
  the Android camera scanner is not implemented in v1 (D-008).
- **Play Integrity.** Disabled by default because the APK is sideloaded and no
  Google Cloud credentials are included (D-007).
- **Recovery, multi-device sync, groups, metadata anonymity, audit.** None.
- The relay can see mailbox ids, padded sizes, timing and client IPs. It cannot
  read bodies or derive conversation keys.

Read `docs/threat-model.md` before using this for anything sensitive.

## Layout

```
app/        Flet Python app (UI, crypto, storage, relay client)
native/     Flet extension: Dart bridge + Kotlin Keystore/FLAG_SECURE plugin
relay/      FastAPI blind relay (Postgres in production)
protocol/   Fixed test vectors
docs/       protocol, threat model, deployment, decisions, checklist
tests/      Crypto, storage, identity, relay, client and end-to-end tests
scripts/    ASCII-path APK build script
```

## Quick start

### Relay (Docker)

```bash
docker compose up --build
curl http://127.0.0.1:8000/healthz
```

The compose service binds to `127.0.0.1`; put a TLS 1.3 terminator in front of
it. See `docs/deployment.md`.

### App (desktop, development relay)

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements-dev.txt
.venv/Scripts/pip install -e native

# terminal 1: cleartext test relay only
set CIPHER_ENV=test
set CIPHER_TEST_PROFILE=1
.venv/Scripts/uvicorn main:app --app-dir relay --port 8000

# terminal 2
set CIPHER_ENV=test
set CIPHER_TEST_PROFILE=1
set CIPHER_RELAY_URL=http://127.0.0.1:8000
cd app
../.venv/Scripts/flet run main.py
```

`CIPHER_ENV=test` is required for cleartext and for the short-TTL profile.
Never use either flag on a public deployment.

### Android APK

```powershell
$env:CIPHER_RELAY_URL = "https://relay.example"
$env:CIPHER_RELAY_PINS = "base64SpkiPin[,backupPin]"
powershell -ExecutionPolicy Bypass -File scripts\build_apk.ps1
```

The build must run from the ASCII staging directory because Gradle rejects the
accented workspace path; the script handles this. The APK is written to
`app\build\apk\app-release.apk`. Relay URL and pins are baked into
`app/relay_config.json` inside the APK, because Android app processes do not
inherit the build shell's environment.

If no URL/pins are baked in, the app starts with an explicit "relay not
configured" banner and pairing is disabled — it does not pretend to work.

## Tests

```bash
.venv/Scripts/python -m pytest -q
```

Do not set `PYTHONPATH`; `tests/conftest.py` manages the app/relay/native
import paths, and setting it causes a `main` module collision.

The suite covers fixed crypto vectors, padding, pairing/SAS, ratchet replay and
gaps, storage and shredding, identity fallback, relay semantics and limits, TLS
pin mapping, and an in-process end-to-end pairing + bidirectional messaging
test. It does not cover a live Postgres instance, a real TLS handshake or a
physical Android device.

## Documentation

- [`docs/protocol.md`](docs/protocol.md) — exact wire format, KDFs, relay API.
- [`docs/threat-model.md`](docs/threat-model.md) — assets, adversaries,
  enforced properties and non-properties.
- [`docs/deployment.md`](docs/deployment.md) — relay, TLS pinning, APK build.
- [`docs/security-checklist.md`](docs/security-checklist.md) — §7 checklist and
  Definition of Done, including FAIL/PARTIAL items.
- [`docs/decisions.md`](docs/decisions.md) — every deviation from the brief.
