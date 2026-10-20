# Deployment

Cipher has two pieces: an Android APK and a blind relay. The relay never needs
the app's keys; the app never trusts the relay with plaintext.

## 1. Relay

### Reference deployment (Docker)

```bash
docker compose up --build
curl http://127.0.0.1:8000/healthz
```

The compose file binds the relay to `127.0.0.1` only. Put a TLS 1.3 terminator
in front of it (Caddy, nginx, a cloud load balancer) and expose only HTTPS.
Postgres keeps its data in the `cipher-db` volume; WAL archiving and logical
replication are off because the durability model is the 24-hour TTL.

### Environment

| Variable | Default | Notes |
|---|---|---|
| `CIPHER_DATABASE_URL` | `postgresql://cipher:cipher@localhost:5432/cipher` | Postgres required in production |
| `CIPHER_TTL_SECONDS` | `86400` | message/envelope lifetime |
| `CIPHER_INVITE_TTL_SECONDS` | `120` | pairing window |
| `CIPHER_SWEEPER_INTERVAL_SECONDS` | `60` | expiry sweeper |
| `CIPHER_MAX_PAYLOAD_BYTES` | `12288` | envelope body cap |
| `CIPHER_MAX_INVITE_BYTES` | `4096` | invite body cap |
| `CIPHER_MAX_REQUEST_BYTES` | `32768` | HTTP request cap |
| `CIPHER_MAX_ENVELOPES` | `200` | live envelopes per mailbox |
| `CIPHER_INVITE_RATE_LIMIT` | `10` | invites per address per window |
| `CIPHER_INVITE_RATE_WINDOW_SECONDS` | `60` | rate window |
| `CIPHER_PLAY_INTEGRITY` | `0` | optional; see below |
| `CIPHER_PLAY_PACKAGE` | `dev.cipher.cipher` | verifier audience |
| `CIPHER_PLAY_CREDENTIALS` | empty | service-account JSON path/content |
| `CIPHER_TEST_PROFILE` | `0` | only honoured with `CIPHER_ENV=test` |
| `CIPHER_ENV` | `release` | `test` enables cleartext/short TTLs |

`CIPHER_TEST_PROFILE=1 CIPHER_ENV=test` is the only way to get 5-second
message TTLs in the reference relay. Both must be set. Never deploy the test
profile on a public host.

### TLS pinning

The APK embeds SHA-256 SPKI pins. Compute the pin for the certificate the relay
terminator actually serves:

```bash
openssl s_client -connect relay.example:443 -servername relay.example </dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl base64
```

Embed the primary pin (and a backup pin for a planned certificate rotation) at
build time:

```bash
CIPHER_RELAY_URL=https://relay.example \
CIPHER_RELAY_PINS="primaryBase64,backupBase64" \
CIPHER_ENV=release \
powershell -ExecutionPolicy Bypass -File scripts/build_apk.ps1
```

A release client with an empty pin set refuses to connect. A pin mismatch never
falls back. Rotating a certificate therefore requires shipping a new APK with
the new pin (or having the backup pin already embedded).

### Play Integrity

`CIPHER_PLAY_INTEGRITY=1` makes invite creation fail closed unless a Google
Play Integrity token is verified. This is **off by default** because Cipher is
sideloaded and Play Integrity rejects apps that were not installed by Play, and
because verification needs a Google Cloud project the deliverable does not
include. If you distribute through Play and configure
`CIPHER_PLAY_CREDENTIALS`, you can enable it; otherwise leave it off and rely on
the one-time 120-second invite plus per-address rate limiting.

The client does not currently send an integrity token, so enabling the gate on
a deployment used by this APK would make pairing impossible. That is a
deliberate fail-closed state, not a silent bypass.

### Postgres

Use a dedicated role and database, TLS to the database if it is remote, and
regular patching. The relay stores only:

- `invites(invite_id, payload, created_at, expires_at)`
- `envelopes(envelope_id, mailbox_id, payload, created_at, expires_at)`

There are no user, device or message tables. Do not enable query logging that
includes parameters; the payloads are ciphertext but the metadata is sensitive.
The relay has no access log (`uvicorn --no-access-log`).

## 2. Android APK

The workspace path contains a non-ASCII character, and Android Gradle rejects
such project paths. Build from the ASCII staging directory using the provided
script:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_apk.ps1
```

The script mirrors the repo to `C:\cipher-build`, deletes stale generated
Flutter packages, runs `flet build apk`, and copies the APK back to
`app\build\apk\app-release.apk`.

Android app processes do not inherit the build shell's environment, so the
script bakes `CIPHER_RELAY_URL` and `CIPHER_RELAY_PINS` into
`app/relay_config.json` inside the APK. These are read at runtime by
`app/config.py`; real environment variables still override them on desktop and
in tests. Without them, the default `https://relay.cipher.invalid` is a
placeholder and the app starts with messaging disabled and an explicit banner.
Never commit the generated `app/relay_config.json`; use
`app/relay_config.example.json` as the template.

Requirements on the build host:

- Python 3.11 with the repo `.venv`;
- Flutter 3.29.2 on `PATH`;
- JDK 17;
- Android SDK 34 (minSdk 26, targetSdk 34);
- the local `cipher-native` package installed (`pip install -e native`).

The APK is signed with Flet's generated debug/upload key for sideloading. For a
real deployment, provide your own keystore and keep it offline.

### Installing

```bash
adb install -r app/build/apk/app-release.apk
```

`FLAG_SECURE` is applied by the native plugin in release builds. Verify on the
device: the app should disappear from the recents thumbnail and screenshots
should be refused.

## 3. Development

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements-dev.txt
.venv/Scripts/pip install -e native
cd app
../.venv/Scripts/flet run main.py
```

For a local relay over cleartext (never in release):

```bash
CIPHER_ENV=test CIPHER_TEST_PROFILE=1 uvicorn main:app --app-dir relay --port 8000
```

and for the app:

```bash
CIPHER_ENV=test \
CIPHER_RELAY_URL=http://127.0.0.1:8000 \
CIPHER_TEST_PROFILE=1 \
../.venv/Scripts/flet run main.py
```

`CIPHER_ENV=test` also enables the short TTL profile if `CIPHER_TEST_PROFILE=1`
is set on both sides. Unset both for any real use.

## 4. Tests

```bash
.venv/Scripts/python -m pytest -q
```

Do not set `PYTHONPATH`; `tests/conftest.py` inserts the right app, relay and
native paths. Setting it can make `app/main.py` and `relay/main.py` collide on
the module name `main`.

The suite covers crypto vectors, storage/crypto-shredding, identity fallback,
the native Python bridge, relay semantics (memory store), TLS pin mapping, and
end-to-end pairing/messaging between two in-process service instances. It does
not exercise a real Postgres instance, a real TLS handshake, or a physical
Android device; those are deployment checks.

## 5. Operational checks

- `GET /healthz` returns `{"status":"ok"}` and no state.
- Confirm no request/body logging is enabled at the terminator.
- Confirm the Postgres volume is encrypted at rest if the host is shared.
- Confirm the certificate pin in the shipped APK matches the live certificate.
- Confirm `CIPHER_TEST_PROFILE` is unset in production.
- Confirm expired rows disappear after the sweeper interval.
