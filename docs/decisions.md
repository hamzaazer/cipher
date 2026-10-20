# Decisions

Conservative choices made where the brief was ambiguous or where the stated
mechanism does not exist in the pinned toolchain. Newest first.

## D-001 — Pin Flet 0.28.3 instead of Flet 1.x (Phase 0)

**Context.** The brief fixes `flet.add_platform_channel` and
`flet build apk --add-flutter-package`. Neither API exists in any published
Flet release: platform channels are not part of the Flet Python API, and
`--add-flutter-package` was removed before 0.28. Flet 1.x additionally changes
the UI programming model and requires a Flutter SDK that is not installed here.

**Decision.** Pin `flet==0.28.3`, which matches the provisioned Flutter 3.29.2
and JDK 17 toolchain, and implement the native functionality as a **Flet
extension** (a local Python package containing a Flutter package with Kotlin
Android code and a thin Dart bridge). The bridge is not a weakening: the
private key still lives only in Android Keystore and only `ensureIdentityKey`,
`sign` and `destroyIdentity` cross the boundary (plus `setSecure`). The Dart
component contains no cryptography.

**Consequence.** The Python-side API is `cipher_native.ensure_identity_key()`
etc. rather than a raw `page.add_platform_channel`. Behaviour and guarantees
are identical to the brief; `docs/threat-model.md` states the mechanism.

## D-002 — Degraded mode is a first-class build mode (Phase 0)

If the extension is not present or the platform channel fails to attach, the
app starts in degraded mode: file-based identity secret, no `FLAG_SECURE`.
A red banner is shown on Onboarding, Conversations and Security, and every
security flag in the Security screen is derived from runtime probing, never
from a build constant.

## D-003 — TLS pinning implemented in the Python network client

Flet runs Python behind its own HTTP stack, and Flet 0.28 does not expose an
Android `network_security_config` hook for Python requests. The relay client
therefore owns the TLS connection: it requires TLS 1.3, checks the SHA-256 of
the leaf certificate's SubjectPublicKeyInfo against an embedded pin set on
every connection (constant-time compare), and has no fallback. A release build
with no pins refuses to construct a client; cleartext is allowed only with
`CIPHER_ENV=test`. A mismatch is a hard failure — no "continue anyway" prompt.

The limitation is documented: this protects the Python relay connection, not
other HTTP clients the Flet runtime might use. The app makes no other network
requests.

## D-004 — No libsignal and no Noise transport session

The brief prefers libsignal but budgets ~200 Kotlin lines and allows the
documented fallback. libsignal's Android artifact alone exceeds the budget and
its protocol requires prekeys/registration that conflict with the accountless
design.

A Noise XX/transport session is also a poor fit for a store-and-forward relay:
Noise transport nonces are strictly sequential, so one lost, expired or
out-of-order mailbox item permanently desynchronises the session, and XX needs
both peers online for three flights. Cipher therefore uses the brief's
per-message symmetric ratchet: two HMAC-SHA256 chains seeded through HKDF from
the pairing secret, with ChaCha20-Poly1305 from the vetted `cryptography`
package and the protocol's padding. `noiseprotocol` is consequently not a
runtime dependency.

**Consequence.** Messages already consumed are forward-secret, but the ratchet
does **not** provide post-compromise security: an attacker who obtains the
current chain key can derive future message keys until the peer re-pairs. This
is shown in the Security screen and in `docs/threat-model.md`; the code does
not claim otherwise.

## D-005 — Test profile uses short TTLs, never enabled in release

The relay reads `CIPHER_TEST_PROFILE` only together with `CIPHER_ENV=test`.
The client applies `CIPHER_TTL_SECONDS` only under the same two conditions.
The release APK has no UI and no supported environment path to change the
24-hour TTL.

## D-006 — Direction-separated mailboxes and a short handshake queue

A single mailbox per conversation per day would make both peers drain their
own outbound envelopes, and the receive ratchet cannot authenticate its own
send chain. Each direction therefore derives a different id:

```
mailbox_id = HKDF(HKDF(conv_secret, "cipher/mbx-secret/v1", 32),
                  "mbx" || role, 16, salt = day_epoch)
```

`role` is the sender's role (`A` or `B`). Draining both yesterday's and today's
mailbox covers a midnight rollover. The pairing handshake uses a third,
secret-derived mailbox (`cipher/handshake-mbx/v1`) and 120 s relay TTLs, so it
cannot be correlated with conversation traffic.

The relay stores client-supplied invite ids: `SHA-256(S)`, 32 bytes (`hex` in
the URL). This lets the manual base32 secret alone locate the invite without a
second lookup channel. The relay never learns `S` and cannot decrypt either
handshake payload.

## D-007 — Play Integrity is optional and off by default

Play Integrity rejects sideloaded apps, which is the only distribution mode
for this build, and it needs a Google Cloud project and credentials that are
not part of the deliverable. Enforcing it by default would make every invite
fail with 503 while claiming an anti-abuse property the client cannot satisfy.

Invite creation is still one-time, expires after 120 s, and is rate-limited per
client address; mailboxes have a hard envelope cap. `CIPHER_PLAY_INTEGRITY=1`
enables the server-side verifier only for deployments that also ship a
Play-distributed client and configure credentials; until then the relay fails
closed rather than silently skipping verification.

## D-008 — QR display, manual secret entry; no camera scanner in v1

Flet 0.28 has no camera/barcode control, and bundling OpenCV for Python on
Android risks a wheel/ABI mismatch in the APK. A native ML Kit/zxing scanner is
feasible but adds an Android activity, a camera permission prompt and a
dependency that cannot be exercised in this environment. The deliverable
therefore displays a standards-compliant QR code and shows the same secret as
grouped base32 text, which is enough to pair two devices without a camera.

This is a scope cut, not a security claim: the QR contains the one-time
secret, must not be screenshotted or shared, and is useless after 120 s or the
first redeem. The UI and `docs/security-checklist.md` list camera scanning as
not implemented.
