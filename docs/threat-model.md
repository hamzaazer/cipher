# Threat model

Cipher is an ephemeral 1:1 messenger with a blind store-and-forward relay. This
document states the properties the code enforces, the properties it does not,
and the assumptions behind each. It is intentionally conservative: anything
not enforced by code is listed as a limitation, not as a feature.

## Assets

1. Message plaintext and attachment-free body content.
2. Conversation secret, message keys and ratchet chain state.
3. The local identity private key and the master KEK derived from it.
4. The fact that two identities are communicating, and when.
5. The one-time pairing secret `S` and the SAS.

## Adversaries considered

| Adversary | Capability |
|---|---|
| Passive network observer | sees TLS records; cannot read them without breaking TLS 1.3 |
| Malicious/curious relay | stores, reorders, replays, drops or substitutes opaque envelopes; sees mailbox ids, sizes, timing, IPs |
| Active pairing attacker | can race to redeem an invite, substitute relay payloads, or trick a user into comparing the wrong screen |
| Device thief (locked) | has the powered-off or locked device |
| Device thief (unlocked) | has the app open and the identity unlocked |
| Malware with app-private access | reads files and process memory (root, custom ROM, debuggable build, backup extraction) |
| Network attacker with a mis-issued certificate | can present any TLS certificate; pinning is the defence |

Out of scope: a compromised relay *and* a compromised endpoint at the same
time, supply-chain compromise of the Python/Flutter/Android toolchain, and
physical coercion of the user.

## Properties enforced by code

### Confidentiality

- Every message body is encrypted with ChaCha20-Poly1305 under a per-message
  key derived from the conversation ratchet.
- The relay only receives `mailbox_id || nonce || ciphertext`, base64-encoded.
  It has no key material and no account mapping.
- At rest, message bodies and DEKs are AES-256-GCM encrypted with keys derived
  from the identity KEK. The KEK is derived from a deterministic signature and
  is never stored.
- The native identity private key is non-exportable in Android Keystore.
- Pairing secrets are never sent to the relay. The invite is addressed by
  `SHA-256(S)`, and the handshake payload is AEAD-encrypted under a key derived
  from `S` and an ephemeral X25519 exchange.

### Integrity and authenticity

- Every envelope is AEAD-authenticated with the mailbox id, sender role and
  counter as associated data.
- A replayed or out-of-order old counter is rejected; a gap larger than 100 is
  rejected.
- Pair payloads are authenticated and bound to the invite secret and both
  ephemeral keys. A substituted ephemeral key changes the SAS, which the users
  must compare.
- The invite record is deleted atomically on first redeem, so two devices
  cannot complete the same invite.
- TLS 1.3 is required and the leaf SPKI must match an embedded SHA-256 pin.
  Failures are hard failures.

### Ephemerality

- Conversations and messages carry a 24-hour expiry.
- Deletion overwrites ciphertext and wrapped DEK columns with zeros, deletes
  the row, and SQLite runs with `secure_delete=ON`; conversation deletion also
  clears the ratchet state and wraps. `wipe` deletes every row and vacuums.
- The relay sweeper deletes expired invites and envelopes every 60 s
  (1 s in the test profile).
- Handshake envelopes use a 120 s relay TTL.
- There is no archive, export, backup or recovery feature.

### Local UI protection

- The native plugin sets `FLAG_SECURE` on the activity in release builds,
  blocking screenshots and blanking the recents thumbnail.
- Message text and SAS values are non-selectable. No copy/export action exists.
- The app never logs bodies, keys, secrets or plaintext conversation ids.

### Abuse resistance

- Invite creation is rate-limited per client address, one-time, and expires.
- A mailbox is capped at 200 live envelopes.
- Request size, invite size and envelope size are bounded before allocation.
- The relay exposes no OpenAPI/docs endpoints and does not log requests.

## Limitations and non-properties

### No post-compromise security

The per-message ratchet deletes old chain keys, so messages already consumed
stay secret if the current state leaks. It is a symmetric chain, not an X3DH /
Double Ratchet: an attacker who obtains the current chain key can derive all
future message keys until the peer re-pairs. The Security screen says this
explicitly. Re-pairing with the same identity replaces the conversation and
shreds the old one, which is the only recovery path.

### Metadata is visible

The relay sees:

- a 16-byte mailbox id and how often it is polled;
- the padded envelope size (one of four buckets) and the number of messages;
- timestamps, client IP address, and TLS connection metadata;
- the 32-byte invite id (`SHA-256(S)`) and the 36-byte public invite payload.

It cannot link mailbox ids across days without the conversation secret, but it
can link repeated polls of the same daily id and infer activity. There is no
cover traffic, delay, mixnet or dummy-message padding schedule. A global
observer can perform traffic analysis even with perfect cryptography.

### Endpoint compromise

- A rooted device, custom ROM, debuggable build, or malware with app-private
  access can read the SQLite database and process memory while the app is
  unlocked. The file-identity fallback is especially exposed: its Ed25519 seed
  is a file, not hardware-bound.
- Android Keystore protects key material at rest, but not a compromised running
  app that can ask Keystore to sign. In that case the attacker can derive the
  KEK and decrypt the local database.
- Screenshot blocking is enforced only by the native plugin. If it is missing
  or the channel failed, the app shows a red degraded banner and reports
  **Screenshot block: OFF**. It does not claim otherwise.
- An external camera pointed at the screen is out of scope.
- The OS clipboard, accessibility services and OEM screenshot tools may capture
  text even though the app offers no copy action.

### Pairing is trust-on-first-use

- The SAS must be compared out of band. A user who taps "codes match" without
  comparing accepts a machine-in-the-middle.
- A shoulder-surfed QR code or manual secret lets the observer redeem the
  invite first. The invite is one-time and expires in 120 s; an observer who
  loses the race cannot pair.
- The relay can deny service (drop handshake envelopes) but cannot silently
  complete a pairing without a SAS mismatch.

### No recovery

There is no password, seed phrase, account, escrow or server-side backup.
Losing the device, uninstalling the app, or using "Delete everything" destroys
the identity and all conversations irreversibly. This is intentional.

### Relay storage and operators

- The Postgres volume is persistent. Expiry removes rows, but the operator (or
  a host-level backup) may retain filesystem snapshots; ciphertext in those
  snapshots is useless without the conversation secrets, which never reach the
  relay, but metadata may remain.
- The relay is a single process in the reference deployment. Its rate limiter
  and mailbox cap are per process; horizontal scaling needs shared state.
- No independent audit or penetration test has been performed. The claims here
  are claims about this code, not about an audited product.

### Transport edge cases

- The app-layer pin set is compiled into the APK. A pin rotation requires an app
  update; there is no remote pin update (which would itself be a trust anchor).
- TLS 1.3 is required. A relay behind a TLS 1.2-only terminator will fail
  closed.
- The pin protects the Python relay connection only. The app makes no other
  network requests, but Flet/Flutter runtime telemetry, if enabled by a future
  build, would not be covered.

### Input and implementation limits

- Message bodies are limited to 8188 UTF-8 bytes before padding.
- A conversation is limited to messages the sender can produce before the
  24-hour conversation expiry; there is no offline outbox or retry queue.
- The UI polls; a message may be visible up to a few seconds after it arrives.
- Only one identity and one device per install. Multi-device sync is not
  implemented.
- QR *scanning* is not implemented in the v1 Android build; the QR is displayed
  and the same secret can be typed manually. Do not claim camera scanning.

## Failure behaviour

- Missing native extension: file identity + red degraded banner; messaging
  still works but screenshots are not blocked.
- Missing relay pins in a release build: the client refuses to construct;
  pairing/messaging are disabled with an explicit banner.
- TLS/pin failure: no fallback, no retry without pinning.
- Database belongs to a different identity: startup fails closed rather than
  mixing keys.
- Corrupt record: AEAD failure raises; the record is not displayed.
- Relay unreachable: messages already sent remain encrypted on the relay until
  TTL; the UI reports that the send failed instead of pretending success.

## Security checklist

See `docs/security-checklist.md` for the line-by-line status of the project
checklist, including the explicitly failed items.
