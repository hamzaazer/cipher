# cipher-native

Flet extension and Flutter plugin used by Cipher for the two things Python
cannot do on Android:

1. **Keystore identity.** An RSA-2048 key is generated inside Android Keystore
   (StrongBox when the device offers it). The private key never leaves the
   keystore; Python receives only the X.509 public key and RSA PKCS#1 v1.5
   signatures over the fixed `KEK_INFO` label. PKCS#1 v1.5 is deterministic,
   so the same signature always derives the same master KEK.
2. **Screen protection.** `FLAG_SECURE` is applied as soon as the plugin
   attaches to the activity, which blocks screenshots, screen recording and
   the recents thumbnail. Touch filtering while overlapped is enabled.

The Dart layer is a dumb transport. It has no cryptography and no storage.

## Python API

```python
import cipher_native

cipher_native.available()             # channel attached?
cipher_native.ensure_identity_key()   # DER SubjectPublicKeyInfo bytes
cipher_native.sign(data)              # deterministic RSA signature bytes
cipher_native.destroy_identity()      # delete the Keystore entry
cipher_native.set_secure(True)        # idempotent
```

All functions raise when the channel is unavailable; callers fall back to the
file identity and must show degraded mode.

## Layout

- `src/cipher_native/` — Python control and helpers.
- `src/flutter/cipher_native/` — Flutter package. `flutter/` is copied into
  the APK by serious_python; `android/` contains the Kotlin plugin.

The package lives at the repository root (`native/`) because Flet resolves
`tool.flet.dev_packages` paths relative to the app directory (`app/`).
