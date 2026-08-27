---
"@nestm/crypto": minor
---

Add `@nestm/crypto/keys`: X25519 keypair generation with raw/DER conversion, an HKDF-SHA256
helper, and a recipient-addressed `sealTo`/`openFrom` primitive (ephemeral-static X25519 →
HKDF-SHA256 → AES-256-GCM) for wrapping an existing secret to a public key. The wire format is
version- and suite-tagged; the recipient public key is bound into the key schedule by the
library, the nonce is derived and never transmitted, callers may bind key-schedule `info` and
AEAD `aad`, and failures use the existing `CryptoError` codes. Independent of `DataKeyProvider`
and `CipherEngine`; `@nestm/crypto/core` stays free of NestJS, tenant, and cloud SDK imports.
