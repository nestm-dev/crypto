# @nestm/crypto

## 0.1.0-alpha.1

### Minor Changes

- a90d79a: Add `@nestm/crypto/keys`: X25519 keypair generation with raw/DER conversion, an HKDF-SHA256
  helper, and a recipient-addressed `sealTo`/`openFrom` primitive (ephemeral-static X25519 →
  HKDF-SHA256 → AES-256-GCM) for wrapping an existing secret to a public key. The wire format is
  version- and suite-tagged; the recipient public key is bound into the key schedule by the
  library, the nonce is derived and never transmitted, callers may bind key-schedule `info` and
  AEAD `aad`, and failures use the existing `CryptoError` codes. Independent of `DataKeyProvider`
  and `CipherEngine`; `@nestm/crypto/core` stays free of NestJS, tenant, and cloud SDK imports.
- f7de164: Add tenant-aware text batches, typed value codecs, explicit NestJS HTTP field adapters, and a
  schema-agnostic Prisma write-encryption processor. Existing ciphertext is authenticated before
  idempotent writes, batch resources are bounded, and the new persistence APIs never accept plaintext
  data-encryption keys.

## 0.1.0-alpha.0

### Minor Changes

- Bootstrap the prerelease package for authenticated AES-256-GCM encryption, envelope key
  providers, explicit field helpers, and tenant-bound encryption for NestJS 12.
