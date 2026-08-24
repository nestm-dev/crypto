# @nestm/crypto

## 0.1.0-alpha.7

### Minor Changes

- 8256dee: Remove the storage-specific `@nestm/crypto/storage-workspace` integration and
  its optional `@nestm/storage` peer. Applications now compose storage policy,
  artifact record formats, authenticated path context, and searchable projections
  from the generic primitives exposed by `@nestm/crypto/core`.

## 0.1.0-alpha.6

### Minor Changes

- 1279ac3: Add the optional `@nestm/crypto/storage-workspace` bridge for composing a
  capability-scoped `@nestm/storage` workspace with strict, authenticated body
  encryption. The bridge keeps storage and crypto policies application-owned,
  binds ciphertext to stable workspace scope and canonical path context, exposes
  only a non-secret protection descriptor, and leaves the framework-neutral
  crypto core independent of storage.

## 0.1.0-alpha.5

### Minor Changes

- 8e48467: Make the local AES key ring fresh-format only: unwrap accepts exactly the 81-byte salted version 2
  wrapper and its `NESTM-A256GCM-HKDF-SHA256-SALT256-V2` identifier. Remove the deprecated version 1
  algorithm export and compatibility path; development data using another wrapper format must be reset.

## 0.1.0-alpha.4

### Minor Changes

- bc22fed: Derive a one-use AES-256-GCM wrapping key with HKDF-SHA256 and a fresh 256-bit salt for every
  local key-ring data key. Version 2 removes the need for a durable global wrapper-invocation counter
  and keeps 128-bit authentication.

## 0.1.0-alpha.3

### Minor Changes

- 4bad419: Add the cloud-neutral `@nestm/crypto/files` entry point and NMF1 streaming file encryption. The
  format uses fresh per-file data keys, fixed 1 MiB authenticated frames, a mandatory authenticated
  final frame and physical-EOF check, detached wrapped-key records, bounded backpressure-aware Web
  streams, and exact context/header/size/hash verification. Deterministic conformance vectors use an
  isolated fixture provider; production providers continue to use the platform CSPRNG.

## 0.1.0-alpha.2

### Minor Changes

- 16e1c5d: `AzureKeyVaultProvider` now fails closed on a non-empty wrapping context. Key Vault's
  wrapKey/unwrapKey operations accept no AAD or OAEP label, so a key context passed through the
  Azure provider was silently dropped instead of authenticated — wrapped keys would unwrap under
  any context. Both `generateDataKey` and `unwrapDataKey` now throw a `CONFIGURATION` error
  before calling the vault when `wrappingContext` is non-empty; envelopes using the Azure
  provider must be written without a key context.

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
