---
"@nestm/crypto": minor
---

Add the primitives a zero-access key hierarchy needs: password-derived key-encryption keys,
recipient-addressed key-wrap records, and a chunked streaming file format.

- `@nestm/crypto/password`: a registry-based `PasswordKdf` (`createPasswordKdf`,
  `scryptPasswordKdf`) deriving a 32-byte `KeyObject` from a login password via scrypt over
  `node:crypto` — no native dependency, versioned parameters stored through a canonical
  `encodePasswordKdfParams`/`decodePasswordKdfParams` codec, an explicit `maxmem`, and a FIFO
  semaphore bounding concurrent memory-hard derivations. Also ships display-once recovery
  codes (`generateRecoveryCode`, `parseRecoveryCode`, `deriveRecoveryKey`) as Crockford
  base32 in uniform eight-character groups — `ASR1-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX` for a
  128-bit secret — carrying a checksum wide enough to reject every single-character
  corruption, parsed fail-closed.
- `@nestm/crypto/keys`: `KeyWrapRecord` — one versioned record type covering both
  `wrapKeyWithSecret` (AES-256-GCM under a shared KEK) and `wrapKeyToRecipient` (sealed to an
  X25519 public key), with encode/decode for single records and lists, `selectKeyWrapRecord`,
  and `keyWrapRecordLength`. Both flavours authenticate the algorithm, recipient type, and
  recipient identifier, so a record cannot be replayed against a different recipient. Adds
  `hmacSha256` and a length-tolerant `timingSafeEqualBytes`.
- `@nestm/crypto/stream`: the `nmcs1` container — a fixed 512-byte authenticated header
  (magic, suite, chunk size, per-object random file identifier, key reference, context
  associated data, and optional inline wrap records) followed by AES-256-GCM chunks framed as
  `u32BE length ‖ ciphertext ‖ tag`. Per-chunk keys and nonce prefixes derive from
  HKDF-SHA256 over the data key, the file identifier, and a hash of the whole header, so no
  nonce counter is ever persisted and a rolled-back database cannot cause nonce reuse. The
  final chunk is flagged in both its nonce and its associated data, which makes truncation,
  reordering, and cross-object splicing fail authentication. Buffered `sealChunked`/
  `openChunked` and Web-Streams `createChunkedSealStream`/`createChunkedOpenStream` produce
  identical bytes when the plaintext length is declared (a stream that cannot know its length
  clears the declared-length flag instead), and the fixed header makes plaintext size exactly
  recoverable from ciphertext size via `chunkedPlaintextLength`. Sealing and opening share one
  default chunk-size ceiling of `2^24`, so the library never writes an object its own default
  reader would refuse; `2^25` and `2^26` require `maxChunkSizeLog2` on both sides. The
  per-object file identifier is never caller-supplied — pinning it is possible only through
  `@nestm/crypto/testing`, because reusing one under the same data key would repeat a
  keystream.
- `@nestm/crypto/core` now exports `isCipherEnvelope` for routing legacy plaintext during a
  migration. The envelope parser stays internal.
