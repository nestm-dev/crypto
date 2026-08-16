# Security policy

## Supported versions

`@nestm/crypto` is prerelease software. Security fixes are provided on the latest published alpha only.
Consumers should pin an exact alpha and review its changelog before upgrading.

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub Security Advisories for
[`nestm-dev/crypto`](https://github.com/nestm-dev/crypto/security/advisories/new). Do not open a public
issue for a suspected vulnerability.

Include the affected version and provider, a minimal reproduction using nonproduction keys, the
expected impact, and any suggested mitigation. Do not include real plaintext, credentials, private
keys, production key identifiers, or production ciphertext.

## Security goal and boundary

The library protects buffered application values at rest against disclosure and undetected
modification when the wrapping keys and application process remain trusted. It authenticates the
versioned envelope, wrapped data key, caller context, and ciphertext before returning plaintext.

It does not protect data from:

- a compromised application process that can call decrypt;
- an incorrectly authorized endpoint, job, administrator, or targeted tenant bypass;
- plaintext copied to logs, traces, exceptions, caches, queues, or database indexes;
- traffic interception outside the application's transport-security boundary;
- deletion, rollback to an older valid ciphertext, or traffic analysis based on ciphertext length;
- loss of every key version needed to unwrap historical data.

Applications remain responsible for authorization, transport security, audit retention, key policy,
backup/restore policy, and deciding which data must be encrypted.

## Cryptographic construction

- Payloads use AES-256-GCM with 256-bit data keys, 96-bit nonces, and 128-bit authentication tags.
- Every encryption operation generates a fresh data key. Multi-field traversal may share one operation-scoped
  data key but must use a unique nonce per field.
- Envelope metadata and external context are length-framed and authenticated. The compact envelope is
  versioned as `nmc1.<protected>.<wrappedKey>.<iv>.<ciphertext>.<tag>`.
- Wrapped data keys use a configured local AES key-encryption-key ring, RSA-OAEP-SHA256, AWS KMS,
  Google Cloud KMS, or Azure Key Vault/Managed HSM.
- Plaintext data keys are held as `KeyObject` values as early as practical. Temporary byte buffers are
  zeroed best-effort, but JavaScript runtimes cannot guarantee erasure of every copy.
- No persistent plaintext data-key cache is part of the design.

Malformed inputs, noncanonical encoding, unknown versions or algorithms, invalid key sizes, wrong AAD,
wrong keys, truncated tags, and modified ciphertext fail closed. Authentication failures deliberately
avoid revealing which authenticated component was wrong. Operational provider outages remain distinct
so operators can diagnose availability without exposing key material.

`inspect()` only parses visible envelope metadata. It does not authenticate that metadata and must not
drive authorization, provider selection, billing, audit identity, or tenant identity.

## Key-provider boundary

Wrapping providers are trusted to enforce key authorization and return the requested key material.
Configure logical provider aliases in application-owned configuration. The library never discovers a
cloud resource by concatenating tenant IDs or other untrusted input into an ARN, alias, URL, vault name,
or key name.

Use least-privilege cloud identities and separate administrative key-management rights from runtime
encrypt/decrypt rights. Prefer provider audit logs, rotation policies, deletion protection, and
region-specific controls appropriate to your threat model. Caller-owned SDK clients and credentials
remain the caller's lifecycle responsibility; the library never closes them. It closes or releases only
owned clients, and only where the SDK exposes such a lifecycle.

Local AES and RSA providers shift key custody into the application. Load their secrets from a managed
secret source, keep active wrapping keys separate from legacy decrypt-only keys, and retain old keys
until all dependent ciphertext has been re-encrypted and verified.

## Tenant boundary

`@nestm/crypto/tenant` derives the canonical tenant only from `TENANT_CONTEXT_READER`. Its ordinary
methods do not accept a tenant ID, raw key reference, or arbitrary provider override. The authenticated
payload context binds a stable application namespace, canonical tenant ID, operation purpose, and
caller AAD. A ciphertext copied between tenants therefore fails even when tenants share a wrapping key.

The configured tenant policy may select only logical provider aliases from the immutable core registry.
The envelope's alias is checked against the tenant's allowed read routes before any external unwrap
call. Missing tenant context and unscoped bypass fail before provider access. Targeted bypass remains an
audited administrative authority and must never be treated as ordinary tenant authority by other
services.

Tenant operations revalidate their lexical tenant capability after policy resolution and after
cryptographic work. Starting an operation without returning or awaiting it cannot carry tenant or
targeted-bypass authority beyond the upstream context callback. Authentication failures at this
boundary are re-emitted without provider-specific cause details, so wrong tenant, namespace, purpose,
AAD, or allowed route has one observable crypto failure shape.

Global or system data must use the non-tenant `CipherService`; do not invent a synthetic tenant ID.

## Field-encryption boundary

Field traversal is explicit and in-place. It encrypts decorated strings, preserves `null` and
`undefined`, and rejects unsupported/cyclic structures rather than silently skipping fields. Existing
envelopes are idempotent only after authentication in the active context.

Plain nested objects and opaque containers such as `Map` and `Set` are rejected. All transformed
strings are authenticated and UTF-8 validated before the in-place commit begins; assignment failures
trigger a best-effort rollback.

Legacy plaintext passthrough is an explicit migration option. It must never pass through a value that
looks like a malformed, tampered, wrong-purpose, or cross-tenant envelope. Applications must ensure
every persistence path invokes the field service or an explicit integration adapter. The HTTP and
Prisma subpaths cover only the routes and write shapes that an application deliberately registers;
they do not make encryption transparent across every framework or database access path.

Field plaintext beginning with the reserved `nmc` namespace is rejected even in migration mode; this
prevents malformed or future envelope versions from being persisted as clear text.

## HTTP adapter boundary

`@nestm/crypto/http` does not validate request DTOs. The encryption pipe requires Nest validation and
class transformation to have already produced a real DTO instance; ambiguous plain objects fail
closed. Response decryption is opt-in through handler metadata and reconstructs the declared response
DTO before field traversal. A decorated non-null response cannot silently bypass missing tenant
context, malformed ciphertext, wrong-purpose ciphertext, or unsupported object shapes.

Do not attach the response interceptor to streams, files, exception payloads, or routes whose response
contract is not the declared DTO. Configure validation with `transform`, `whitelist`, and
`forbidNonWhitelisted` according to the application's input policy.

## Prisma adapter boundary

`@nestm/crypto/prisma` is a schema-agnostic write-argument processor, not an automatic schema scanner
or read interceptor. Its application-owned registry assigns a stable purpose to every protected
model field. Existing `nmc` values authenticate under the active tenant and field purpose before an
idempotent write accepts them; envelope shape or `inspect()` metadata alone is never sufficient.

The processor never accepts a raw or encoded plaintext data key. It completes traversal and
cryptographic work before committing encrypted strings to caller-owned Prisma arguments, with
best-effort rollback if assignment is rejected. Applications remain responsible for invoking it on
every registered write path and for separately decrypting data at a DTO or service boundary.

The registry binds ciphertext to the tenant, application namespace, and field purpose, but not to a
specific database row. Like other AEAD schemes, it does not prevent replaying a valid envelope into a
different row that uses the same purpose in the same tenant. Applications that require row binding
must use an explicit service boundary with stable row-specific AAD; a future Prisma AAD-resolver API
would need to define update/upsert identity and migration behavior before offering that guarantee.

## Chunked stream boundary

`@nestm/crypto/stream` (`nmcs1`) protects whole objects, buffered or streamed.

- The 512-byte header is authenticated by its own tag and hashed into the chunk key schedule, so a
  change to the key reference, chunk size, context associated data, or inline wrap records makes
  every chunk fail authentication. Header padding must be zero and reserved flag bits must be clear.
- Each chunk's nonce is `noncePrefix ‖ chunkIndex ‖ finalFlag`, where the prefix derives from the
  data key and a per-object random 16-byte file identifier. **No nonce input is ever persisted or
  read back from storage.** A counter written to a database and later restored to an earlier point
  in time — by point-in-time recovery, a replica promotion, or a restored backup — would reissue
  nonces under the same key and break AES-GCM catastrophically. Any future change to this format
  must preserve that property: nonces come from a CSPRNG draw or from an HKDF over per-object
  random material, never from durable mutable state.
- The final chunk is flagged in both its nonce and its associated data, so truncation, chunk
  reordering, and splicing chunks between objects all fail authentication rather than yielding a
  short or wrong plaintext.
- `createChunkedOpenStream` emits an **authenticated prefix**. Each chunk is verified before it is
  emitted, but truncation is only detectable at end of stream, so a consumer acting on partial
  output may act on a prefix of the plaintext. Use `openChunked` where all-or-nothing semantics are
  required, and treat a stream that errors mid-flight as having produced nothing.
- `inspectChunked` reports framing only and marks itself `authenticated: false`. Never make a trust
  decision on its output.
- The context associated data in the header is **not encrypted**. Bind location and ownership there
  (organization, workspace, object key); never put secrets in it.
- Bound `maxPlaintextBytes` and `maxChunkSizeLog2` when opening untrusted ciphertext; a hostile
  header can otherwise declare a chunk size far larger than the reader intends to buffer.
- The chunk-size ceiling is symmetric: sealing and opening both default to `2^24`, so the
  library never writes an object that a default reader would refuse. Exponents of 25 and 26
  exist in the format but require `maxChunkSizeLog2` on the seal side _and_ the open side;
  an object written above the default is unreadable to a caller that has not opted in.
- The per-object file identifier is drawn from the CSPRNG on every seal and is deliberately
  not settable through `ChunkedSealOptions`. It is the only per-object input to the key
  schedule, so reusing one under the same data key would repeat a chunk key and nonce
  prefix — exposing the XOR of two plaintexts and leaking the header GMAC subkey. The
  `@nestm/crypto/testing` seam that pins it exists solely to freeze format vectors and must
  never be reachable from production code.
- Never persist a nonce, a nonce counter, or a file identifier and replay it. Nonces here are
  either drawn fresh or derived from a fresh per-object identifier, which is what makes a
  database rollback (point-in-time restore, replica promotion) unable to cause nonce reuse.
- `scrypt` parameters are bounded absolutely, not just per field: a derivation may not
  reserve more than 1 GiB, and `maxmem` is capped independently of the caller. Combined with
  the concurrency semaphore, this keeps a password-hardening parameter from becoming a
  denial-of-service lever.

## Password and recovery-code boundary

`@nestm/crypto/password` derives key-encryption keys from user-supplied secrets.

- scrypt is memory-hard by design: each derivation holds roughly `128 * N * r` bytes, which is
  64 MiB at the shipped defaults. `createPasswordKdf` bounds concurrent derivations (default 4) to
  keep a burst of sign-ins from exhausting memory; raise the limit only against measured headroom.
- Parameters and salt are per-record and versioned. Re-derive and re-wrap on the next successful
  authentication when policy strengthens; never reuse a salt across records.
- Always pass `info` to separate purposes. Without it, the same password yields the same key for
  every use.
- Recovery secrets are full-entropy, so `deriveRecoveryKey` uses HKDF rather than a memory-hard KDF.
  Store only the wrap the recovery key produces — persisting a verifier hash of the code creates an
  offline oracle for anyone who reads the database.
- Recovery codes are display-once. The library never retains one, and `parseRecoveryCode` fails
  closed on any prefix, character, length, canonicality, or checksum deviation.
- A derived key is a `KeyObject`. Node keeps that material outside the JavaScript heap, but it
  cannot be wiped on demand; see the custody note below.

## Key custody

Unwrapped keys live only in process memory for as long as the application holds them.

- The library zeroes its own intermediate buffers, but a resident `KeyObject` is released to the
  runtime, not erased. Anything that can read process memory — a core dump, a heap snapshot, an
  attached debugger, `--inspect` — is equivalent to holding the keys.
- Disable core dumps and inspector ports in production, and keep key material out of logs, error
  causes, and crash reporters.
- Keys held for a session should have an explicit lifetime and be dropped on sign-out, session
  revocation, and password change. Replicating them to a shared cache re-introduces a decryptable
  copy at rest and weakens the model that per-user key derivation is there to provide.

## Operational guidance

- Put stable, domain-specific data classification in `purpose`; never use request IDs or mutable labels.
- Keep caller AAD reproducible for as long as ciphertext must remain decryptable.
- Keep `maxPayloadBytes`, `maxBatchItems`, and `maxBatchBytes` aligned with endpoint limits. Defaults
  bound a batch to 256 items and 10 MiB of aggregate plaintext/ciphertext.
- Monitor authentication failures and provider failures without logging values or native SDK payloads.
- Test key rotation and disaster recovery with representative ciphertext before retiring a key.
- Bound input sizes before accepting untrusted ciphertext. The `nmc1` envelope is buffered and not a
  streaming format; use `@nestm/crypto/stream` for payloads that must not be held in memory whole.
- Run credential-gated live tests only against disposable provider resources.
