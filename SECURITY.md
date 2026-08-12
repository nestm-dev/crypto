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

## Operational guidance

- Put stable, domain-specific data classification in `purpose`; never use request IDs or mutable labels.
- Keep caller AAD reproducible for as long as ciphertext must remain decryptable.
- Keep `maxPayloadBytes`, `maxBatchItems`, and `maxBatchBytes` aligned with endpoint limits. Defaults
  bound a batch to 256 items and 10 MiB of aggregate plaintext/ciphertext.
- Monitor authentication failures and provider failures without logging values or native SDK payloads.
- Test key rotation and disaster recovery with representative ciphertext before retiring a key.
- Bound input sizes before accepting untrusted ciphertext; the library is buffered and not a streaming
  encryption format.
- Run credential-gated live tests only against disposable provider resources.
