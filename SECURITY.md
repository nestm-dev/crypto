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
every persistence path invokes the field service; v1 intentionally does not claim transparent ORM or
HTTP interception.

Field plaintext beginning with the reserved `nmc` namespace is rejected even in migration mode; this
prevents malformed or future envelope versions from being persisted as clear text.

## Operational guidance

- Put stable, domain-specific data classification in `purpose`; never use request IDs or mutable labels.
- Keep caller AAD reproducible for as long as ciphertext must remain decryptable.
- Monitor authentication failures and provider failures without logging values or native SDK payloads.
- Test key rotation and disaster recovery with representative ciphertext before retiring a key.
- Bound input sizes before accepting untrusted ciphertext; the library is buffered and not a streaming
  encryption format.
- Run credential-gated live tests only against disposable provider resources.
