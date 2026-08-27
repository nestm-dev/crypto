# Contributing

## Setup

Use Node.js 22.13 or newer and the package-manager version declared in `package.json`.

```bash
corepack enable
pnpm install
```

The package is ESM-only. TypeScript source uses explicit extensions and must remain compatible with
NodeNext resolution. Nest providers use legacy decorator metadata because that is the contract NestJS
12 consumes.

### Tenant development dependency

The development dependency is pinned to the first tenant release containing the context-reader
contract, `@nestm/tenant@0.1.0-alpha.7`. Keep it registry-resolvable so standalone CI and release jobs
do not depend on a sibling checkout. The public peer range remains `>=0.1.0-alpha.3 <0.2.0`.

The packed-consumer test may use a sibling tenant checkout during coordinated local development. Set
`NESTM_TENANT_PACKAGE` to an explicit registry version or tarball to exercise another release candidate.

## Workflow

```bash
pnpm run check          # Oxlint, Prettier, and TypeScript
pnpm run test           # deterministic and mocked unit/contract tests
pnpm run test:live      # explicit, credential-gated cloud KMS tests
pnpm run build          # tsdown ESM output in dist/
pnpm run verify:pack    # package shape, Publint, ATTW, and packed consumers
pnpm run verify         # all non-live release gates
```

Live tests must never be part of the default test command or require credentials in CI. Use disposable
test keys, narrowly scoped identities, and provider-specific environment variables. Never place key
material, cloud credentials, plaintext, wrapped keys, or real ciphertext fixtures in source control.
The accepted gates are `NESTM_CRYPTO_LIVE_AWS_KEY_ID`, `NESTM_CRYPTO_LIVE_GCP_KEY_NAME`, and the
pair `NESTM_CRYPTO_LIVE_AZURE_KEY_ID` / `NESTM_CRYPTO_LIVE_AZURE_ACCESS_TOKEN`. AWS uses its default
credential chain, Google uses Application Default Credentials, and the Azure token must be short-lived.

Add a Changeset for every user-visible change:

```bash
pnpm changeset
```

## Security invariants

- Preserve the versioned, canonical envelope format and authenticated header/AAD framing.
- Never release plaintext before AEAD authentication succeeds.
- Use a fresh 96-bit nonce for every AES-256-GCM encryption under a data key.
- Keep plaintext data keys operation-scoped; do not add a persistent data-key cache.
- Normalize malformed, wrong-context, and wrong-key failures without logging sensitive values.
- Keep `@nestm/crypto/core` free of NestJS, tenant, and cloud SDK imports.
- Keep cloud provider names logical and configured. Never construct key resource names from tenant input.
- Treat `inspect()` metadata as untrusted until decryption authenticates the envelope.
- Preserve tenant fail-closed behavior for missing context and unscoped bypass.

Changes to envelope framing, key lifecycle, tenant binding, provider routing, or failure classification
need focused negative tests and a security review. Do not silently change the meaning of an existing
envelope version.

## Pull requests

Keep changes focused, document public behavior, add regression coverage, and run `pnpm run verify`.
Do not publish packages, create cloud keys, or add a Git remote from a contribution workflow.
