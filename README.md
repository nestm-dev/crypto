# @nestm/crypto

Authenticated, versioned encryption for Node.js and NestJS 12. The package provides an
AES-256-GCM core, envelope key providers, explicit field traversal, cloud KMS adapters, and a
fail-closed bridge to `@nestm/tenant`.

> This package is an alpha. Pin an exact version, retain every key needed by stored ciphertext, and
> test rotation and recovery before using it for production data.

## Requirements and installation

- Node.js 22.13 or newer
- ESM and NodeNext module resolution
- NestJS 12 only when using the root, field, or tenant services

Install only the integrations the application uses:

```bash
pnpm add @nestm/crypto

# Nest integration
pnpm add @nestjs/common@next @nestjs/core@next reflect-metadata rxjs

# Optional tenant bridge
pnpm add @nestm/tenant

# Optional cloud adapters
pnpm add @aws-sdk/client-kms
pnpm add @google-cloud/kms
pnpm add @azure/core-auth @azure/keyvault-keys
```

Cloud SDKs, NestJS, and `@nestm/tenant` are optional peers. A consumer that imports only
`@nestm/crypto/core` installs none of them.

## NestJS quick start

Register one or more logical providers and select the default. Load the key-encryption key from a
secret manager or other durable key source; do not generate a new wrapping key at every startup.

```ts
import { Module } from "@nestjs/common";
import { AesKeyRingProvider, CryptoModule } from "@nestm/crypto";

declare const currentKek: Uint8Array;
declare const previousKek: Uint8Array;

@Module({
	imports: [
		CryptoModule.forRoot({
			defaultProvider: "local",
			providers: [
				{
					name: "local",
					provider: new AesKeyRingProvider({
						activeKeyId: "2026-08",
						keys: {
							"2026-05": previousKek,
							"2026-08": currentKek,
						},
					}),
				},
			],
		}),
	],
})
export class ApplicationModule {}
```

Inject `CipherService` into an application service:

```ts
import { Injectable } from "@nestjs/common";
import { CipherService } from "@nestm/crypto";

@Injectable()
export class CustomerSecrets {
	constructor(private readonly cipher: CipherService) {}

	encryptTaxId(taxId: string): Promise<string> {
		return this.cipher.encryptText(taxId, { aad: "customer.tax-id" });
	}

	decryptTaxId(envelope: string): Promise<string> {
		return this.cipher.decryptText(envelope, { aad: "customer.tax-id" });
	}
}
```

`CryptoModule.forRootAsync()` accepts the same options through a Nest factory. Modules are local by
default; pass the module extra `isGlobal: true` only when the application deliberately wants a global
provider.

## Framework-neutral core

`CipherEngine` exposes the same buffered API without importing NestJS:

```ts
import { generateKeySync } from "node:crypto";
import { AesKeyRingProvider, CipherEngine } from "@nestm/crypto/core";

const engine = new CipherEngine({
	defaultProvider: "ephemeral",
	providers: [
		{
			name: "ephemeral",
			provider: new AesKeyRingProvider({
				activeKeyId: "demo",
				keys: { demo: generateKeySync("aes", { length: 256 }) },
			}),
		},
	],
});

const envelope = await engine.encryptText("hello", { aad: "example.message" });
const plaintext = await engine.decryptText(envelope, { aad: "example.message" });

await engine.close();
```

The generated key in this example is intentionally ephemeral. Persisted data would become
undecryptable after restart; production applications need a durable wrapping key or KMS provider.

## Operations

Both `CipherService` and `CipherEngine` provide:

- `encryptText()` and `decryptText()` for UTF-8 strings;
- `encryptBytes()` and `decryptBytes()` for `Uint8Array` values;
- `reencrypt()` to authenticate and rewrite one envelope with the selected current provider/cipher;
- `inspect()` to parse visible envelope metadata.

Operations accept `AbortSignal`. Encrypt can select a registered logical `provider` and `cipher`;
decrypt can restrict `allowedProviders`. The default maximum buffered plaintext/ciphertext size is
10 MiB and can be changed with `maxPayloadBytes` at engine/module registration.

Cancellation rejects the caller promptly and is cooperative underneath: a provider or cloud SDK that
cannot interrupt an in-flight request may finish that request in the background, and its late result is
discarded.

Use stable, reproducible AAD for domain separation:

```ts
const encrypted = await cipher.encryptText(value, {
	aad: "billing.invoice.external-reference",
});
```

The identical AAD is required for decryption. `keyContext` is an advanced provider-wrapping context and
must also be reproducible; the tenant bridge supplies its own framed and hashed context automatically.

`inspect()` always returns `authenticated: false`. It must not decide tenant identity, authorization,
provider permissions, or whether a value is trusted. Those decisions occur only during authenticated
decryption.

## Envelope and rotation

Ciphertext is encoded as:

```text
nmc1.<protected>.<wrappedKey>.<iv>.<ciphertext>.<tag>
```

The canonical protected header records the format version, cipher, logical provider, key reference,
and wrapping algorithm. Header bytes, the wrapped key, and caller context are authenticated by
AES-256-GCM. The current version uses a fresh 32-byte data key and 12-byte nonce per encryption with a
16-byte authentication tag.

The `nmc1` format constrains registered ciphers to a 12-byte nonce so batch encryption can reserve the
final four bytes for a collision-free operation counter. The cipher/provider contracts are extensible,
but an algorithm needing a different nonce construction requires a future envelope version.

Wrapping-key rotation does not require immediately rewriting every value: keep old keys in the local
ring as decrypt-only entries, or keep an old named provider in `allowedProviders`. Use `reencrypt()` to
move one authenticated value to the current route, then retire old material only after verifying no
stored envelopes depend on it.

## Field encryption

The `@nestm/crypto/fields` entry point provides `@EncryptedField("stable.purpose")` and an explicit
`FieldCipherService`. Traversal mutates the supplied class instance in place, encrypts decorated string
properties, preserves `null`/`undefined`, and supports nested decorated class instances and arrays.

```ts
import { EncryptedField, FieldCipherService } from "@nestm/crypto/fields";

class CustomerRecord {
	@EncryptedField("customer.tax-id")
	taxId: string | null = null;
}

declare const fields: FieldCipherService;
const record = new CustomerRecord();
record.taxId = "123-45-6789";
await fields.encryptFieldsInPlace(record);
await fields.decryptFieldsInPlace(record);
```

`CryptoModule` provides and exports `FieldCipherService`; inject it like any Nest provider.

Traversal fails on cycles, excessive depth, unsupported decorated values, and ambiguous plain nested
objects. It does not hook HTTP serialization or an ORM. Every persistence/read path remains responsible
for calling the service.

Strict decryption is the default. A migration may explicitly allow legacy plaintext, but malformed,
tampered, wrong-purpose, and cross-context envelopes still fail. An existing envelope counts as an
idempotent encrypted value only after it authenticates in the active context.

The complete `nmc` string prefix is reserved for versioned ciphertext. Legacy-plaintext mode rejects
every value beginning with that prefix, including malformed and future-looking versions.

## Tenant-bound encryption

`@nestm/crypto/tenant` integrates with the narrow `TENANT_CONTEXT_READER` port from
`@nestm/tenant/context`. `TenantCipherService` derives the active canonical tenant from context; its
ordinary methods do not accept a tenant ID, raw key reference, or arbitrary provider override.

`TenantCryptoModule` must be able to inject both the tenant context reader and `CipherService`. The
tenant module is global by default; keep crypto local by importing it into the tenant bridge:

```ts
import { Module } from "@nestjs/common";
import { CryptoModule } from "@nestm/crypto";
import { TenantCryptoModule } from "@nestm/crypto/tenant";
import { TenantModule } from "@nestm/tenant";

declare const cryptoOptions: Parameters<typeof CryptoModule.forRoot>[0];
declare const tenantOptions: Parameters<typeof TenantModule.forRoot>[0];

@Module({
	imports: [
		TenantModule.forRoot(tenantOptions),
		TenantCryptoModule.forRoot({
			namespace: "billing-api",
			imports: [CryptoModule.forRoot(cryptoOptions)],
		}),
	],
})
export class ApplicationModule {}
```

If the tenant module is configured with `isGlobal: false`, include it in the bridge's `imports` too.

```ts
const envelope = await tenantCipher.encryptText(value, {
	purpose: "customer.tax-id",
});

const valueAgain = await tenantCipher.decryptText(envelope, {
	purpose: "customer.tax-id",
});
```

Every tenant module registration requires a stable application namespace. The authenticated context
binds that namespace, canonical tenant ID, purpose, and caller AAD. Copying ciphertext to another tenant
therefore fails even if both tenants use the same wrapping key.

An optional `TenantCryptoPolicy` resolves logical `{ writeProvider, readProviders }` routes for the
current tenant. New data uses `writeProvider`; decrypt and re-encryption may read staged legacy routes.
Provider aliases must come from the immutable core registry and must never be constructed from tenant
input. Disallowed envelope routes fail before an unwrap/KMS call.

Missing tenant context and ordinary unscoped bypass fail closed. An audited targeted bypass from
`@nestm/tenant` can operate only on its canonical target. Encrypt global/system data with the ordinary
`CipherService`, not a synthetic tenant.

`TenantFieldCipherService` applies the same tenant binding to decorated fields and resolves the tenant
profile once per traversal.

## Key-provider entry points

| Entry point                  | Purpose                                                                       |
| ---------------------------- | ----------------------------------------------------------------------------- |
| `@nestm/crypto/core`         | AES-256-GCM engine, envelope codec, local AES KEK ring, contracts, and errors |
| `@nestm/crypto/key-wrap/rsa` | RSA-OAEP-SHA256 wrapping with named public/private keys                       |
| `@nestm/crypto/kms/aws`      | AWS KMS data-key generation and decrypt                                       |
| `@nestm/crypto/kms/gcp`      | Google Cloud KMS encrypt/decrypt with AAD and CRC32C validation               |
| `@nestm/crypto/kms/azure`    | Azure Key Vault/Managed HSM wrap/unwrap                                       |
| `@nestm/crypto/testing`      | dependency-free deterministic nonce source for tests                          |

Adapters accept caller-owned SDK clients as well as configuration-created clients. Caller-owned clients
are never closed; owned clients are closed or released where the SDK exposes that lifecycle. Each cloud
subpath can be imported independently; importing core never loads a cloud SDK.

Register an adapter under a logical name exactly like the local key ring:

```ts
import { AwsKmsProvider } from "@nestm/crypto/kms/aws";
import { AzureKeyVaultProvider } from "@nestm/crypto/kms/azure";
import { GcpKmsProvider } from "@nestm/crypto/kms/gcp";

const aws = new AwsKmsProvider({
	keyId: "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000",
	clientConfig: { region: "us-east-1" },
});

const gcp = new GcpKmsProvider({
	keyName: "projects/example/locations/global/keyRings/app/cryptoKeys/records",
});

declare const azureCredential: import("@azure/core-auth").TokenCredential;
const azure = new AzureKeyVaultProvider({
	keyId: "https://example.vault.azure.net/keys/records/00000000000000000000000000000000",
	credential: azureCredential,
});
```

AWS aliases are rejected in favor of stable key IDs/ARNs. Google Cloud requires a full CryptoKey
resource name. Azure requires a canonical version-specific key URL and defaults to RSA-OAEP-256;
A256KW is available for compatible Managed HSM keys. Library-owned Azure credentials are sent only
to known Azure Key Vault/Managed HSM DNS suffixes or exact application-configured `trustedHosts`.
Applications may pass a prebuilt SDK client instead of construction options.

## Errors

Failures use `CryptoError` and a stable `code`, including configuration/argument failures, malformed or
unsupported envelopes, provider/key lookup failures, authentication failures, size limits,
cancellation, tenant/field policy failures, and cipher failures.

```ts
import { isCryptoError } from "@nestm/crypto/core";

try {
	await cipher.decryptText(envelope, { aad: purpose });
} catch (error: unknown) {
	if (isCryptoError(error, "AUTHENTICATION_FAILED")) {
		// Return a generic invalid-ciphertext response. Do not log the value.
	}
	throw error;
}
```

Error messages intentionally omit plaintext and key material. Native causes are reduced to a
non-secret failure summary (plus safe numeric status metadata where available); the original provider
message and payload are never attached. Sanitize logs before recording any error.

## Development

```bash
pnpm run check
pnpm run test
pnpm run build
pnpm run verify:pack
```

Live cloud tests are credential-gated and separate:

```bash
# AWS default credential chain; the key must be a stable key ID or ARN.
NESTM_CRYPTO_LIVE_AWS_KEY_ID=... AWS_REGION=... pnpm run test:live

# Google Application Default Credentials.
NESTM_CRYPTO_LIVE_GCP_KEY_NAME=projects/.../cryptoKeys/... pnpm run test:live

# A short-lived Azure access token and a version-specific key URL.
NESTM_CRYPTO_LIVE_AZURE_KEY_ID=https://.../keys/.../... \
NESTM_CRYPTO_LIVE_AZURE_ACCESS_TOKEN=... pnpm run test:live

# With no configured provider, all live cases are reported as skipped.
pnpm run test:live
```

See [SECURITY.md](./SECURITY.md) for the threat model and operational guidance and
[CONTRIBUTING.md](./CONTRIBUTING.md) for the prerelease tenant dependency gate.
