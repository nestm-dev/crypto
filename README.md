# @nestm/crypto

Authenticated, versioned encryption for Node.js and NestJS 12. The package provides an
AES-256-GCM core, envelope key providers, explicit field traversal, cloud KMS adapters, a
fail-closed bridge to `@nestm/tenant`, an optional protected-workspace bridge to `@nestm/storage`,
and opt-in HTTP and Prisma field adapters.

> This package is an alpha. Pin an exact version, retain every key needed by stored ciphertext, and
> test rotation and recovery before using it for production data.

## Requirements and installation

- Node.js 22.13 or newer
- ESM and NodeNext module resolution
- NestJS 12 only when using the root, field, tenant, HTTP, or Prisma services

Install only the integrations the application uses:

```bash
pnpm add @nestm/crypto

# Nest integration
pnpm add @nestjs/common@next @nestjs/core@next reflect-metadata rxjs

# Optional tenant bridge
pnpm add @nestm/tenant

# Optional protected StorageWorkspace bridge (pin prerelease integrations exactly)
pnpm add @nestm/storage@0.1.0-alpha.9

# Optional HTTP DTO adapter
pnpm add class-transformer class-validator

# Optional cloud adapters
pnpm add @aws-sdk/client-kms
pnpm add @google-cloud/kms
pnpm add @azure/core-auth @azure/keyvault-keys
```

Cloud SDKs, NestJS, `@nestm/storage`, `@nestm/tenant`, and `class-transformer` are optional peers.
`class-validator` is application-owned and needed only when the app uses Nest's `ValidationPipe`
validation. The Prisma adapter is schema-agnostic and uses the consuming application's Prisma client,
so it adds no Prisma dependency. A consumer that imports only `@nestm/crypto/core` installs none of
the optional integrations.

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

## Streaming encrypted files

`@nestm/crypto/files` implements the NMF1 immutable-file format without importing NestJS, a database,
or an object-storage SDK. It accepts a Web `ReadableStream<Uint8Array>` or an
`AsyncIterable<Uint8Array>`, applies backpressure, and uses fixed 1 MiB authenticated frames so large
files are never buffered as one value.

The engine uses a fixed frame accumulator and retains at most one caller-owned source yield while
draining it. Generic live memory is therefore bounded by one frame plus the largest upstream yield;
applications that accept untrusted or SDK-provided streams should re-chunk source yields to at most
1 MiB before encryption or decryption.

```ts
import { generateKeySync } from "node:crypto";
import { AesKeyRingProvider } from "@nestm/crypto/core";
import { FileCipherEngine } from "@nestm/crypto/files";

const provider = new AesKeyRingProvider({
	activeKeyId: "workspace-domain-v1",
	keys: { "workspace-domain-v1": generateKeySync("aes", { length: 256 }) },
});
const files = new FileCipherEngine({
	defaultProvider: "workspace",
	providers: [{ name: "workspace", provider }],
	maxPlaintextBytes: 10n * 1024n * 1024n * 1024n,
});

declare const source: AsyncIterable<Uint8Array>;
declare const canonicalFileAad: Uint8Array;
declare function uploadCiphertext(stream: ReadableStream<Uint8Array>): Promise<void>;
const result = await files.encrypt(source, { aad: canonicalFileAad });

// Persist result.detachedKey, result.headerBytes, and result.wrappingContextDigest before
// consuming result.encrypted and uploading its first byte.
let summary: Awaited<typeof result.completion>;
try {
	[summary] = await Promise.all([result.completion, uploadCiphertext(result.encrypted)]);
} catch (error) {
	await result.cancel(error);
	throw error;
}
```

The object bytes contain only the clear NMF1 framing plus ciphertext and authentication tags. The
wrapped file key is detached for an authorized catalog. Decryption requires the caller-supplied AAD,
an explicitly allowed provider, and—where a catalog exists—the exact expected 52-byte header.
Completion/verification also authenticates the mandatory final frame and physical EOF.

An authenticated full frame may be emitted before a later frame or EOF fails. A download may stream
that authenticated prefix and abort on failure, but agents, previews, archive/skill validation, and
other side-effecting consumers must stage all plaintext until `verification` resolves.

## Protected storage workspaces

`@nestm/crypto/storage-workspace` composes an already-authorized `StorageWorkspace` from
`@nestm/storage/workspace` with an application-supplied authenticated cipher. The adapter imports
both libraries only from this optional subpath: `@nestm/crypto/core` and the root entry point remain
independent of storage, while `@nestm/storage` remains independent of key providers and crypto
policy.

The built-in `createCipherEngineWorkspaceCipher()` adapter uses `CipherEngine` and the bounded
`nmc1` format. It strictly encrypts the logical metadata record and body independently, and it rejects
plaintext, malformed records, wrong scope/policy/path context, and unauthenticated envelopes on read.
The backing workspace stores one versioned outer JSON record whose `metadata` and `content` members
are `nmc1` envelopes; it never receives the original body or logical content type.

```ts
import type { StorageWorkspace } from "@nestm/storage/workspace";
import type { CipherEngine } from "@nestm/crypto/core";
import {
	createCipherEngineWorkspaceCipher,
	protectStorageWorkspace,
} from "@nestm/crypto/storage-workspace";

declare const mountedWorkspace: StorageWorkspace;
declare const engine: CipherEngine;
declare const canonicalOrganizationId: string;
declare const canonicalWorkspaceId: string;

const logicalLimits = {
	...mountedWorkspace.limits,
	maxReadBytes: 1024 * 1024,
	maxWriteBytes: 1024 * 1024,
};
const protectedWorkspace = protectStorageWorkspace({
	storage: mountedWorkspace,
	cipher: createCipherEngineWorkspaceCipher(engine, {
		allowedProviders: ["workspace-current", "workspace-previous"],
	}),
	scopeContext: `organization:${canonicalOrganizationId}/workspace:${canonicalWorkspaceId}`,
	policyRevision: "artifact-body:v1",
	limits: logicalLimits,
	// This is a separate ceiling for the expanded outer record held by the backing workspace.
	maxCiphertextBytes: 2 * 1024 * 1024,
	// Explicitly accepts that the backing provider can search visible object paths.
	pathSearch: "provider-visible",
});

await protectedWorkspace.writeFile("reports/result.md", "# Verified\n", {
	mode: "create",
	contentType: "text/markdown; charset=utf-8",
});
const restored = await protectedWorkspace.readText("reports/result.md");
```

On the initial protected view, the path, page, search, cursor, and cursor-TTL limits must match the
already-mounted backing workspace because that capability owns their enforcement. Logical
`maxReadBytes` and `maxWriteBytes` may be lower. A derived `mount()` creates a correspondingly narrowed
backing capability, so every child limit can be reduced safely. Configure `CipherEngine.maxPayloadBytes`
to cover the larger logical read/write ceiling and size `maxCiphertextBytes` for `nmc1` plus outer-record
expansion; a plaintext value within its logical limit can still exceed an undersized physical ceiling.

`scopeContext` and `policyRevision` are authenticated domain inputs. Derive the scope from trusted,
canonical application context and keep both values reproducible for the lifetime of stored objects.
Do not change `policyRevision` merely because the active wrapping key rotates; use an explicit
read/migrate policy when changing the authenticated policy domain. The cipher adapter does not take
ownership of `CipherEngine`, so the application that created the engine must close it.

`AuthenticatedWorkspaceCipher` is a trusted composition contract for alternative implementations.
Implementations must remain bounded, authenticate both supplied contexts, honor cancellation, and not
retain borrowed plaintext or context buffers after a call settles. The built-in adapter supplies those
properties through `CipherEngine`; registered cipher algorithms and key providers remain part of the
application's crypto trust boundary.

The canonical logical path and record purpose are also bound automatically, so copying a raw backing
record to another path does not produce valid plaintext there. Protected `copyFile()` and `moveFile()`
therefore fail with `NOT_SUPPORTED`. An authorized application workflow must read/authenticate the
source and write a newly encrypted destination; a move may then conditionally delete the source, with
the same multi-object transactional caveats as any application-managed move.

The bridge deliberately does not hide all storage metadata. Object paths, directory shape, existence,
ciphertext length, provider ETag/timestamps, and access patterns remain visible to the backing store.
Path search is disabled unless `pathSearch: "provider-visible"` explicitly accepts that leakage.
Applications such as artifact catalogs should keep only deliberately searchable fields—safe IDs,
titles, descriptions, status, and other chosen projections—in their own authorized catalog and store
the sensitive artifact body through this protected workspace. The bridge does not encrypt arbitrary
database columns or decide which catalog fields are safe.

Protected list, stat, and enabled search operations authenticate file metadata before returning it.
Synthetic directories, provider-level existence, cursors, and access patterns remain storage signals,
and the file body is authenticated only by a protected read.

`protectedWorkspace.protection` exposes a frozen, non-secret integration descriptor containing the
outer format/version, `nmc1` envelope, path binding, metadata/body protection, path-search mode, and
policy revision. It describes the configured boundary; it does not reveal provider keys, storage
coordinates, plaintext, or ciphertext.

## Operations

Both `CipherService` and `CipherEngine` provide:

- `encryptText()` and `decryptText()` for UTF-8 strings;
- `encryptBytes()` and `decryptBytes()` for `Uint8Array` values;
- `encryptTextBatch()` and `decryptTextBatch()` for one-key text batches with per-item AAD;
- `encryptValue()` and `decryptValue()` through an explicit, typed `CipherCodec<Value>`;
- `reencrypt()` to authenticate and rewrite one envelope with the selected current provider/cipher;
- `inspect()` to parse visible envelope metadata.

Codecs make serialization an application-owned contract. `jsonCodec()` requires a validator for the
authenticated JSON value instead of trusting the parsed shape:

```ts
import { jsonCodec } from "@nestm/crypto/core";

interface Preferences {
	theme: "dark" | "light";
}

const preferencesCodec = jsonCodec<Preferences>((value) => {
	if (
		typeof value !== "object" ||
		value === null ||
		!("theme" in value) ||
		(value.theme !== "dark" && value.theme !== "light")
	) {
		throw new TypeError("Invalid preferences");
	}
	return { theme: value.theme };
});

const protectedPreferences = await cipher.encryptValue({ theme: "dark" }, preferencesCodec, {
	aad: "customer.preferences",
});
const preferences = await cipher.decryptValue(protectedPreferences, preferencesCodec, {
	aad: "customer.preferences",
});
```

The added core/service signatures are:

```ts
interface CipherCodec<Value> {
	encode(this: void, value: Value): Uint8Array;
	decode(this: void, plaintext: Uint8Array): Value;
}

interface BatchEncryptTextItem {
	readonly plaintext: string;
	readonly aad?: CipherAad;
}

interface BatchDecryptTextItem {
	readonly envelope: string;
	readonly aad?: CipherAad;
}

encryptTextBatch(
	items: readonly BatchEncryptTextItem[],
	options?: BatchEncryptOptions,
): Promise<readonly string[]>;

decryptTextBatch(
	items: readonly BatchDecryptTextItem[],
	options?: BatchDecryptOptions,
): Promise<readonly string[]>;

encryptValue<Value>(
	value: Value,
	codec: CipherCodec<Value>,
	options?: EncryptOptions,
): Promise<string>;

decryptValue<Value>(
	envelope: string,
	codec: CipherCodec<Value>,
	options?: DecryptOptions,
): Promise<Value>;
```

Operations accept `AbortSignal`. Encrypt can select a registered logical `provider` and `cipher`;
decrypt can restrict `allowedProviders`. The default maximum buffered plaintext/ciphertext size is
10 MiB and can be changed with `maxPayloadBytes` at engine/module registration. Batches default to at
most 256 items through `maxBatchItems`. Their aggregate plaintext/ciphertext limit is controlled by
`maxBatchBytes`, which defaults to `maxPayloadBytes`. Single-item APIs use the same batch engine, so a
lower `maxBatchBytes` also lowers their effective payload limit.

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
AES-256-GCM. The current version uses a fresh 32-byte data key for each single-item operation or batch.
Every envelope has a unique 12-byte nonce and 16-byte authentication tag.

The `nmc1` format constrains registered ciphers to a 12-byte nonce so batch encryption can reserve the
final four bytes for a collision-free operation counter. The cipher/provider contracts are extensible,
but an algorithm needing a different nonce construction requires a future envelope version.

`AesKeyRingProvider` derives a one-use AES-256-GCM wrapping key from the configured key, a fresh
256-bit random salt, and domain-separated HKDF-SHA256 info bound to the key reference and wrapping
context. The one-use key makes the format's fixed 96-bit GCM nonce safe without a durable invocation
counter. Wrappers are exactly 81 bytes (`version || salt || ciphertext || tag`), tagged version 2,
and report `NESTM-A256GCM-HKDF-SHA256-SALT256-V2`. Any other algorithm, size, or version is rejected;
development data written with another format must be reset.

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
objects. The base field service does not hook HTTP serialization or an ORM. Use the explicit adapters
below when those are the application's chosen enforcement boundaries.

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

Tenant text batches accept a purpose and optional AAD for every item. `protectTextBatch()` is the
idempotent write-boundary operation: it authenticates every existing `nmc*` value in the active tenant
context before encrypting any plaintext item.

```ts
const [taxId, email] = await tenantCipher.protectTextBatch([
	{ value: input.taxId, purpose: "customer.tax-id" },
	{ value: input.email, purpose: "customer.email" },
]);
```

```ts
interface TenantBatchOptions {
	readonly signal?: AbortSignal;
}

interface TenantBatchEncryptTextItem {
	readonly plaintext: string;
	readonly purpose: string;
	readonly aad?: CipherAad;
}

interface TenantBatchDecryptTextItem {
	readonly envelope: string;
	readonly purpose: string;
	readonly aad?: CipherAad;
}

interface TenantProtectTextItem {
	readonly value: string;
	readonly purpose: string;
	readonly aad?: CipherAad;
}

encryptTextBatch(
	items: readonly TenantBatchEncryptTextItem[],
	options?: TenantBatchOptions,
): Promise<readonly string[]>;

decryptTextBatch(
	items: readonly TenantBatchDecryptTextItem[],
	options?: TenantBatchOptions,
): Promise<readonly string[]>;

encryptValue<Value>(
	value: Value,
	codec: CipherCodec<Value>,
	options: TenantCipherOperationOptions,
): Promise<string>;

decryptValue<Value>(
	envelope: string,
	codec: CipherCodec<Value>,
	options: TenantCipherOperationOptions,
): Promise<Value>;

protectTextBatch(
	items: readonly TenantProtectTextItem[],
	options?: TenantBatchOptions,
): Promise<readonly string[]>;
```

## NestJS HTTP field adapter

`@nestm/crypto/http` supplies an explicit request pipe and opt-in response interceptor. Request
validation and transformation remain separate: the encryption pipe requires real DTO class instances,
so run a transforming `ValidationPipe` before it. Nested DTO properties still need
`@Type(() => NestedDto)` from `class-transformer`.

```ts
import { Body, Controller, Post, UseInterceptors, UsePipes, ValidationPipe } from "@nestjs/common";
import { Type } from "class-transformer";
import { EncryptedField } from "@nestm/crypto/fields";
import {
	DecryptTenantFieldsAs,
	TenantDecryptFieldsInterceptor,
	TenantEncryptFieldsPipe,
} from "@nestm/crypto/http";

class AddressDto {
	@EncryptedField("customer.address.line-1")
	line1!: string;
}

class CustomerDto {
	@EncryptedField("customer.tax-id")
	taxId!: string;

	@Type(() => AddressDto)
	address!: AddressDto;
}

@Controller("customers")
export class CustomersController {
	@Post()
	@UsePipes(new ValidationPipe({ transform: true }), TenantEncryptFieldsPipe)
	@UseInterceptors(TenantDecryptFieldsInterceptor)
	@DecryptTenantFieldsAs(() => CustomerDto)
	create(@Body() input: CustomerDto): Promise<CustomerDto> {
		return this.save(input);
	}

	private save(input: CustomerDto): Promise<CustomerDto> {
		return Promise.resolve(input);
	}
}
```

Register both adapter classes as providers where they are used. The interceptor does nothing unless
the handler has `@DecryptTenantFieldsAs()`. A decorated handler accepts an object, an array, or `null`,
maps objects to the declared DTO class, and then decrypts decorated fields. Decrypting into an HTTP
response is a data-exposure decision; apply the decorator only to routes whose authorization and DTO
shape intentionally expose those fields. The pipe ignores non-body parameters; an opted-in body with
missing DTO metadata or a value of the wrong class fails closed.

The public adapter signatures are:

```ts
class TenantEncryptFieldsPipe implements PipeTransform<unknown, Promise<unknown>> {
	constructor(fields: TenantFieldCipherService, options?: TenantEncryptFieldsPipeOptions);
	transform(value: unknown, metadata: ArgumentMetadata): Promise<unknown>;
}

function DecryptTenantFieldsAs<Value extends object>(
	type: () => Type<Value>,
	options?: TenantFieldDecryptOptions,
): MethodDecorator;

class TenantDecryptFieldsInterceptor implements NestInterceptor<unknown, unknown> {
	constructor(fields: TenantFieldCipherService, reflector: Reflector);
	intercept(context: ExecutionContext, next: CallHandler<unknown>): Observable<unknown>;
}
```

## Prisma write-encryption adapter

`@nestm/crypto/prisma` encrypts registered fields in Prisma-shaped write arguments without importing
or retaining a raw data-encryption key. It supports direct `create`, `update`, `upsert`, `createMany`,
`createManyAndReturn`, `updateMany`, and `updateManyAndReturn` data, plus configured nested
create/update/upsert/createMany/updateMany relations.

```ts
import { createTenantPrismaFieldEncryption } from "@nestm/crypto/prisma";

const prismaEncryption = createTenantPrismaFieldEncryption(tenantCipher, {
	registry: {
		Customer: {
			taxId: { purpose: "customer.tax-id" },
			billingEmail: { purpose: "customer.billing-email" },
		},
		Order: {
			internalNotes: { purpose: "order.internal-notes" },
		},
	},
	relations: {
		Account: { customers: "Customer", orders: "Order" },
	},
});

await prismaEncryption.encryptWriteArgs({
	model: "Customer",
	operation: "update",
	args,
});

// Or use this as an independent final guard immediately before query(args).
await prismaEncryption.assertWriteArgsEncrypted({
	model: "Customer",
	operation: "update",
	args,
});
```

Wire the processor into the application's Prisma `$extends` query hook for the seven exported
`TENANT_PRISMA_WRITE_OPERATIONS`, immediately before `query(args)`. Both methods mutate no structural
shape: encryption changes only registered string values (including `{ set: value }` operations), and
assertion changes nothing. Existing `nmc*` values are authenticated for the active tenant and purpose;
malformed, cross-tenant, or wrong-purpose values fail closed. Unsupported or ambiguous nested write
shapes also fail instead of being silently skipped. Reads remain an explicit application/HTTP
decryption concern. The adapter does not bind an envelope to a row ID, so a valid value can be replayed
between rows with the same purpose inside one tenant; use a service boundary with stable row-specific
AAD when that threat is in scope.

The processor contract is:

```ts
interface TenantPrismaWriteProcessor {
	encryptWriteArgs(input: TenantPrismaWriteInput): Promise<void>;
	assertWriteArgsEncrypted(input: TenantPrismaWriteInput): Promise<void>;
}

type TenantPrismaWriteOperation =
	| "create"
	| "update"
	| "upsert"
	| "createMany"
	| "createManyAndReturn"
	| "updateMany"
	| "updateManyAndReturn";

interface TenantPrismaWriteInput {
	readonly model: string;
	readonly operation: TenantPrismaWriteOperation;
	readonly args: unknown;
}

interface TenantPrismaFieldEncryptionOptions {
	readonly registry: TenantPrismaFieldRegistry;
	readonly relations?: TenantPrismaRelationMap;
	readonly maxDepth?: number;
}

function createTenantPrismaFieldEncryption(
	cipher: TenantCipherService,
	options: TenantPrismaFieldEncryptionOptions,
): TenantPrismaWriteProcessor;
```

## `nestjs-field-encryption` compatibility map

This package now covers the integration surfaces demonstrated by
[`RoyAbra27/nestjs-field-encryption`](https://github.com/RoyAbra27/nestjs-field-encryption), with
purpose-bound and tenant-bound contracts:

| Referenced package                            | `@nestm/crypto` equivalent                                 | Status and important difference                                      |
| --------------------------------------------- | ---------------------------------------------------------- | -------------------------------------------------------------------- |
| `@Encrypt()`                                  | `@EncryptedField(purpose)`                                 | Implemented; every field has authenticated domain separation         |
| `FieldEncryptor`                              | `FieldCipherService` / `TenantFieldCipherService`          | Implemented; explicit strict traversal and authenticated idempotency |
| `EncryptPipe`                                 | `TenantEncryptFieldsPipe` from `/http`                     | Implemented; requires an already transformed DTO instance            |
| `TransformResponseTo` + `DecryptInterceptor`  | `DecryptTenantFieldsAs` + `TenantDecryptFieldsInterceptor` | Implemented; handler-only opt-in response decryption                 |
| `createFieldEncryptionExtension`              | `createTenantPrismaFieldEncryption` from `/prisma`         | Implemented; purpose registry, no caller-supplied plaintext DEK      |
| `KmsKeyProvider` + tenant `EncryptedKeyStore` | named key providers + `TenantCryptoPolicy`                 | Implemented with local, AWS, GCP, Azure, and RSA wrapping providers  |
| one-operation field encryption                | text batches and `protectTextBatch`                        | Implemented; one tenant/profile resolution and one batch key         |
| application-specific serialization            | `CipherCodec<Value>` / validated `jsonCodec()`             | Implemented as an explicit typed boundary                            |

The ciphertext formats are intentionally not interoperable. The referenced package documents
AES-256-CBC ciphertext, while `@nestm/crypto` uses authenticated AES-256-GCM `nmc1` envelopes that bind
the header, wrapped key, tenant namespace/identity, purpose, and caller AAD. Migrating stored values
therefore requires decrypting them with the old library inside an audited migration and encrypting the
plaintext with `@nestm/crypto`; relabeling or importing the old ciphertext is not supported.

## Entry points

| Entry point                       | Purpose                                                                       |
| --------------------------------- | ----------------------------------------------------------------------------- |
| `@nestm/crypto/core`              | AES-256-GCM engine, envelope codec, local AES KEK ring, contracts, and errors |
| `@nestm/crypto/files`             | NMF1 bounded-memory streaming file encryption with detached wrapped keys      |
| `@nestm/crypto/storage-workspace` | strict authenticated body/metadata protection for `StorageWorkspace`          |
| `@nestm/crypto/fields`            | purpose-decorated class traversal                                             |
| `@nestm/crypto/tenant`            | tenant-bound cipher and field services                                        |
| `@nestm/crypto/http`              | request-encryption pipe and opt-in response-decryption interceptor            |
| `@nestm/crypto/prisma`            | schema-agnostic tenant Prisma write processor                                 |
| `@nestm/crypto/key-wrap/rsa`      | RSA-OAEP-SHA256 wrapping with named public/private keys                       |
| `@nestm/crypto/kms/aws`           | AWS KMS data-key generation and decrypt                                       |
| `@nestm/crypto/kms/gcp`           | Google Cloud KMS encrypt/decrypt with AAD and CRC32C validation               |
| `@nestm/crypto/kms/azure`         | Azure Key Vault/Managed HSM wrap/unwrap                                       |
| `@nestm/crypto/testing`           | dependency-free deterministic nonce source for tests                          |

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
A256KW is available for compatible Managed HSM keys. Key Vault's wrap operations cannot bind
additional authenticated data, so the Azure provider rejects a non-empty wrapping context with a
`CONFIGURATION` error — use it only without a key context, or choose a provider that can bind one
(AWS, GCP, RSA-OAEP, or the local key ring). Library-owned Azure credentials are sent only
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
