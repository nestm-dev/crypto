import { createHash } from "node:crypto";
import { Inject, Injectable } from "@nestjs/common";
import {
	TENANT_CONTEXT_READER,
	type TenantContextReader,
	type TenantTarget,
} from "@nestm/tenant/context";
import { CipherService } from "../cipher.service.js";
import {
	aadBytes,
	authenticationFailed,
	CryptoError,
	decodeUtf8,
	frame,
	isCryptoError,
	utf8,
	type CipherEnvelopeInfo,
} from "../core/index.js";
import { TENANT_CRYPTO_OPTIONS, TENANT_CRYPTO_POLICY } from "./tenant-crypto.tokens.js";
import type {
	TenantCipherOperationOptions,
	TenantCryptoModuleOptions,
	TenantCryptoPolicy,
	TenantCryptoProfile,
} from "./tenant-crypto.types.js";

const TENANT_DOMAIN = utf8("@nestm/crypto/tenant");
const TENANT_VERSION = utf8("1");

async function raceAbort<Result>(
	operation: () => Result | Promise<Result>,
	signal?: AbortSignal,
): Promise<Result> {
	if (signal?.aborted) {
		throw new CryptoError("ABORTED", "The cryptographic operation was aborted.");
	}
	const pending = Promise.resolve().then(operation);
	if (signal === undefined) return await pending;
	return await new Promise<Result>((resolve, reject) => {
		let settled = false;
		const finish = (callback: () => void): void => {
			if (settled) return;
			settled = true;
			signal.removeEventListener("abort", onAbort);
			callback();
		};
		const onAbort = (): void => {
			finish(() => reject(new CryptoError("ABORTED", "The cryptographic operation was aborted.")));
		};
		signal.addEventListener("abort", onAbort, { once: true });
		if (signal.aborted) onAbort();
		void pending.then(
			(value) => finish(() => resolve(value)),
			(error: unknown) => finish(() => reject(error)),
		);
	});
}

export async function normalizeTenantAuthentication<Result>(
	operation: () => Promise<Result>,
): Promise<Result> {
	try {
		return await operation();
	} catch (error: unknown) {
		if (isCryptoError(error, "AUTHENTICATION_FAILED")) throw authenticationFailed();
		throw error;
	}
}

/** @internal Operation-scoped data shared only by the tenant integration services. */
export interface ResolvedTenantCryptoContext {
	readonly target: TenantTarget;
	readonly writeProvider: string;
	readonly readProviders: readonly string[];
	readonly tenantScope: Uint8Array;
	readonly keyContext: Uint8Array;
}

function assertPurpose(purpose: string): void {
	if (
		typeof purpose !== "string" ||
		purpose.length === 0 ||
		Buffer.byteLength(purpose, "utf8") > 255 ||
		purpose.trim() !== purpose ||
		/\p{Cc}/u.test(purpose)
	) {
		throw new CryptoError(
			"INVALID_ARGUMENT",
			"A printable tenant crypto purpose of at most 255 UTF-8 bytes is required.",
		);
	}
}

function assertNamespace(namespace: string): void {
	if (
		typeof namespace !== "string" ||
		namespace.length === 0 ||
		Buffer.byteLength(namespace, "utf8") > 255 ||
		namespace.trim() !== namespace ||
		/\p{Cc}/u.test(namespace)
	) {
		throw new CryptoError(
			"CONFIGURATION",
			"A printable tenant crypto namespace of at most 255 UTF-8 bytes is required.",
		);
	}
}

function captureOperationOptions(
	options: TenantCipherOperationOptions,
): TenantCipherOperationOptions & { readonly aad: Uint8Array } {
	let aad: Uint8Array | undefined;
	try {
		if (typeof options !== "object" || options === null) {
			throw new TypeError("Missing tenant crypto options.");
		}
		const purpose = options.purpose;
		aad = aadBytes(options.aad);
		const signal = options.signal;
		if (signal !== undefined && !(signal instanceof AbortSignal)) {
			throw new TypeError("Invalid abort signal.");
		}
		assertPurpose(purpose);
		return Object.freeze({
			purpose,
			aad,
			...(signal === undefined ? {} : { signal }),
		});
	} catch (error: unknown) {
		aad?.fill(0);
		throw new CryptoError("INVALID_ARGUMENT", "Tenant crypto operation options are invalid.", {
			cause: error,
		});
	}
}

/** @internal Not exported from the package tenant entry point. */
@Injectable()
export class TenantCryptoScopeService {
	readonly #context: TenantContextReader;
	readonly #cipher: CipherService;
	readonly #policy: TenantCryptoPolicy | null;
	readonly #namespace: string;

	constructor(
		@Inject(TENANT_CONTEXT_READER) context: TenantContextReader,
		cipher: CipherService,
		@Inject(TENANT_CRYPTO_POLICY) policy: TenantCryptoPolicy | null,
		@Inject(TENANT_CRYPTO_OPTIONS) options: TenantCryptoModuleOptions,
	) {
		assertNamespace(options.namespace);
		this.#context = context;
		this.#cipher = cipher;
		this.#policy = policy;
		this.#namespace = options.namespace;
	}

	async resolve(signal?: AbortSignal): Promise<ResolvedTenantCryptoContext> {
		if (signal !== undefined && !(signal instanceof AbortSignal)) {
			throw new CryptoError("INVALID_ARGUMENT", "The tenant abort signal is invalid.");
		}
		const target = this.#requireTarget();
		if (signal?.aborted) {
			throw new CryptoError("ABORTED", "The cryptographic operation was aborted.");
		}
		let unresolvedProfile: TenantCryptoProfile;
		const policy = this.#policy;
		try {
			unresolvedProfile = policy
				? await raceAbort(
						() => policy.resolve({ tenant: target.tenant, authority: target.authority }),
						signal,
					)
				: { writeProvider: this.#cipher.defaultProvider };
		} catch (error: unknown) {
			if (isCryptoError(error, "ABORTED")) {
				throw new CryptoError("ABORTED", "The cryptographic operation was aborted.", {
					cause: error,
				});
			}
			throw new CryptoError("TENANT_POLICY", "The tenant crypto policy failed.", {
				cause: error,
			});
		}
		let writeProvider: string;
		let readProviders: readonly string[];
		try {
			if (
				typeof unresolvedProfile !== "object" ||
				unresolvedProfile === null ||
				Array.isArray(unresolvedProfile)
			) {
				throw new TypeError("Invalid tenant route.");
			}
			const unresolvedReads = unresolvedProfile.readProviders;
			if (unresolvedReads !== undefined && !Array.isArray(unresolvedReads)) {
				throw new TypeError("Invalid tenant read route.");
			}
			writeProvider = this.#validateProvider(unresolvedProfile.writeProvider);
			readProviders = Object.freeze([
				...new Set(
					[writeProvider, ...(unresolvedReads === undefined ? [] : [...unresolvedReads])].map(
						(name) => this.#validateProvider(name),
					),
				),
			]);
		} catch (error: unknown) {
			throw new CryptoError(
				"TENANT_POLICY",
				"The tenant crypto policy returned an invalid route.",
				{
					cause: error,
				},
			);
		}
		const tenantScope = frame(
			TENANT_DOMAIN,
			TENANT_VERSION,
			utf8(this.#namespace),
			utf8(target.tenant.id),
		);
		const keyContext = new Uint8Array(createHash("sha256").update(tenantScope).digest());
		const resolved = Object.freeze({
			target,
			writeProvider,
			readProviders,
			tenantScope,
			keyContext,
		});
		this.assertActive(resolved);
		return resolved;
	}

	assertActive(context: ResolvedTenantCryptoContext): void {
		const active = this.#requireTarget();
		if (
			active.authority !== context.target.authority ||
			active.tenant.id !== context.target.tenant.id
		) {
			throw authenticationFailed();
		}
	}

	payloadAad(
		context: ResolvedTenantCryptoContext,
		options: TenantCipherOperationOptions,
	): Uint8Array {
		return frame(context.tenantScope, utf8(options.purpose), aadBytes(options.aad));
	}

	#requireTarget(): TenantTarget {
		try {
			return this.#context.requireTenantTarget();
		} catch (error: unknown) {
			throw new CryptoError("TENANT_POLICY", "A tenant crypto target is unavailable.", {
				cause: error,
			});
		}
	}

	#validateProvider(name: string): string {
		if (
			typeof name !== "string" ||
			name.length === 0 ||
			name.trim() !== name ||
			/\p{Cc}/u.test(name) ||
			!this.#cipher.hasProvider(name)
		) {
			throw new CryptoError("TENANT_POLICY", "The tenant crypto policy returned an invalid route.");
		}
		return name;
	}
}

@Injectable()
export class TenantCipherService {
	readonly #cipher: CipherService;
	readonly #scope: TenantCryptoScopeService;

	constructor(cipher: CipherService, scope: TenantCryptoScopeService) {
		this.#cipher = cipher;
		this.#scope = scope;
	}

	async encryptBytes(
		plaintext: Uint8Array,
		options: TenantCipherOperationOptions,
	): Promise<string> {
		if (!(plaintext instanceof Uint8Array)) {
			throw new CryptoError("INVALID_ARGUMENT", "Plaintext bytes are required.");
		}
		const captured = captureOperationOptions(options);
		const capturedPlaintext = new Uint8Array(plaintext);
		try {
			const context = await this.#scope.resolve(captured.signal);
			this.#scope.assertActive(context);
			const envelope = await this.#cipher.encryptBytes(capturedPlaintext, {
				aad: this.#scope.payloadAad(context, captured),
				keyContext: context.keyContext,
				provider: context.writeProvider,
				...(captured.signal === undefined ? {} : { signal: captured.signal }),
			});
			this.#scope.assertActive(context);
			return envelope;
		} finally {
			capturedPlaintext.fill(0);
			captured.aad.fill(0);
		}
	}

	async encryptText(plaintext: string, options: TenantCipherOperationOptions): Promise<string> {
		if (typeof plaintext !== "string") {
			throw new CryptoError("INVALID_ARGUMENT", "Plaintext text is required.");
		}
		const captured = captureOperationOptions(options);
		try {
			const context = await this.#scope.resolve(captured.signal);
			this.#scope.assertActive(context);
			const envelope = await this.#cipher.encryptText(plaintext, {
				aad: this.#scope.payloadAad(context, captured),
				keyContext: context.keyContext,
				provider: context.writeProvider,
				...(captured.signal === undefined ? {} : { signal: captured.signal }),
			});
			this.#scope.assertActive(context);
			return envelope;
		} finally {
			captured.aad.fill(0);
		}
	}

	async decryptBytes(envelope: string, options: TenantCipherOperationOptions): Promise<Uint8Array> {
		const captured = captureOperationOptions(options);
		try {
			const context = await this.#scope.resolve(captured.signal);
			this.#scope.assertActive(context);
			this.#assertAllowedEnvelope(envelope, context);
			const plaintext = await normalizeTenantAuthentication(() =>
				this.#cipher.decryptBytes(envelope, {
					aad: this.#scope.payloadAad(context, captured),
					keyContext: context.keyContext,
					allowedProviders: context.readProviders,
					...(captured.signal === undefined ? {} : { signal: captured.signal }),
				}),
			);
			try {
				this.#scope.assertActive(context);
				return plaintext;
			} catch (error: unknown) {
				plaintext.fill(0);
				throw error;
			}
		} finally {
			captured.aad.fill(0);
		}
	}

	async decryptText(envelope: string, options: TenantCipherOperationOptions): Promise<string> {
		const captured = captureOperationOptions(options);
		try {
			const context = await this.#scope.resolve(captured.signal);
			this.#scope.assertActive(context);
			this.#assertAllowedEnvelope(envelope, context);
			const plaintext = await normalizeTenantAuthentication(() =>
				this.#cipher.decryptBytes(envelope, {
					aad: this.#scope.payloadAad(context, captured),
					keyContext: context.keyContext,
					allowedProviders: context.readProviders,
					...(captured.signal === undefined ? {} : { signal: captured.signal }),
				}),
			);
			try {
				this.#scope.assertActive(context);
				return decodeUtf8(plaintext);
			} finally {
				plaintext.fill(0);
			}
		} finally {
			captured.aad.fill(0);
		}
	}

	async reencrypt(envelope: string, options: TenantCipherOperationOptions): Promise<string> {
		const captured = captureOperationOptions(options);
		try {
			const context = await this.#scope.resolve(captured.signal);
			this.#scope.assertActive(context);
			this.#assertAllowedEnvelope(envelope, context);
			const reencrypted = await normalizeTenantAuthentication(() =>
				this.#cipher.reencrypt(envelope, {
					aad: this.#scope.payloadAad(context, captured),
					keyContext: context.keyContext,
					allowedProviders: context.readProviders,
					provider: context.writeProvider,
					...(captured.signal === undefined ? {} : { signal: captured.signal }),
				}),
			);
			this.#scope.assertActive(context);
			return reencrypted;
		} finally {
			captured.aad.fill(0);
		}
	}

	inspect(envelope: string): CipherEnvelopeInfo {
		return this.#cipher.inspect(envelope);
	}

	#assertAllowedEnvelope(envelope: string, context: ResolvedTenantCryptoContext): void {
		const info = this.#cipher.inspect(envelope);
		if (!context.readProviders.includes(info.provider)) throw authenticationFailed();
	}
}
