import { createSecretKey, randomBytes, type KeyObject } from "node:crypto";
import type { TokenCredential } from "@azure/core-auth";
import type { CryptographyClient, CryptographyClientOptions } from "@azure/keyvault-keys";
import { authenticationFailed, CryptoError, providerCall } from "../../core/errors.js";
import type {
	DataKeyContext,
	DataKeyProvider,
	GeneratedDataKey,
	WrappedDataKey,
} from "../../core/types.js";

export const AZURE_RSA_OAEP_256 = "RSA-OAEP-256";
export const AZURE_A256KW = "A256KW";

export type AzureKeyWrapAlgorithm = typeof AZURE_RSA_OAEP_256 | typeof AZURE_A256KW;

export interface AzureKeyVaultProviderOptions {
	/** A canonical, version-specific Key Vault or Managed HSM key URL. */
	readonly keyId: string;
	readonly algorithm?: AzureKeyWrapAlgorithm;
	/** A caller-owned client. It is never closed by this provider. */
	readonly client?: CryptographyClient;
	/** Required when the provider should construct its own CryptographyClient. */
	readonly credential?: TokenCredential;
	readonly clientOptions?: CryptographyClientOptions;
	/** Additional exact hosts trusted to receive a library-owned credential. */
	readonly trustedHosts?: readonly string[];
}

type AzureSdk = typeof import("@azure/keyvault-keys");
let azureSdkPromise: Promise<AzureSdk> | undefined;

function loadAzureSdk(): Promise<AzureSdk> {
	azureSdkPromise ??= import("@azure/keyvault-keys");
	return azureSdkPromise;
}

function isCanonicalVersionedKeyId(keyId: string): boolean {
	if (
		keyId.length === 0 ||
		keyId.length > 2048 ||
		keyId.trim() !== keyId ||
		/[\p{Cc}\s]/u.test(keyId)
	) {
		return false;
	}
	try {
		const parsed = new URL(keyId);
		const parts = parsed.pathname.split("/").filter(Boolean);
		return (
			parsed.protocol === "https:" &&
			parsed.username === "" &&
			parsed.password === "" &&
			parsed.search === "" &&
			parsed.hash === "" &&
			parsed.toString() === keyId &&
			parts.length === 3 &&
			parts[0] === "keys" &&
			parts[1]!.length > 0 &&
			parts[2]!.length > 0
		);
	} catch {
		return false;
	}
}

const AZURE_KEY_HOST_SUFFIXES = [
	".vault.azure.net",
	".managedhsm.azure.net",
	".vault.azure.cn",
	".managedhsm.azure.cn",
	".vault.usgovcloudapi.net",
	".managedhsm.usgovcloudapi.net",
	".vault.microsoftazure.de",
	".managedhsm.microsoftazure.de",
] as const;

function trustedHosts(input: readonly string[] | undefined): ReadonlySet<string> {
	if (input === undefined) return new Set();
	if (!Array.isArray(input)) {
		throw new CryptoError("CONFIGURATION", "The Azure trusted-host allowlist is invalid.");
	}
	const result = new Set<string>();
	for (const host of input) {
		if (
			typeof host !== "string" ||
			host.length === 0 ||
			host.length > 253 ||
			host !== host.toLowerCase() ||
			!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/u.test(host)
		) {
			throw new CryptoError("CONFIGURATION", "The Azure trusted-host allowlist is invalid.");
		}
		result.add(host);
	}
	return result;
}

function isTrustedCredentialHost(keyId: string, additionalHosts: ReadonlySet<string>): boolean {
	const host = new URL(keyId).hostname;
	return (
		additionalHosts.has(host) ||
		AZURE_KEY_HOST_SUFFIXES.some((suffix) => host.length > suffix.length && host.endsWith(suffix))
	);
}

function invalidResponse(): CryptoError {
	return new CryptoError("KEY_PROVIDER", "Azure Key Vault returned an invalid response.");
}

// Key Vault wrapKey/unwrapKey (RSA-OAEP-256, A256KW) accept no AAD or OAEP label, so a
// wrapping context can never be authenticated by the vault. Accepting one silently would
// produce keys that unwrap under any context; refuse it instead.
function assertEmptyWrappingContext(context: DataKeyContext): void {
	if (context.wrappingContext.byteLength !== 0) {
		throw new CryptoError(
			"CONFIGURATION",
			"Azure Key Vault cannot bind a wrapping context; it must be empty.",
		);
	}
}

function isCiphertextFailure(error: unknown): boolean {
	if (typeof error !== "object" || error === null) return false;
	if ("statusCode" in error && error.statusCode === 400) return true;
	return "code" in error && error.code === "BadParameter";
}

export class AzureKeyVaultProvider implements DataKeyProvider {
	readonly #keyId: string;
	readonly #algorithm: AzureKeyWrapAlgorithm;
	readonly #owned: boolean;
	readonly #credential: TokenCredential | undefined;
	readonly #clientOptions: CryptographyClientOptions | undefined;
	#client: CryptographyClient | undefined;
	#clientPromise: Promise<CryptographyClient> | undefined;
	#closed = false;

	constructor(options: AzureKeyVaultProviderOptions) {
		if (!isCanonicalVersionedKeyId(options.keyId)) {
			throw new CryptoError(
				"CONFIGURATION",
				"Azure Key Vault requires a canonical, version-specific HTTPS key URL.",
			);
		}
		const additionalHosts = trustedHosts(options.trustedHosts);
		if (options.client !== undefined) {
			if (options.credential !== undefined || options.clientOptions !== undefined) {
				throw new CryptoError(
					"CONFIGURATION",
					"Provide either an Azure cryptography client or client construction options, not both.",
				);
			}
			if (options.client.keyID !== options.keyId) {
				throw new CryptoError(
					"CONFIGURATION",
					"The Azure cryptography client is bound to a different key.",
				);
			}
		} else if (options.credential === undefined) {
			throw new CryptoError(
				"CONFIGURATION",
				"An Azure credential is required when no cryptography client is provided.",
			);
		} else if (!isTrustedCredentialHost(options.keyId, additionalHosts)) {
			throw new CryptoError(
				"CONFIGURATION",
				"The Azure key host is not trusted to receive the configured credential.",
			);
		}
		const algorithm = options.algorithm ?? AZURE_RSA_OAEP_256;
		if (algorithm !== AZURE_RSA_OAEP_256 && algorithm !== AZURE_A256KW) {
			throw new CryptoError("CONFIGURATION", "The Azure key-wrapping algorithm is unsupported.");
		}

		this.#keyId = options.keyId;
		this.#algorithm = algorithm;
		this.#owned = options.client === undefined;
		this.#client = options.client;
		this.#credential = options.credential;
		this.#clientOptions = options.clientOptions;
	}

	async generateDataKey(context: DataKeyContext): Promise<GeneratedDataKey> {
		assertEmptyWrappingContext(context);
		return providerCall(async () => {
			this.#assertOpen();
			const client = await this.#getClient();
			const raw = randomBytes(32);
			const plaintextKey = createSecretKey(raw);
			try {
				const response = await client.wrapKey(
					this.#algorithm,
					raw,
					context.signal === undefined ? {} : { abortSignal: context.signal },
				);
				if (
					!(response.result instanceof Uint8Array) ||
					response.result.byteLength === 0 ||
					response.result.byteLength > 65_536 ||
					response.keyID !== this.#keyId ||
					response.algorithm !== this.#algorithm
				) {
					throw invalidResponse();
				}
				return Object.freeze({
					plaintextKey,
					wrappedKey: new Uint8Array(response.result),
					keyReference: response.keyID,
					wrappingAlgorithm: response.algorithm,
				});
			} finally {
				raw.fill(0);
			}
		}, context.signal);
	}

	async unwrapDataKey(dataKey: WrappedDataKey, context: DataKeyContext): Promise<KeyObject> {
		assertEmptyWrappingContext(context);
		if (dataKey.wrappingAlgorithm !== this.#algorithm) {
			throw new CryptoError("INVALID_KEY", "The wrapped-key algorithm is unsupported.");
		}
		if (dataKey.keyReference !== this.#keyId) {
			throw new CryptoError("KEY_NOT_FOUND", "The Azure Key Vault key was not found.");
		}
		if (dataKey.wrappedKey.byteLength === 0 || dataKey.wrappedKey.byteLength > 65_536) {
			throw new CryptoError("INVALID_KEY", "The wrapped data key is invalid.");
		}

		return providerCall(async () => {
			this.#assertOpen();
			const client = await this.#getClient();
			let response;
			try {
				response = await client.unwrapKey(
					this.#algorithm,
					new Uint8Array(dataKey.wrappedKey),
					context.signal === undefined ? {} : { abortSignal: context.signal },
				);
			} catch (error: unknown) {
				if (isCiphertextFailure(error)) throw authenticationFailed({ cause: error });
				throw error;
			}
			if (
				!(response.result instanceof Uint8Array) ||
				response.result.byteLength !== 32 ||
				response.keyID !== this.#keyId ||
				response.algorithm !== this.#algorithm
			) {
				if (response.result instanceof Uint8Array) response.result.fill(0);
				throw invalidResponse();
			}
			const raw = Buffer.from(response.result);
			try {
				return createSecretKey(raw);
			} finally {
				raw.fill(0);
				response.result.fill(0);
			}
		}, context.signal);
	}

	async close(): Promise<void> {
		if (this.#closed) return;
		this.#closed = true;
		// CryptographyClient does not expose a close method. Caller-owned clients are
		// deliberately untouched; owned clients become unreachable with the provider.
		if (this.#owned) this.#client = undefined;
	}

	async #getClient(): Promise<CryptographyClient> {
		this.#assertOpen();
		if (this.#client !== undefined) return this.#client;
		this.#clientPromise ??= loadAzureSdk().then(({ CryptographyClient: Client }) => {
			const client = new Client(this.#keyId, this.#credential!, this.#clientOptions);
			if (client.keyID !== this.#keyId) throw invalidResponse();
			this.#client = client;
			return client;
		});
		return this.#clientPromise;
	}

	#assertOpen(): void {
		if (this.#closed) {
			throw new CryptoError("KEY_PROVIDER", "The Azure Key Vault provider is closed.");
		}
	}
}
