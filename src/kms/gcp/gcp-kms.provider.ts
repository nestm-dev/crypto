import { createSecretKey, randomBytes, type KeyObject } from "node:crypto";
import type { KeyManagementServiceClient } from "@google-cloud/kms";
import { authenticationFailed, CryptoError, providerCall } from "../../core/errors.js";
import type {
	DataKeyContext,
	DataKeyProvider,
	GeneratedDataKey,
	WrappedDataKey,
} from "../../core/types.js";

export const GCP_KMS = "GCP-KMS";

export type GcpKmsClientOptions = ConstructorParameters<typeof KeyManagementServiceClient>[0];

export interface GcpKmsProviderOptions {
	/** Full CryptoKey resource name, without a CryptoKeyVersion suffix. */
	readonly keyName: string;
	/** A caller-owned client. It is never closed by this provider. */
	readonly client?: KeyManagementServiceClient;
	/** Used only when the provider lazily creates and owns a client. */
	readonly clientOptions?: GcpKmsClientOptions;
}

type GcpSdk = typeof import("@google-cloud/kms");
let gcpSdkPromise: Promise<GcpSdk> | undefined;

function loadGcpSdk(): Promise<GcpSdk> {
	gcpSdkPromise ??= import("@google-cloud/kms");
	return gcpSdkPromise;
}

function isCryptoKeyName(value: string): boolean {
	return (
		value.length <= 2048 &&
		value.trim() === value &&
		!/[\p{Cc}\s]/u.test(value) &&
		/^projects\/[^/]+\/locations\/[^/]+\/keyRings\/[^/]+\/cryptoKeys\/[^/]+$/u.test(value)
	);
}

function validateKeyName(keyName: string): void {
	if (!isCryptoKeyName(keyName)) {
		throw new CryptoError("CONFIGURATION", "The Google Cloud KMS CryptoKey name is invalid.");
	}
}

function isVersionOf(keyName: string, returnedName: string): boolean {
	if (returnedName === keyName) return true;
	const prefix = `${keyName}/cryptoKeyVersions/`;
	const version = returnedName.slice(prefix.length);
	return (
		returnedName.startsWith(prefix) &&
		version.length > 0 &&
		version.length <= 128 &&
		!/[/\p{Cc}\s]/u.test(version)
	);
}

/** Calculates the Castagnoli CRC32C checksum used by Google Cloud KMS. */
export function calculateCrc32c(input: Uint8Array): number {
	let crc = 0xffff_ffff;
	for (const byte of input) {
		crc ^= byte;
		for (let bit = 0; bit < 8; bit += 1) {
			crc = (crc >>> 1) ^ (crc & 1 ? 0x82f6_3b78 : 0);
		}
	}
	return (crc ^ 0xffff_ffff) >>> 0;
}

function parseCrc32c(value: unknown): number | undefined {
	let candidate = value;
	if (typeof candidate === "object" && candidate !== null && "value" in candidate) {
		candidate = candidate.value;
	}
	if (typeof candidate === "number") {
		return Number.isInteger(candidate) && candidate >= 0 && candidate <= 0xffff_ffff
			? candidate
			: undefined;
	}
	if (typeof candidate === "bigint") {
		return candidate >= 0n && candidate <= 0xffff_ffffn ? Number(candidate) : undefined;
	}
	if (typeof candidate === "string" && /^\d{1,10}$/u.test(candidate)) {
		const parsed = Number(candidate);
		return parsed <= 0xffff_ffff ? parsed : undefined;
	}
	if (
		typeof candidate === "object" &&
		candidate !== null &&
		"low" in candidate &&
		"high" in candidate &&
		typeof candidate.low === "number" &&
		typeof candidate.high === "number" &&
		candidate.high === 0
	) {
		return candidate.low >>> 0;
	}
	return undefined;
}

function crcValue(input: Uint8Array): { readonly value: number } {
	return { value: calculateCrc32c(input) };
}

function invalidResponse(): CryptoError {
	return new CryptoError("KEY_PROVIDER", "Google Cloud KMS returned an invalid response.");
}

function isCiphertextFailure(error: unknown): boolean {
	if (typeof error !== "object" || error === null) return false;
	if ("code" in error && (error.code === 3 || error.code === "INVALID_ARGUMENT")) return true;
	return "status" in error && error.status === "INVALID_ARGUMENT";
}

function assertRequestSize(payload: Uint8Array, aad: Uint8Array): void {
	if (payload.byteLength + aad.byteLength > 65_536) {
		throw new CryptoError("LIMIT_EXCEEDED", "The Google Cloud KMS request is too large.");
	}
}

export class GcpKmsProvider implements DataKeyProvider {
	readonly #keyName: string;
	readonly #owned: boolean;
	readonly #clientOptions: GcpKmsClientOptions;
	#client: KeyManagementServiceClient | undefined;
	#clientPromise: Promise<KeyManagementServiceClient> | undefined;
	#closed = false;

	constructor(options: GcpKmsProviderOptions) {
		validateKeyName(options.keyName);
		if (options.client !== undefined && options.clientOptions !== undefined) {
			throw new CryptoError(
				"CONFIGURATION",
				"Provide either a Google Cloud KMS client or client options, not both.",
			);
		}
		this.#keyName = options.keyName;
		this.#owned = options.client === undefined;
		this.#client = options.client;
		this.#clientOptions = { ...options.clientOptions };
	}

	async generateDataKey(context: DataKeyContext): Promise<GeneratedDataKey> {
		assertRequestSize(new Uint8Array(32), context.wrappingContext);
		return providerCall(async () => {
			this.#assertOpen();
			const client = await this.#getClient();
			const raw = randomBytes(32);
			const plaintextKey = createSecretKey(raw);
			try {
				const [response] = await client.encrypt({
					name: this.#keyName,
					plaintext: raw,
					additionalAuthenticatedData: context.wrappingContext,
					plaintextCrc32c: crcValue(raw),
					additionalAuthenticatedDataCrc32c: crcValue(context.wrappingContext),
				});
				const ciphertext = response.ciphertext;
				const returnedName = response.name;
				if (
					!(ciphertext instanceof Uint8Array) ||
					ciphertext.byteLength === 0 ||
					ciphertext.byteLength > 65_536 ||
					typeof returnedName !== "string" ||
					!isVersionOf(this.#keyName, returnedName) ||
					response.verifiedPlaintextCrc32c !== true ||
					response.verifiedAdditionalAuthenticatedDataCrc32c !== true ||
					parseCrc32c(response.ciphertextCrc32c) !== calculateCrc32c(ciphertext)
				) {
					throw invalidResponse();
				}
				return Object.freeze({
					plaintextKey,
					wrappedKey: new Uint8Array(ciphertext),
					keyReference: this.#keyName,
					wrappingAlgorithm: GCP_KMS,
				});
			} finally {
				raw.fill(0);
			}
		}, context.signal);
	}

	async unwrapDataKey(dataKey: WrappedDataKey, context: DataKeyContext): Promise<KeyObject> {
		if (dataKey.wrappingAlgorithm !== GCP_KMS) {
			throw new CryptoError("INVALID_KEY", "The wrapped-key algorithm is unsupported.");
		}
		if (dataKey.keyReference !== this.#keyName) {
			throw new CryptoError("KEY_NOT_FOUND", "The Google Cloud KMS key was not found.");
		}
		if (dataKey.wrappedKey.byteLength === 0 || dataKey.wrappedKey.byteLength > 65_536) {
			throw new CryptoError("INVALID_KEY", "The wrapped data key is invalid.");
		}
		assertRequestSize(dataKey.wrappedKey, context.wrappingContext);

		return providerCall(async () => {
			this.#assertOpen();
			const client = await this.#getClient();
			const ciphertext = new Uint8Array(dataKey.wrappedKey);
			let response;
			try {
				[response] = await client.decrypt({
					name: this.#keyName,
					ciphertext,
					additionalAuthenticatedData: context.wrappingContext,
					ciphertextCrc32c: crcValue(ciphertext),
					additionalAuthenticatedDataCrc32c: crcValue(context.wrappingContext),
				});
			} catch (error: unknown) {
				if (isCiphertextFailure(error)) throw authenticationFailed({ cause: error });
				throw error;
			}
			const plaintext = response.plaintext;
			if (
				!(plaintext instanceof Uint8Array) ||
				plaintext.byteLength !== 32 ||
				parseCrc32c(response.plaintextCrc32c) !== calculateCrc32c(plaintext)
			) {
				if (plaintext instanceof Uint8Array) plaintext.fill(0);
				throw invalidResponse();
			}
			const raw = Buffer.from(plaintext);
			try {
				return createSecretKey(raw);
			} finally {
				raw.fill(0);
				plaintext.fill(0);
			}
		}, context.signal);
	}

	async close(): Promise<void> {
		if (this.#closed) return;
		this.#closed = true;
		if (!this.#owned) return;
		const client = this.#client ?? (await this.#clientPromise);
		if (client !== undefined) await client.close();
		this.#client = undefined;
	}

	async #getClient(): Promise<KeyManagementServiceClient> {
		this.#assertOpen();
		if (this.#client !== undefined) return this.#client;
		this.#clientPromise ??= loadGcpSdk().then(({ KeyManagementServiceClient: Client }) => {
			const client = new Client(this.#clientOptions);
			this.#client = client;
			return client;
		});
		return this.#clientPromise;
	}

	#assertOpen(): void {
		if (this.#closed) {
			throw new CryptoError("KEY_PROVIDER", "The Google Cloud KMS provider is closed.");
		}
	}
}
