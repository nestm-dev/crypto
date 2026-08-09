import { createHash, createSecretKey, type KeyObject } from "node:crypto";
import type { KMSClient, KMSClientConfig } from "@aws-sdk/client-kms";
import { authenticationFailed, CryptoError, providerCall } from "../../core/errors.js";
import type {
	DataKeyContext,
	DataKeyProvider,
	GeneratedDataKey,
	WrappedDataKey,
} from "../../core/types.js";

export const AWS_KMS = "AWS-KMS";
export const AWS_WRAPPING_CONTEXT_KEY = "nestm:wrapping-context-sha256";

export interface AwsKmsProviderOptions {
	/** A stable key ID or key ARN. Aliases are rejected because they can retarget silently. */
	readonly keyId: string;
	/** A caller-owned client. It is never destroyed by this provider. */
	readonly client?: KMSClient;
	/** Used only when the provider lazily creates and owns a client. */
	readonly clientConfig?: KMSClientConfig;
	/** Non-secret values recorded by AWS in CloudTrail. */
	readonly encryptionContext?: Readonly<Record<string, string>>;
}

type AwsSdk = typeof import("@aws-sdk/client-kms");
let awsSdkPromise: Promise<AwsSdk> | undefined;

function loadAwsSdk(): Promise<AwsSdk> {
	awsSdkPromise ??= import("@aws-sdk/client-kms");
	return awsSdkPromise;
}

function isSafeIdentifier(value: string, maxLength = 2048): boolean {
	return (
		value.length > 0 &&
		value.length <= maxLength &&
		value.trim() === value &&
		!/\p{Cc}/u.test(value)
	);
}

function validateConfiguredKeyId(keyId: string): void {
	if (
		!isSafeIdentifier(keyId) ||
		keyId.startsWith("alias/") ||
		/^arn:[^:]+:kms:[^:]+:[^:]+:alias\//u.test(keyId)
	) {
		throw new CryptoError(
			"CONFIGURATION",
			"AWS KMS requires a stable key ID or key ARN; aliases are not supported.",
		);
	}
}

function keyReferenceMatches(configuredKeyId: string, returnedKeyId: string): boolean {
	if (configuredKeyId === returnedKeyId) return true;
	if (configuredKeyId.startsWith("arn:")) return false;
	return returnedKeyId.endsWith(`:key/${configuredKeyId}`);
}

function normalizeEncryptionContext(
	input: Readonly<Record<string, string>> | undefined,
): Readonly<Record<string, string>> {
	const result: Record<string, string> = {};
	let encodedLength = 0;
	for (const [key, value] of Object.entries(input ?? {})) {
		if (
			!isSafeIdentifier(key, 256) ||
			typeof value !== "string" ||
			value.length > 4096 ||
			/\p{Cc}/u.test(value)
		) {
			throw new CryptoError("CONFIGURATION", "The AWS KMS encryption context is invalid.");
		}
		if (key === AWS_WRAPPING_CONTEXT_KEY) {
			throw new CryptoError("CONFIGURATION", "The AWS KMS encryption context uses a reserved key.");
		}
		encodedLength += Buffer.byteLength(key) + Buffer.byteLength(value);
		if (encodedLength > 8192) {
			throw new CryptoError("CONFIGURATION", "The AWS KMS encryption context is too large.");
		}
		result[key] = value;
	}
	return Object.freeze(result);
}

function operationContext(
	staticContext: Readonly<Record<string, string>>,
	wrappingContext: Uint8Array,
): Record<string, string> {
	return {
		...staticContext,
		[AWS_WRAPPING_CONTEXT_KEY]: createHash("sha256").update(wrappingContext).digest("base64url"),
	};
}

function invalidResponse(): CryptoError {
	return new CryptoError("KEY_PROVIDER", "AWS KMS returned an invalid response.");
}

function isCiphertextFailure(error: unknown): boolean {
	return (
		error instanceof Error &&
		(error.name === "InvalidCiphertextException" || error.name === "IncorrectKeyException")
	);
}

export class AwsKmsProvider implements DataKeyProvider {
	readonly #keyId: string;
	readonly #encryptionContext: Readonly<Record<string, string>>;
	readonly #owned: boolean;
	readonly #clientConfig: KMSClientConfig;
	#client: KMSClient | undefined;
	#clientPromise: Promise<KMSClient> | undefined;
	#closed = false;

	constructor(options: AwsKmsProviderOptions) {
		validateConfiguredKeyId(options.keyId);
		if (options.client !== undefined && options.clientConfig !== undefined) {
			throw new CryptoError(
				"CONFIGURATION",
				"Provide either an AWS KMS client or client configuration, not both.",
			);
		}
		this.#keyId = options.keyId;
		this.#encryptionContext = normalizeEncryptionContext(options.encryptionContext);
		this.#owned = options.client === undefined;
		this.#client = options.client;
		this.#clientConfig = { ...options.clientConfig };
	}

	async generateDataKey(context: DataKeyContext): Promise<GeneratedDataKey> {
		return providerCall(async () => {
			this.#assertOpen();
			const [{ GenerateDataKeyCommand }, client] = await Promise.all([
				loadAwsSdk(),
				this.#getClient(),
			]);
			const command = new GenerateDataKeyCommand({
				KeyId: this.#keyId,
				KeySpec: "AES_256",
				EncryptionContext: operationContext(this.#encryptionContext, context.wrappingContext),
			});
			const response = await client.send(
				command,
				context.signal === undefined ? {} : { abortSignal: context.signal },
			);
			const plaintext = response.Plaintext;
			const ciphertext = response.CiphertextBlob;
			const returnedKeyId = response.KeyId;
			if (
				plaintext === undefined ||
				plaintext.byteLength !== 32 ||
				ciphertext === undefined ||
				ciphertext.byteLength === 0 ||
				ciphertext.byteLength > 65_536 ||
				returnedKeyId === undefined ||
				!isSafeIdentifier(returnedKeyId) ||
				!keyReferenceMatches(this.#keyId, returnedKeyId)
			) {
				plaintext?.fill(0);
				throw invalidResponse();
			}

			const raw = Buffer.from(plaintext);
			try {
				return Object.freeze({
					plaintextKey: createSecretKey(raw),
					wrappedKey: new Uint8Array(ciphertext),
					keyReference: this.#keyId,
					wrappingAlgorithm: AWS_KMS,
				});
			} finally {
				raw.fill(0);
				plaintext.fill(0);
			}
		}, context.signal);
	}

	async unwrapDataKey(dataKey: WrappedDataKey, context: DataKeyContext): Promise<KeyObject> {
		if (dataKey.wrappingAlgorithm !== AWS_KMS) {
			throw new CryptoError("INVALID_KEY", "The wrapped-key algorithm is unsupported.");
		}
		if (!isSafeIdentifier(dataKey.keyReference) || dataKey.keyReference !== this.#keyId) {
			throw new CryptoError("KEY_NOT_FOUND", "The AWS KMS key was not found.");
		}
		if (dataKey.wrappedKey.byteLength === 0 || dataKey.wrappedKey.byteLength > 65_536) {
			throw new CryptoError("INVALID_KEY", "The wrapped data key is invalid.");
		}

		return providerCall(async () => {
			this.#assertOpen();
			const [{ DecryptCommand }, client] = await Promise.all([loadAwsSdk(), this.#getClient()]);
			const command = new DecryptCommand({
				CiphertextBlob: new Uint8Array(dataKey.wrappedKey),
				KeyId: this.#keyId,
				EncryptionAlgorithm: "SYMMETRIC_DEFAULT",
				EncryptionContext: operationContext(this.#encryptionContext, context.wrappingContext),
			});
			let response;
			try {
				response = await client.send(
					command,
					context.signal === undefined ? {} : { abortSignal: context.signal },
				);
			} catch (error: unknown) {
				if (isCiphertextFailure(error)) throw authenticationFailed({ cause: error });
				throw error;
			}
			const plaintext = response.Plaintext;
			if (
				plaintext === undefined ||
				plaintext.byteLength !== 32 ||
				typeof response.KeyId !== "string" ||
				!keyReferenceMatches(this.#keyId, response.KeyId) ||
				response.EncryptionAlgorithm !== "SYMMETRIC_DEFAULT"
			) {
				plaintext?.fill(0);
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
		client?.destroy();
		this.#client = undefined;
	}

	async #getClient(): Promise<KMSClient> {
		this.#assertOpen();
		if (this.#client !== undefined) return this.#client;
		this.#clientPromise ??= loadAwsSdk().then(({ KMSClient: Client }) => {
			const client = new Client(this.#clientConfig);
			this.#client = client;
			return client;
		});
		return this.#clientPromise;
	}

	#assertOpen(): void {
		if (this.#closed) {
			throw new CryptoError("KEY_PROVIDER", "The AWS KMS provider is closed.");
		}
	}
}
