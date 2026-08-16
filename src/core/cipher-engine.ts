import { KeyObject, randomBytes } from "node:crypto";
import { Aes256GcmCipher, AES_256_GCM } from "./aes-256-gcm.js";
import {
	captureCipherCodec,
	decodeCipherValue,
	encodeCipherValue,
	type CipherCodec,
} from "./cipher-codec.js";
import { aadBytes, frame, isStableBytes, utf8, decodeUtf8 } from "./encoding.js";
import {
	encodeProtectedHeader,
	envelopeInfo,
	ENVELOPE_PREFIX,
	parseEnvelope,
	serializeEnvelope,
} from "./envelope.js";
import { authenticationFailed, CryptoError, providerCall, throwIfAborted } from "./errors.js";
import type {
	BatchDecryptItem,
	BatchDecryptOptions,
	BatchDecryptTextItem,
	BatchEncryptItem,
	BatchEncryptOptions,
	BatchEncryptTextItem,
	CipherAlgorithm,
	CipherEngineOptions,
	CipherEnvelopeInfo,
	DecryptOptions,
	EncryptOptions,
	KeyProviderRegistration,
	ReencryptOptions,
} from "./types.js";

export const DEFAULT_MAX_PAYLOAD_BYTES = 10 * 1024 * 1024;
export const DEFAULT_MAX_BATCH_ITEMS = 256;

function registry<Input, Value extends { readonly name: string }>(
	values: readonly Input[],
	label: string,
	snapshot: (value: Input) => Value,
): ReadonlyMap<string, Value> {
	if (!Array.isArray(values)) {
		throw new CryptoError("CONFIGURATION", `A ${label} registry is required.`);
	}
	const result = new Map<string, Value>();
	for (const input of values) {
		try {
			const value = Object.freeze(snapshot(input));
			if (
				!value.name ||
				value.name.length > 128 ||
				value.name.trim() !== value.name ||
				/\p{Cc}/u.test(value.name)
			) {
				throw new TypeError("Invalid registration name.");
			}
			if (result.has(value.name)) {
				throw new TypeError("Duplicate registration name.");
			}
			result.set(value.name, value);
		} catch (error: unknown) {
			throw new CryptoError("CONFIGURATION", `A ${label} registration is invalid.`, {
				cause: error,
			});
		}
	}
	return result;
}

function validIdentifier(value: unknown, maxLength: number): value is string {
	return (
		typeof value === "string" &&
		value.length > 0 &&
		value.length <= maxLength &&
		value.trim() === value &&
		!/\p{Cc}/u.test(value)
	);
}

function captureAad(value: unknown, message: string): Uint8Array {
	if (value === undefined || typeof value === "string" || isStableBytes(value)) {
		return aadBytes(value);
	}
	throw new CryptoError("INVALID_ARGUMENT", message);
}

function assertCipher(cipher: CipherAlgorithm): void {
	try {
		if (
			typeof cipher !== "object" ||
			cipher === null ||
			!validIdentifier(cipher.name, 128) ||
			!Number.isSafeInteger(cipher.keyLength) ||
			cipher.keyLength <= 0 ||
			!Number.isSafeInteger(cipher.nonceLength) ||
			cipher.nonceLength !== 12 ||
			!Number.isSafeInteger(cipher.tagLength) ||
			cipher.tagLength <= 0 ||
			cipher.tagLength > 64 ||
			typeof cipher.encrypt !== "function" ||
			typeof cipher.decrypt !== "function"
		) {
			throw new TypeError("Invalid cipher contract.");
		}
	} catch (error: unknown) {
		throw new CryptoError("CONFIGURATION", "A cipher registration is invalid.", {
			cause: error,
		});
	}
}

function assertProvider(provider: import("./types.js").DataKeyProvider): void {
	try {
		if (
			typeof provider !== "object" ||
			provider === null ||
			typeof provider.generateDataKey !== "function" ||
			typeof provider.unwrapDataKey !== "function" ||
			(provider.close !== undefined && typeof provider.close !== "function")
		) {
			throw new TypeError("Invalid key-provider contract.");
		}
	} catch (error: unknown) {
		throw new CryptoError("CONFIGURATION", "A key-provider registration is invalid.", {
			cause: error,
		});
	}
}

function captureGeneratedDataKey(
	value: unknown,
	cipher: CipherAlgorithm,
): import("./types.js").GeneratedDataKey {
	try {
		if (typeof value !== "object" || value === null) throw new TypeError("Invalid data key.");
		const dataKey = value as Partial<import("./types.js").GeneratedDataKey>;
		const plaintextKey = dataKey.plaintextKey;
		const wrappedKeySource = dataKey.wrappedKey;
		const keyReference = dataKey.keyReference;
		const wrappingAlgorithm = dataKey.wrappingAlgorithm;
		if (
			!(plaintextKey instanceof KeyObject) ||
			plaintextKey.type !== "secret" ||
			plaintextKey.symmetricKeySize !== cipher.keyLength ||
			!isStableBytes(wrappedKeySource) ||
			!validIdentifier(keyReference, 1024) ||
			!validIdentifier(wrappingAlgorithm, 128)
		) {
			throw new TypeError("Invalid data key.");
		}
		const wrappedKey = new Uint8Array(wrappedKeySource);
		if (wrappedKey.byteLength === 0 || wrappedKey.byteLength > 65_536) {
			throw new TypeError("Invalid wrapped data key.");
		}
		return Object.freeze({ plaintextKey, wrappedKey, keyReference, wrappingAlgorithm });
	} catch (error: unknown) {
		throw new CryptoError("INVALID_KEY", "The generated data key is invalid.", {
			cause: error,
		});
	}
}

function captureCiphertext(
	value: unknown,
	cipher: CipherAlgorithm,
	maxPayloadBytes: number,
): import("./types.js").CipherEncryptResult {
	try {
		if (typeof value !== "object" || value === null) {
			throw new TypeError("Invalid cipher result.");
		}
		const result = value as Partial<import("./types.js").CipherEncryptResult>;
		const ciphertextSource = result.ciphertext;
		const tagSource = result.tag;
		if (
			!isStableBytes(ciphertextSource) ||
			!isStableBytes(tagSource) ||
			ciphertextSource.byteLength > maxPayloadBytes ||
			tagSource.byteLength !== cipher.tagLength
		) {
			throw new TypeError("Invalid cipher result.");
		}
		return Object.freeze({
			ciphertext: new Uint8Array(ciphertextSource),
			tag: new Uint8Array(tagSource),
		});
	} catch (error: unknown) {
		throw new CryptoError("CIPHER_FAILURE", "The cipher returned an invalid result.", {
			cause: error,
		});
	}
}

function captureNonce(value: unknown, length: number): Uint8Array {
	try {
		if (!isStableBytes(value) || value.byteLength !== length) {
			throw new TypeError("Invalid nonce source result.");
		}
		return new Uint8Array(value);
	} catch (error: unknown) {
		throw new CryptoError("CIPHER_FAILURE", "The nonce source returned an invalid nonce.", {
			cause: error,
		});
	}
}

function captureUnwrappedDataKey(value: unknown, cipher: CipherAlgorithm): KeyObject {
	try {
		if (
			!(value instanceof KeyObject) ||
			value.type !== "secret" ||
			value.symmetricKeySize !== cipher.keyLength
		) {
			throw new TypeError("Invalid unwrapped data key.");
		}
		return value;
	} catch (error: unknown) {
		throw new CryptoError("INVALID_KEY", "The unwrapped data key has an invalid size.", {
			cause: error,
		});
	}
}

export class CipherEngine {
	readonly #providers: ReadonlyMap<string, KeyProviderRegistration>;
	readonly #ciphers: ReadonlyMap<
		string,
		{ readonly name: string; readonly cipher: CipherAlgorithm }
	>;
	readonly #defaultProvider: string;
	readonly #defaultCipher: string;
	readonly #maxPayloadBytes: number;
	readonly #maxBatchItems: number;
	readonly #maxBatchBytes: number;
	readonly #nonceSource: (length: number) => Uint8Array;
	#closed = false;

	constructor(options: CipherEngineOptions) {
		if (typeof options !== "object" || options === null) {
			throw new CryptoError("CONFIGURATION", "Cipher engine options are required.");
		}
		this.#providers = registry(options.providers, "key provider", (registration) => ({
			name: registration.name,
			provider: registration.provider,
		}));
		this.#ciphers = registry(
			options.ciphers ?? [{ name: AES_256_GCM, cipher: new Aes256GcmCipher() }],
			"cipher",
			(registration) => ({ name: registration.name, cipher: registration.cipher }),
		);
		for (const { provider } of this.#providers.values()) assertProvider(provider);
		for (const { cipher } of this.#ciphers.values()) assertCipher(cipher);
		this.#defaultProvider = options.defaultProvider;
		this.#defaultCipher = options.defaultCipher ?? AES_256_GCM;
		if (!this.#providers.has(this.#defaultProvider)) {
			throw new CryptoError("CONFIGURATION", "The default key provider is not registered.");
		}
		if (!this.#ciphers.has(this.#defaultCipher)) {
			throw new CryptoError("CONFIGURATION", "The default cipher is not registered.");
		}
		const maxPayloadBytes = options.maxPayloadBytes ?? DEFAULT_MAX_PAYLOAD_BYTES;
		if (!Number.isSafeInteger(maxPayloadBytes) || maxPayloadBytes < 0) {
			throw new CryptoError(
				"CONFIGURATION",
				"The payload limit must be a nonnegative safe integer.",
			);
		}
		this.#maxPayloadBytes = maxPayloadBytes;
		const maxBatchItems = options.maxBatchItems ?? DEFAULT_MAX_BATCH_ITEMS;
		if (!Number.isSafeInteger(maxBatchItems) || maxBatchItems < 1 || maxBatchItems > 0xffff_ffff) {
			throw new CryptoError(
				"CONFIGURATION",
				"The batch item limit must be a positive safe integer no greater than 2^32 - 1.",
			);
		}
		this.#maxBatchItems = maxBatchItems;
		const maxBatchBytes = options.maxBatchBytes ?? maxPayloadBytes;
		if (!Number.isSafeInteger(maxBatchBytes) || maxBatchBytes < 0) {
			throw new CryptoError(
				"CONFIGURATION",
				"The aggregate batch-byte limit must be a nonnegative safe integer.",
			);
		}
		this.#maxBatchBytes = maxBatchBytes;
		this.#nonceSource = options.nonceSource ?? ((length) => new Uint8Array(randomBytes(length)));
	}

	get defaultProvider(): string {
		return this.#defaultProvider;
	}

	get maxBatchItems(): number {
		return this.#maxBatchItems;
	}

	hasProvider(name: string): boolean {
		return this.#providers.has(name);
	}

	async encryptBytes(plaintext: Uint8Array, options: EncryptOptions = {}): Promise<string> {
		let captured: EncryptOptions;
		try {
			if (typeof options !== "object" || options === null) {
				throw new TypeError("Invalid encryption options.");
			}
			const aad = options.aad;
			const keyContext = options.keyContext;
			const provider = options.provider;
			const cipher = options.cipher;
			const signal = options.signal;
			captured = Object.freeze({
				...(aad === undefined ? {} : { aad }),
				...(keyContext === undefined ? {} : { keyContext }),
				...(provider === undefined ? {} : { provider }),
				...(cipher === undefined ? {} : { cipher }),
				...(signal === undefined ? {} : { signal }),
			});
		} catch (error: unknown) {
			throw new CryptoError("INVALID_ARGUMENT", "Encryption options are invalid.", {
				cause: error,
			});
		}
		const [encrypted] = await this.encryptBatch(
			[{ plaintext, ...(captured.aad === undefined ? {} : { aad: captured.aad }) }],
			{
				...(captured.keyContext === undefined ? {} : { keyContext: captured.keyContext }),
				...(captured.provider === undefined ? {} : { provider: captured.provider }),
				...(captured.cipher === undefined ? {} : { cipher: captured.cipher }),
				...(captured.signal === undefined ? {} : { signal: captured.signal }),
			},
		);
		if (encrypted === undefined) {
			throw new CryptoError("CIPHER_FAILURE", "Encryption produced no ciphertext.");
		}
		return encrypted;
	}

	async encryptBatch(
		items: readonly BatchEncryptItem[],
		options: BatchEncryptOptions = {},
	): Promise<readonly string[]> {
		this.#assertOpen();
		let signal: AbortSignal | undefined;
		let providerName: string;
		let cipherName: string;
		let keyContext: unknown;
		try {
			if (typeof options !== "object" || options === null) {
				throw new TypeError("Invalid encryption options.");
			}
			signal = options.signal;
			if (signal !== undefined && !(signal instanceof AbortSignal)) {
				throw new TypeError("Invalid abort signal.");
			}
			const selectedProvider = options.provider;
			const selectedCipher = options.cipher;
			if (selectedProvider !== undefined && typeof selectedProvider !== "string") {
				throw new TypeError("Invalid provider selection.");
			}
			if (selectedCipher !== undefined && typeof selectedCipher !== "string") {
				throw new TypeError("Invalid cipher selection.");
			}
			providerName = selectedProvider ?? this.#defaultProvider;
			cipherName = selectedCipher ?? this.#defaultCipher;
			keyContext = options.keyContext;
		} catch (error: unknown) {
			throw new CryptoError("INVALID_ARGUMENT", "Encryption options are invalid.", {
				cause: error,
			});
		}
		throwIfAborted(signal);
		if (!Array.isArray(items)) {
			throw new CryptoError("INVALID_ARGUMENT", "An encryption batch is required.");
		}
		this.#assertBatchItemCount(items.length, "encryption");
		if (items.length === 0) return Object.freeze([]);
		const capturedItems: Array<Readonly<{ plaintext: Uint8Array; aad: Uint8Array }>> = [];
		let aggregateBytes = 0;
		try {
			for (const item of items) {
				let plaintext: unknown;
				let callerAad: unknown;
				try {
					if (typeof item !== "object" || item === null) {
						throw new TypeError("Invalid encryption batch item.");
					}
					plaintext = item.plaintext;
					callerAad = item.aad;
				} catch (error: unknown) {
					throw new CryptoError("INVALID_ARGUMENT", "An encryption batch item is invalid.", {
						cause: error,
					});
				}
				if (!isStableBytes(plaintext)) {
					throw new CryptoError("INVALID_ARGUMENT", "Plaintext bytes are required.");
				}
				if (plaintext.byteLength > this.#maxPayloadBytes) {
					throw new CryptoError("LIMIT_EXCEEDED", "The plaintext exceeds the configured limit.");
				}
				aggregateBytes = this.#addBatchBytes(
					aggregateBytes,
					plaintext.byteLength,
					"The plaintext batch exceeds the configured aggregate limit.",
				);
				let capturedAad: Uint8Array | undefined;
				let capturedPlaintext: Uint8Array | undefined;
				try {
					capturedAad = captureAad(callerAad, "Authenticated data must be text or bytes.");
					capturedPlaintext = new Uint8Array(plaintext);
					capturedItems.push(Object.freeze({ plaintext: capturedPlaintext, aad: capturedAad }));
				} catch (error: unknown) {
					capturedPlaintext?.fill(0);
					capturedAad?.fill(0);
					throw error;
				}
			}
		} catch (error: unknown) {
			for (const item of capturedItems) {
				item.plaintext.fill(0);
				item.aad.fill(0);
			}
			throw error;
		}
		let wrappingContext: Uint8Array;
		try {
			wrappingContext = captureAad(keyContext, "Key context must be text or bytes.");
		} catch (error: unknown) {
			for (const item of capturedItems) {
				item.plaintext.fill(0);
				item.aad.fill(0);
			}
			throw error;
		}
		try {
			const provider = this.#providers.get(providerName)?.provider;
			if (!provider) throw new CryptoError("PROVIDER_NOT_FOUND", "The key provider was not found.");
			const cipher = this.#ciphers.get(cipherName)?.cipher;
			if (!cipher)
				throw new CryptoError("UNSUPPORTED_CIPHER", "The requested cipher is unsupported.");
			assertCipher(cipher);
			const dataKey = await providerCall(
				async () =>
					captureGeneratedDataKey(
						await provider.generateDataKey({
							wrappingContext,
							...(signal === undefined ? {} : { signal }),
						}),
						cipher,
					),
				signal,
			);
			const wrappedKey = dataKey.wrappedKey;
			const protectedSegment = encodeProtectedHeader({
				v: 1,
				cipher: cipherName,
				provider: providerName,
				key: dataKey.keyReference,
				wrap: dataKey.wrappingAlgorithm,
			});
			let noncePrefix: Uint8Array;
			try {
				noncePrefix = captureNonce(this.#nonceSource(8), 8);
			} catch (error: unknown) {
				throw new CryptoError("CIPHER_FAILURE", "The nonce source returned an invalid nonce.", {
					cause: error,
				});
			}
			const envelopes = capturedItems.map((item, index) => {
				const nonce = new Uint8Array(12);
				nonce.set(noncePrefix);
				new DataView(nonce.buffer).setUint32(8, index, false);
				const aad = frame(utf8(ENVELOPE_PREFIX), utf8(protectedSegment), wrappedKey, item.aad);
				let encrypted: import("./types.js").CipherEncryptResult;
				try {
					encrypted = captureCiphertext(
						cipher.encrypt({
							plaintext: item.plaintext,
							key: dataKey.plaintextKey,
							nonce,
							aad,
						}),
						cipher,
						this.#maxPayloadBytes,
					);
				} catch (error: unknown) {
					throw new CryptoError("CIPHER_FAILURE", "Encryption failed.", { cause: error });
				}
				return serializeEnvelope({
					protectedSegment,
					header: {
						v: 1,
						cipher: cipherName,
						provider: providerName,
						key: dataKey.keyReference,
						wrap: dataKey.wrappingAlgorithm,
					},
					wrappedKey,
					nonce,
					ciphertext: encrypted.ciphertext,
					tag: encrypted.tag,
				});
			});
			throwIfAborted(signal);
			return Object.freeze(envelopes);
		} finally {
			wrappingContext.fill(0);
			for (const item of capturedItems) {
				item.plaintext.fill(0);
				item.aad.fill(0);
			}
		}
	}

	async encryptText(plaintext: string, options: EncryptOptions = {}): Promise<string> {
		if (typeof plaintext !== "string") {
			throw new CryptoError("INVALID_ARGUMENT", "Plaintext text is required.");
		}
		const bytes = utf8(plaintext);
		try {
			return await this.encryptBytes(bytes, options);
		} finally {
			bytes.fill(0);
		}
	}

	async encryptTextBatch(
		items: readonly BatchEncryptTextItem[],
		options: BatchEncryptOptions = {},
	): Promise<readonly string[]> {
		if (!Array.isArray(items)) {
			throw new CryptoError("INVALID_ARGUMENT", "A text encryption batch is required.");
		}
		this.#assertBatchItemCount(items.length, "text encryption");
		const batch: Array<Readonly<{ plaintext: Uint8Array; aad: Uint8Array }>> = [];
		let aggregateBytes = 0;
		try {
			for (const item of items) {
				let plaintext: unknown;
				let callerAad: unknown;
				try {
					if (typeof item !== "object" || item === null) {
						throw new TypeError("Invalid text encryption batch item.");
					}
					plaintext = item.plaintext;
					callerAad = item.aad;
				} catch (error: unknown) {
					throw new CryptoError("INVALID_ARGUMENT", "A text encryption batch item is invalid.", {
						cause: error,
					});
				}
				if (typeof plaintext !== "string") {
					throw new CryptoError("INVALID_ARGUMENT", "Plaintext text is required.");
				}
				let aad: Uint8Array | undefined;
				let encoded: Uint8Array | undefined;
				try {
					aad = captureAad(callerAad, "Authenticated data must be text or bytes.");
					encoded = utf8(plaintext);
					if (encoded.byteLength > this.#maxPayloadBytes) {
						throw new CryptoError("LIMIT_EXCEEDED", "The plaintext exceeds the configured limit.");
					}
					aggregateBytes = this.#addBatchBytes(
						aggregateBytes,
						encoded.byteLength,
						"The plaintext batch exceeds the configured aggregate limit.",
					);
					batch.push(Object.freeze({ plaintext: encoded, aad }));
				} catch (error: unknown) {
					aad?.fill(0);
					encoded?.fill(0);
					throw error;
				}
			}
			return await this.encryptBatch(batch, options);
		} finally {
			for (const item of batch) {
				item.plaintext.fill(0);
				item.aad.fill(0);
			}
		}
	}

	async encryptValue<Value>(
		value: Value,
		codec: CipherCodec<Value>,
		options: EncryptOptions = {},
	): Promise<string> {
		const capturedCodec = captureCipherCodec(codec);
		const plaintext = encodeCipherValue(value, capturedCodec);
		try {
			return await this.encryptBytes(plaintext, options);
		} finally {
			plaintext.fill(0);
		}
	}

	async decryptBytes(envelope: string, options: DecryptOptions = {}): Promise<Uint8Array> {
		let captured: DecryptOptions;
		try {
			if (typeof options !== "object" || options === null) {
				throw new TypeError("Invalid decryption options.");
			}
			const aad = options.aad;
			const keyContext = options.keyContext;
			const allowedProviders = options.allowedProviders;
			const signal = options.signal;
			captured = Object.freeze({
				...(aad === undefined ? {} : { aad }),
				...(keyContext === undefined ? {} : { keyContext }),
				...(allowedProviders === undefined ? {} : { allowedProviders }),
				...(signal === undefined ? {} : { signal }),
			});
		} catch (error: unknown) {
			throw new CryptoError("INVALID_ARGUMENT", "Decryption options are invalid.", {
				cause: error,
			});
		}
		const [plaintext] = await this.decryptBatch(
			[{ envelope, ...(captured.aad === undefined ? {} : { aad: captured.aad }) }],
			{
				...(captured.keyContext === undefined ? {} : { keyContext: captured.keyContext }),
				...(captured.allowedProviders === undefined
					? {}
					: { allowedProviders: captured.allowedProviders }),
				...(captured.signal === undefined ? {} : { signal: captured.signal }),
			},
		);
		if (plaintext === undefined) {
			throw new CryptoError("CIPHER_FAILURE", "Decryption produced no plaintext.");
		}
		return plaintext;
	}

	async decryptBatch(
		items: readonly BatchDecryptItem[],
		options: BatchDecryptOptions = {},
	): Promise<readonly Uint8Array[]> {
		this.#assertOpen();
		let signal: AbortSignal | undefined;
		let keyContext: unknown;
		let allowedProviders: ReadonlySet<string> | undefined;
		try {
			if (typeof options !== "object" || options === null) {
				throw new TypeError("Invalid decryption options.");
			}
			signal = options.signal;
			if (signal !== undefined && !(signal instanceof AbortSignal)) {
				throw new TypeError("Invalid abort signal.");
			}
			keyContext = options.keyContext;
			const configuredProviders = options.allowedProviders;
			if (configuredProviders !== undefined) {
				if (!Array.isArray(configuredProviders)) {
					throw new TypeError("Invalid allowed-provider list.");
				}
				const capturedProviders = [...configuredProviders];
				if (capturedProviders.some((name) => typeof name !== "string")) {
					throw new TypeError("Invalid allowed-provider name.");
				}
				allowedProviders = new Set(capturedProviders);
			}
		} catch (error: unknown) {
			throw new CryptoError("INVALID_ARGUMENT", "Decryption options are invalid.", {
				cause: error,
			});
		}
		throwIfAborted(signal);
		if (!Array.isArray(items)) {
			throw new CryptoError("INVALID_ARGUMENT", "A decryption batch is required.");
		}
		this.#assertBatchItemCount(items.length, "decryption");
		if (items.length === 0) return Object.freeze([]);
		const wrappingContext = captureAad(keyContext, "Key context must be text or bytes.");
		const parsedItems: Array<
			Readonly<{
				aad: Uint8Array;
				parsed: import("./envelope.js").ParsedEnvelope;
			}>
		> = [];
		let aggregateBytes = 0;
		try {
			for (const item of items) {
				let envelope: unknown;
				let callerAad: unknown;
				try {
					if (typeof item !== "object" || item === null) {
						throw new TypeError("Invalid decryption batch item.");
					}
					envelope = item.envelope;
					callerAad = item.aad;
				} catch (error: unknown) {
					throw new CryptoError("INVALID_ARGUMENT", "A decryption batch item is invalid.", {
						cause: error,
					});
				}
				if (typeof envelope !== "string") {
					throw new CryptoError("INVALID_ARGUMENT", "A ciphertext envelope is required.");
				}
				let capturedAad: Uint8Array | undefined;
				try {
					capturedAad = captureAad(callerAad, "Authenticated data must be text or bytes.");
					const parsed = parseEnvelope(envelope, this.#maxPayloadBytes);
					aggregateBytes = this.#addBatchBytes(
						aggregateBytes,
						parsed.ciphertext.byteLength,
						"The ciphertext batch exceeds the configured aggregate limit.",
					);
					parsedItems.push(Object.freeze({ aad: capturedAad, parsed }));
				} catch (error: unknown) {
					capturedAad?.fill(0);
					throw error;
				}
			}
		} catch (error: unknown) {
			wrappingContext.fill(0);
			for (const item of parsedItems) item.aad.fill(0);
			throw error;
		}
		const keys = new Map<string, KeyObject>();
		const plaintexts: Uint8Array[] = [];
		try {
			for (const { parsed } of parsedItems) {
				if (allowedProviders !== undefined && !allowedProviders.has(parsed.header.provider)) {
					throw authenticationFailed();
				}
			}
			for (const { aad: callerAad, parsed } of parsedItems) {
				const provider = this.#providers.get(parsed.header.provider)?.provider;
				if (!provider) {
					throw new CryptoError("PROVIDER_NOT_FOUND", "The key provider was not found.");
				}
				const cipher = this.#ciphers.get(parsed.header.cipher)?.cipher;
				if (!cipher) {
					throw new CryptoError("UNSUPPORTED_CIPHER", "The envelope cipher is unsupported.");
				}
				assertCipher(cipher);
				if (
					parsed.nonce.byteLength !== cipher.nonceLength ||
					parsed.tag.byteLength !== cipher.tagLength
				) {
					throw authenticationFailed();
				}
				const cacheKey = [
					parsed.header.provider,
					parsed.header.key,
					parsed.header.wrap,
					Buffer.from(parsed.wrappedKey).toString("base64url"),
				].join("\u0000");
				let key = keys.get(cacheKey);
				if (!key) {
					key = await providerCall(
						async () =>
							captureUnwrappedDataKey(
								await provider.unwrapDataKey(
									{
										wrappedKey: parsed.wrappedKey,
										keyReference: parsed.header.key,
										wrappingAlgorithm: parsed.header.wrap,
									},
									{
										wrappingContext,
										...(signal === undefined ? {} : { signal }),
									},
								),
								cipher,
							),
						signal,
					);
					keys.set(cacheKey, key);
				}
				const aad = frame(
					utf8(ENVELOPE_PREFIX),
					utf8(parsed.protectedSegment),
					parsed.wrappedKey,
					callerAad,
				);
				let plaintext: Uint8Array | undefined;
				try {
					const output = cipher.decrypt({
						ciphertext: parsed.ciphertext,
						key,
						nonce: parsed.nonce,
						tag: parsed.tag,
						aad,
					});
					if (!isStableBytes(output)) throw new TypeError("Invalid plaintext result.");
					plaintext = new Uint8Array(output);
					output.fill(0);
				} catch (error: unknown) {
					plaintext?.fill(0);
					throw authenticationFailed({ cause: error });
				}
				if (plaintext.byteLength > this.#maxPayloadBytes) {
					plaintext.fill(0);
					throw new CryptoError("LIMIT_EXCEEDED", "The plaintext exceeds the configured limit.");
				}
				plaintexts.push(plaintext);
			}
			throwIfAborted(signal);
			return Object.freeze(plaintexts);
		} catch (error: unknown) {
			for (const plaintext of plaintexts) plaintext.fill(0);
			throw error;
		} finally {
			wrappingContext.fill(0);
			for (const item of parsedItems) item.aad.fill(0);
		}
	}

	async decryptText(envelope: string, options: DecryptOptions = {}): Promise<string> {
		const plaintext = await this.decryptBytes(envelope, options);
		try {
			return decodeUtf8(plaintext);
		} finally {
			plaintext.fill(0);
		}
	}

	async decryptTextBatch(
		items: readonly BatchDecryptTextItem[],
		options: BatchDecryptOptions = {},
	): Promise<readonly string[]> {
		if (!Array.isArray(items)) {
			throw new CryptoError("INVALID_ARGUMENT", "A text decryption batch is required.");
		}
		this.#assertBatchItemCount(items.length, "text decryption");
		const batch: Array<Readonly<{ envelope: string; aad: Uint8Array }>> = [];
		try {
			for (const item of items) {
				let envelope: unknown;
				let callerAad: unknown;
				try {
					if (typeof item !== "object" || item === null) {
						throw new TypeError("Invalid text decryption batch item.");
					}
					envelope = item.envelope;
					callerAad = item.aad;
				} catch (error: unknown) {
					throw new CryptoError("INVALID_ARGUMENT", "A text decryption batch item is invalid.", {
						cause: error,
					});
				}
				if (typeof envelope !== "string") {
					throw new CryptoError("INVALID_ARGUMENT", "A ciphertext envelope is required.");
				}
				const aad = captureAad(callerAad, "Authenticated data must be text or bytes.");
				batch.push(Object.freeze({ envelope, aad }));
			}
			const plaintexts = await this.decryptBatch(batch, options);
			try {
				return Object.freeze(plaintexts.map((plaintext) => decodeUtf8(plaintext)));
			} finally {
				for (const plaintext of plaintexts) plaintext.fill(0);
			}
		} finally {
			for (const item of batch) item.aad.fill(0);
		}
	}

	async decryptValue<Value>(
		envelope: string,
		codec: CipherCodec<Value>,
		options: DecryptOptions = {},
	): Promise<Value> {
		const capturedCodec = captureCipherCodec(codec);
		const plaintext = await this.decryptBytes(envelope, options);
		try {
			return decodeCipherValue(plaintext, capturedCodec);
		} finally {
			plaintext.fill(0);
		}
	}

	async reencrypt(envelope: string, options: ReencryptOptions = {}): Promise<string> {
		let aad: Uint8Array | undefined;
		let keyContext: Uint8Array | undefined;
		let signal: AbortSignal | undefined;
		let provider: string | undefined;
		let cipher: string | undefined;
		let allowedProviders: readonly string[] | undefined;
		try {
			if (typeof options !== "object" || options === null) {
				throw new TypeError("Invalid re-encryption options.");
			}
			aad = captureAad(options.aad, "Authenticated data must be text or bytes.");
			keyContext = captureAad(options.keyContext, "Key context must be text or bytes.");
			signal = options.signal;
			provider = options.provider;
			cipher = options.cipher;
			const configuredProviders = options.allowedProviders;
			if (signal !== undefined && !(signal instanceof AbortSignal)) {
				throw new TypeError("Invalid abort signal.");
			}
			if (provider !== undefined && typeof provider !== "string") {
				throw new TypeError("Invalid provider selection.");
			}
			if (cipher !== undefined && typeof cipher !== "string") {
				throw new TypeError("Invalid cipher selection.");
			}
			if (configuredProviders !== undefined) {
				if (!Array.isArray(configuredProviders)) {
					throw new TypeError("Invalid allowed-provider list.");
				}
				allowedProviders = Object.freeze([...configuredProviders]);
				if (allowedProviders.some((name) => typeof name !== "string")) {
					throw new TypeError("Invalid allowed-provider name.");
				}
			}
		} catch (error: unknown) {
			aad?.fill(0);
			keyContext?.fill(0);
			throw new CryptoError("INVALID_ARGUMENT", "Re-encryption options are invalid.", {
				cause: error,
			});
		}
		let plaintext: Uint8Array | undefined;
		try {
			plaintext = await this.decryptBytes(envelope, {
				aad,
				keyContext,
				...(allowedProviders === undefined ? {} : { allowedProviders }),
				...(signal === undefined ? {} : { signal }),
			});
			return await this.encryptBytes(plaintext, {
				aad,
				keyContext,
				...(provider === undefined ? {} : { provider }),
				...(cipher === undefined ? {} : { cipher }),
				...(signal === undefined ? {} : { signal }),
			});
		} finally {
			plaintext?.fill(0);
			aad.fill(0);
			keyContext.fill(0);
		}
	}

	inspect(envelope: string): CipherEnvelopeInfo {
		this.#assertOpen();
		return envelopeInfo(parseEnvelope(envelope, this.#maxPayloadBytes));
	}

	async close(): Promise<void> {
		if (this.#closed) return;
		this.#closed = true;
		const providers = new Set([...this.#providers.values()].map(({ provider }) => provider));
		await Promise.all(
			[...providers].map((provider) =>
				providerCall(async () => {
					await provider.close?.();
				}),
			),
		);
	}

	#assertBatchItemCount(length: number, operation: string): void {
		if (length > this.#maxBatchItems) {
			throw new CryptoError("LIMIT_EXCEEDED", `The ${operation} batch has too many items.`);
		}
	}

	#addBatchBytes(total: number, next: number, message: string): number {
		if (next > this.#maxBatchBytes - total) {
			throw new CryptoError("LIMIT_EXCEEDED", message);
		}
		return total + next;
	}

	#assertOpen(): void {
		if (this.#closed) throw new CryptoError("CIPHER_FAILURE", "The cipher engine is closed.");
	}
}
