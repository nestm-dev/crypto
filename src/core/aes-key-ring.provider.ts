import {
	createCipheriv,
	createDecipheriv,
	createHash,
	createSecretKey,
	generateKeySync,
	hkdfSync,
	randomBytes,
	type DecipherGCM,
	type KeyObject,
} from "node:crypto";
import { authenticationFailed, CryptoError, throwIfAborted } from "./errors.js";
import type { DataKeyContext, DataKeyProvider, GeneratedDataKey, WrappedDataKey } from "./types.js";

/** Salt-derived, one-use AES-256-GCM key wrapping used by the local key ring. */
export const AES_GCM_HKDF_SHA256_KEY_WRAP = "NESTM-A256GCM-HKDF-SHA256-SALT256-V2";

const WRAP_VERSION = 2;
const SALT_BYTES = 32;
const DATA_KEY_BYTES = 32;
const TAG_BYTES = 16;
const WRAPPED_KEY_BYTES = 1 + SALT_BYTES + DATA_KEY_BYTES + TAG_BYTES;
const FIXED_WRAP_IV = new Uint8Array(12);
const KEY_DERIVATION_INFO = "nestm:aes-key-ring:a256gcm-hkdf-sha256-salt256:v2\0";
const KEY_REFERENCE_CONTEXT = "nestm:aes-key-ring:key-reference:v2\0";
const WRAPPING_CONTEXT = "nestm:aes-key-ring:wrapping-context:v2\0";
const WRAP_AUTHENTICATED_DATA = Buffer.concat([
	Buffer.from("nestm:aes-key-ring:wrapped-data-key:v2\0", "utf8"),
	Buffer.of(WRAP_VERSION),
]);

export interface AesKeyRingProviderOptions {
	readonly activeKeyId: string;
	readonly keys: Readonly<Record<string, KeyObject | Uint8Array>>;
}

function normalizeKek(key: KeyObject | Uint8Array): KeyObject {
	if ("type" in key) {
		if (key.type !== "secret" || key.symmetricKeySize !== 32) {
			throw new CryptoError("INVALID_KEY", "Every AES wrapping key must contain 32 bytes.");
		}
		return key;
	}
	if (key.byteLength !== 32) {
		throw new CryptoError("INVALID_KEY", "Every AES wrapping key must contain 32 bytes.");
	}
	const copy = Buffer.from(key);
	try {
		return createSecretKey(copy);
	} finally {
		copy.fill(0);
	}
}

function validateKeyId(keyId: string): void {
	if (!keyId || keyId.length > 1024 || keyId.trim() !== keyId || /\p{Cc}/u.test(keyId)) {
		throw new CryptoError("CONFIGURATION", "An AES key-ring key identifier is invalid.");
	}
}

function framedDigest(domain: string, value: Uint8Array): Buffer {
	const length = Buffer.alloc(8);
	length.writeBigUInt64BE(BigInt(value.byteLength));
	try {
		return createHash("sha256").update(domain, "utf8").update(length).update(value).digest();
	} finally {
		length.fill(0);
	}
}

function deriveOneUseWrappingKey(
	kek: KeyObject,
	salt: Uint8Array,
	keyReference: string,
	wrappingContext: Uint8Array,
): Buffer {
	const reference = Buffer.from(keyReference, "utf8");
	const referenceDigest = framedDigest(KEY_REFERENCE_CONTEXT, reference);
	const contextDigest = framedDigest(WRAPPING_CONTEXT, wrappingContext);
	const info = Buffer.concat([
		Buffer.from(KEY_DERIVATION_INFO, "utf8"),
		Buffer.of(WRAP_VERSION),
		referenceDigest,
		contextDigest,
	]);
	try {
		return Buffer.from(hkdfSync("sha256", kek, salt, info, DATA_KEY_BYTES));
	} finally {
		reference.fill(0);
		referenceDigest.fill(0);
		contextDigest.fill(0);
		info.fill(0);
	}
}

function decryptDataKey(decipher: DecipherGCM, ciphertext: Uint8Array): KeyObject {
	const first = decipher.update(ciphertext);
	let last: Buffer | undefined;
	let raw: Buffer | undefined;
	try {
		last = decipher.final();
		raw = Buffer.concat([first, last]);
		if (raw.byteLength !== DATA_KEY_BYTES) throw authenticationFailed();
		return createSecretKey(raw);
	} finally {
		first.fill(0);
		last?.fill(0);
		raw?.fill(0);
	}
}

export class AesKeyRingProvider implements DataKeyProvider {
	readonly #activeKeyId: string;
	readonly #keys: ReadonlyMap<string, KeyObject>;

	constructor(options: AesKeyRingProviderOptions) {
		validateKeyId(options.activeKeyId);
		const keys = new Map<string, KeyObject>();
		for (const [keyId, key] of Object.entries(options.keys)) {
			validateKeyId(keyId);
			keys.set(keyId, normalizeKek(key));
		}
		if (!keys.has(options.activeKeyId)) {
			throw new CryptoError("CONFIGURATION", "The active AES wrapping key is not registered.");
		}
		this.#activeKeyId = options.activeKeyId;
		this.#keys = keys;
	}

	async generateDataKey(context: DataKeyContext): Promise<GeneratedDataKey> {
		throwIfAborted(context.signal);
		const plaintextKey = generateKeySync("aes", { length: 256 });
		const wrappedKey = this.#wrap(
			plaintextKey,
			this.#keys.get(this.#activeKeyId)!,
			this.#activeKeyId,
			context,
		);
		throwIfAborted(context.signal);
		return Object.freeze({
			plaintextKey,
			wrappedKey,
			keyReference: this.#activeKeyId,
			wrappingAlgorithm: AES_GCM_HKDF_SHA256_KEY_WRAP,
		});
	}

	async unwrapDataKey(dataKey: WrappedDataKey, context: DataKeyContext): Promise<KeyObject> {
		throwIfAborted(context.signal);
		if (dataKey.wrappingAlgorithm !== AES_GCM_HKDF_SHA256_KEY_WRAP) {
			throw new CryptoError("INVALID_KEY", "The wrapped-key algorithm is unsupported.");
		}
		const kek = this.#keys.get(dataKey.keyReference);
		if (!kek) throw new CryptoError("KEY_NOT_FOUND", "The wrapping key was not found.");
		return this.#unwrap(dataKey.wrappedKey, kek, dataKey.keyReference, context);
	}

	#unwrap(
		wrappedKey: Uint8Array,
		kek: KeyObject,
		keyReference: string,
		context: DataKeyContext,
	): KeyObject {
		if (wrappedKey.byteLength !== WRAPPED_KEY_BYTES || wrappedKey[0] !== WRAP_VERSION) {
			throw authenticationFailed();
		}
		const salt = wrappedKey.subarray(1, 1 + SALT_BYTES);
		const ciphertext = wrappedKey.subarray(1 + SALT_BYTES, 1 + SALT_BYTES + DATA_KEY_BYTES);
		const tag = wrappedKey.subarray(1 + SALT_BYTES + DATA_KEY_BYTES);
		let wrappingKey: Buffer | undefined;
		try {
			wrappingKey = deriveOneUseWrappingKey(kek, salt, keyReference, context.wrappingContext);
			const decipher = createDecipheriv("aes-256-gcm", wrappingKey, FIXED_WRAP_IV, {
				authTagLength: TAG_BYTES,
			});
			decipher.setAAD(WRAP_AUTHENTICATED_DATA, { plaintextLength: DATA_KEY_BYTES });
			decipher.setAuthTag(tag);
			return decryptDataKey(decipher, ciphertext);
		} catch (error: unknown) {
			if (error instanceof CryptoError) throw error;
			throw authenticationFailed({ cause: error });
		} finally {
			wrappingKey?.fill(0);
		}
	}

	#wrap(key: KeyObject, kek: KeyObject, keyReference: string, context: DataKeyContext): Uint8Array {
		const salt = randomBytes(SALT_BYTES);
		const raw = key.export();
		let wrappingKey: Buffer | undefined;
		let ciphertext: Buffer | undefined;
		let tag: Buffer | undefined;
		try {
			wrappingKey = deriveOneUseWrappingKey(kek, salt, keyReference, context.wrappingContext);
			const cipher = createCipheriv("aes-256-gcm", wrappingKey, FIXED_WRAP_IV, {
				authTagLength: TAG_BYTES,
			});
			cipher.setAAD(WRAP_AUTHENTICATED_DATA, { plaintextLength: DATA_KEY_BYTES });
			ciphertext = Buffer.concat([cipher.update(raw), cipher.final()]);
			if (ciphertext.byteLength !== DATA_KEY_BYTES) {
				throw new CryptoError("CIPHER_FAILURE", "Key wrapping produced an invalid result.");
			}
			tag = cipher.getAuthTag();
			const output = new Uint8Array(WRAPPED_KEY_BYTES);
			output[0] = WRAP_VERSION;
			output.set(salt, 1);
			output.set(ciphertext, 1 + SALT_BYTES);
			output.set(tag, 1 + SALT_BYTES + DATA_KEY_BYTES);
			return output;
		} catch (error: unknown) {
			if (error instanceof CryptoError) throw error;
			throw new CryptoError("CIPHER_FAILURE", "Key wrapping failed.", { cause: error });
		} finally {
			wrappingKey?.fill(0);
			ciphertext?.fill(0);
			tag?.fill(0);
			raw.fill(0);
		}
	}
}
