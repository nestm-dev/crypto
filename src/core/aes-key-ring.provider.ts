import {
	createCipheriv,
	createDecipheriv,
	createSecretKey,
	generateKeySync,
	randomBytes,
	type KeyObject,
} from "node:crypto";
import { authenticationFailed, CryptoError, throwIfAborted } from "./errors.js";
import type { DataKeyContext, DataKeyProvider, GeneratedDataKey, WrappedDataKey } from "./types.js";

export const AES_GCM_KEY_WRAP = "A256GCMKW";
const WRAP_VERSION = 1;
const WRAPPED_LENGTH = 1 + 12 + 32 + 16;

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
		const wrappedKey = this.#wrap(plaintextKey, this.#keys.get(this.#activeKeyId)!, context);
		throwIfAborted(context.signal);
		return Object.freeze({
			plaintextKey,
			wrappedKey,
			keyReference: this.#activeKeyId,
			wrappingAlgorithm: AES_GCM_KEY_WRAP,
		});
	}

	async unwrapDataKey(dataKey: WrappedDataKey, context: DataKeyContext): Promise<KeyObject> {
		throwIfAborted(context.signal);
		if (dataKey.wrappingAlgorithm !== AES_GCM_KEY_WRAP) {
			throw new CryptoError("INVALID_KEY", "The wrapped-key algorithm is unsupported.");
		}
		const kek = this.#keys.get(dataKey.keyReference);
		if (!kek) throw new CryptoError("KEY_NOT_FOUND", "The wrapping key was not found.");
		if (
			dataKey.wrappedKey.byteLength !== WRAPPED_LENGTH ||
			dataKey.wrappedKey[0] !== WRAP_VERSION
		) {
			throw authenticationFailed();
		}
		try {
			const nonce = dataKey.wrappedKey.subarray(1, 13);
			const ciphertext = dataKey.wrappedKey.subarray(13, 45);
			const tag = dataKey.wrappedKey.subarray(45);
			const decipher = createDecipheriv("aes-256-gcm", kek, nonce, { authTagLength: 16 });
			decipher.setAAD(context.wrappingContext, { plaintextLength: 32 });
			decipher.setAuthTag(tag);
			const first = decipher.update(ciphertext);
			let last: Buffer | undefined;
			let raw: Buffer | undefined;
			try {
				last = decipher.final();
				raw = Buffer.concat([first, last]);
				if (raw.byteLength !== 32) throw authenticationFailed();
				return createSecretKey(raw);
			} finally {
				first.fill(0);
				last?.fill(0);
				raw?.fill(0);
			}
		} catch (error: unknown) {
			if (error instanceof CryptoError) throw error;
			throw authenticationFailed({ cause: error });
		}
	}

	#wrap(key: KeyObject, kek: KeyObject, context: DataKeyContext): Uint8Array {
		const nonce = randomBytes(12);
		const raw = key.export();
		try {
			const cipher = createCipheriv("aes-256-gcm", kek, nonce, { authTagLength: 16 });
			cipher.setAAD(context.wrappingContext, { plaintextLength: raw.byteLength });
			const ciphertext = Buffer.concat([cipher.update(raw), cipher.final()]);
			const output = new Uint8Array(WRAPPED_LENGTH);
			output[0] = WRAP_VERSION;
			output.set(nonce, 1);
			output.set(ciphertext, 13);
			output.set(cipher.getAuthTag(), 45);
			return output;
		} finally {
			raw.fill(0);
		}
	}
}
