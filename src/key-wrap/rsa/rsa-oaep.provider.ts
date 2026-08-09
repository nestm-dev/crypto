import {
	constants,
	createPrivateKey,
	createPublicKey,
	createSecretKey,
	generateKeySync,
	privateDecrypt,
	publicEncrypt,
	timingSafeEqual,
	KeyObject,
} from "node:crypto";
import { authenticationFailed, CryptoError, throwIfAborted } from "../../core/errors.js";
import type {
	DataKeyContext,
	DataKeyProvider,
	GeneratedDataKey,
	WrappedDataKey,
} from "../../core/types.js";

export const RSA_OAEP_256 = "RSA-OAEP-256";

export type RsaPublicKeyInput = KeyObject | Parameters<typeof createPublicKey>[0];
export type RsaPrivateKeyInput = KeyObject | Parameters<typeof createPrivateKey>[0];

export interface RsaOaepKeyEntry {
	/** Required for the active key. May be omitted for a decrypt-only legacy key. */
	readonly publicKey?: RsaPublicKeyInput;
	/** Required to decrypt data keys wrapped with this key identifier. */
	readonly privateKey?: RsaPrivateKeyInput;
}

export interface RsaOaepKeyRingProviderOptions {
	readonly activeKeyId: string;
	readonly keys: Readonly<Record<string, RsaOaepKeyEntry>>;
}

interface NormalizedRsaKeyEntry {
	readonly publicKey?: KeyObject;
	readonly privateKey?: KeyObject;
}

function validateKeyId(keyId: string): void {
	if (
		keyId.length === 0 ||
		keyId.length > 1024 ||
		keyId.trim() !== keyId ||
		/\p{Cc}/u.test(keyId)
	) {
		throw new CryptoError("CONFIGURATION", "An RSA wrapping-key identifier is invalid.");
	}
}

function validateRsaKey(key: KeyObject): KeyObject {
	if (key.asymmetricKeyType !== "rsa") {
		throw new CryptoError("INVALID_KEY", "An RSA wrapping key is required.");
	}
	const modulusLength = key.asymmetricKeyDetails?.modulusLength;
	if (modulusLength === undefined || modulusLength < 2048) {
		throw new CryptoError("INVALID_KEY", "RSA wrapping keys must contain at least 2048 bits.");
	}
	return key;
}

function normalizePublicKey(input: RsaPublicKeyInput): KeyObject {
	try {
		const key =
			input instanceof KeyObject
				? input.type === "private"
					? createPublicKey(input)
					: input
				: createPublicKey(input);
		return validateRsaKey(key);
	} catch (error: unknown) {
		if (error instanceof CryptoError) throw error;
		throw new CryptoError("INVALID_KEY", "The RSA public wrapping key is invalid.", {
			cause: error,
		});
	}
}

function normalizePrivateKey(input: RsaPrivateKeyInput): KeyObject {
	try {
		const key = input instanceof KeyObject ? input : createPrivateKey(input);
		if (key.type !== "private") {
			throw new CryptoError("INVALID_KEY", "An RSA private wrapping key is required.");
		}
		return validateRsaKey(key);
	} catch (error: unknown) {
		if (error instanceof CryptoError) throw error;
		throw new CryptoError("INVALID_KEY", "The RSA private wrapping key is invalid.", {
			cause: error,
		});
	}
}

function assertMatchingPair(entry: NormalizedRsaKeyEntry): void {
	if (entry.publicKey === undefined || entry.privateKey === undefined) return;
	const publicDer = entry.publicKey.export({ type: "spki", format: "der" });
	const derivedDer = createPublicKey(entry.privateKey).export({ type: "spki", format: "der" });
	if (publicDer.byteLength !== derivedDer.byteLength || !timingSafeEqual(publicDer, derivedDer)) {
		throw new CryptoError("INVALID_KEY", "The RSA wrapping-key pair does not match.");
	}
}

function normalizeEntry(entry: RsaOaepKeyEntry): NormalizedRsaKeyEntry {
	if (entry.publicKey === undefined && entry.privateKey === undefined) {
		throw new CryptoError("INVALID_KEY", "An RSA wrapping-key entry is empty.");
	}
	const normalized: NormalizedRsaKeyEntry = {
		...(entry.publicKey === undefined ? {} : { publicKey: normalizePublicKey(entry.publicKey) }),
		...(entry.privateKey === undefined
			? {}
			: { privateKey: normalizePrivateKey(entry.privateKey) }),
	};
	assertMatchingPair(normalized);
	return Object.freeze(normalized);
}

export class RsaOaepKeyRingProvider implements DataKeyProvider {
	readonly #activeKeyId: string;
	readonly #keys: ReadonlyMap<string, NormalizedRsaKeyEntry>;

	constructor(options: RsaOaepKeyRingProviderOptions) {
		validateKeyId(options.activeKeyId);
		const keys = new Map<string, NormalizedRsaKeyEntry>();
		for (const [keyId, entry] of Object.entries(options.keys)) {
			validateKeyId(keyId);
			keys.set(keyId, normalizeEntry(entry));
		}
		if (keys.get(options.activeKeyId)?.publicKey === undefined) {
			throw new CryptoError(
				"CONFIGURATION",
				"The active RSA public wrapping key is not registered.",
			);
		}
		this.#activeKeyId = options.activeKeyId;
		this.#keys = keys;
	}

	async generateDataKey(context: DataKeyContext): Promise<GeneratedDataKey> {
		throwIfAborted(context.signal);
		const plaintextKey = generateKeySync("aes", { length: 256 });
		const raw = plaintextKey.export();
		try {
			let wrappedKey: Uint8Array;
			try {
				wrappedKey = publicEncrypt(
					{
						key: this.#keys.get(this.#activeKeyId)!.publicKey!,
						padding: constants.RSA_PKCS1_OAEP_PADDING,
						oaepHash: "sha256",
						oaepLabel: context.wrappingContext,
					},
					raw,
				);
			} catch (error: unknown) {
				throw new CryptoError("CIPHER_FAILURE", "The data key could not be wrapped.", {
					cause: error,
				});
			}
			throwIfAborted(context.signal);
			return Object.freeze({
				plaintextKey,
				wrappedKey: new Uint8Array(wrappedKey),
				keyReference: this.#activeKeyId,
				wrappingAlgorithm: RSA_OAEP_256,
			});
		} finally {
			raw.fill(0);
		}
	}

	async unwrapDataKey(dataKey: WrappedDataKey, context: DataKeyContext): Promise<KeyObject> {
		throwIfAborted(context.signal);
		if (dataKey.wrappingAlgorithm !== RSA_OAEP_256) {
			throw new CryptoError("INVALID_KEY", "The wrapped-key algorithm is unsupported.");
		}
		const privateKey = this.#keys.get(dataKey.keyReference)?.privateKey;
		if (privateKey === undefined) {
			throw new CryptoError("KEY_NOT_FOUND", "The RSA private wrapping key was not found.");
		}

		let raw: Buffer;
		try {
			raw = privateDecrypt(
				{
					key: privateKey,
					padding: constants.RSA_PKCS1_OAEP_PADDING,
					oaepHash: "sha256",
					oaepLabel: context.wrappingContext,
				},
				dataKey.wrappedKey,
			);
		} catch (error: unknown) {
			throw authenticationFailed({ cause: error });
		}
		try {
			if (raw.byteLength !== 32) throw authenticationFailed();
			throwIfAborted(context.signal);
			return createSecretKey(raw);
		} finally {
			raw.fill(0);
		}
	}
}
