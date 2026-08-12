import { decodeUtf8, utf8 } from "./encoding.js";
import { CryptoError } from "./errors.js";

/**
 * Converts a value to owned plaintext bytes and reconstructs an independent
 * value from an ephemeral plaintext view.
 */
export interface CipherCodec<Value> {
	encode(this: void, value: Value): Uint8Array;
	decode(this: void, plaintext: Uint8Array): Value;
}

function isStableBytes(value: unknown): value is Uint8Array {
	try {
		if (!(value instanceof Uint8Array) || !ArrayBuffer.isView(value)) return false;
		const prototype = Reflect.getPrototypeOf(value);
		if (prototype !== Uint8Array.prototype && prototype !== Buffer.prototype) return false;
		if (
			Reflect.ownKeys(value).some(
				(key) => typeof key !== "string" || !/^(?:0|[1-9]\d*)$/u.test(key),
			)
		) {
			return false;
		}
		return !(value.buffer instanceof SharedArrayBuffer) && Number.isSafeInteger(value.byteLength);
	} catch {
		return false;
	}
}

/** @internal Captures codec methods before an asynchronous crypto boundary. */
export function captureCipherCodec<Value>(codec: CipherCodec<Value>): CipherCodec<Value> {
	try {
		if (typeof codec !== "object" || codec === null) {
			throw new TypeError("A cipher codec is required.");
		}
		const encode = codec.encode;
		const decode = codec.decode;
		if (typeof encode !== "function" || typeof decode !== "function") {
			throw new TypeError("Invalid cipher codec contract.");
		}
		return Object.freeze({
			encode: (value: Value) => encode(value),
			decode: (plaintext: Uint8Array) => decode(plaintext),
		});
	} catch (error: unknown) {
		throw new CryptoError("INVALID_ARGUMENT", "The cipher codec is invalid.", {
			cause: error,
		});
	}
}

/** @internal Returns a private copy that the caller must zero. */
export function encodeCipherValue<Value>(value: Value, codec: CipherCodec<Value>): Uint8Array {
	try {
		const encoded: unknown = codec.encode(value);
		if (!isStableBytes(encoded)) {
			throw new TypeError("The cipher codec returned invalid plaintext bytes.");
		}
		return new Uint8Array(encoded);
	} catch (error: unknown) {
		throw new CryptoError("INVALID_ARGUMENT", "The cipher codec could not encode the value.", {
			cause: error,
		});
	}
}

/** @internal The decoder receives a copy that is zeroed before this returns. */
export function decodeCipherValue<Value>(plaintext: Uint8Array, codec: CipherCodec<Value>): Value {
	const input = new Uint8Array(plaintext);
	try {
		return codec.decode(input);
	} catch (error: unknown) {
		throw new CryptoError("CIPHER_FAILURE", "The cipher codec could not decode the value.", {
			cause: error,
		});
	} finally {
		input.fill(0);
	}
}

export function jsonCodec<Value>(validate: (parsed: unknown) => Value): CipherCodec<Value> {
	if (typeof validate !== "function") {
		throw new CryptoError("INVALID_ARGUMENT", "A JSON codec validator is required.");
	}
	return Object.freeze({
		encode: (value: Value): Uint8Array => {
			let serialized: string | undefined;
			try {
				serialized = JSON.stringify(value);
			} catch (error: unknown) {
				throw new CryptoError("INVALID_ARGUMENT", "The value is not JSON serializable.", {
					cause: error,
				});
			}
			if (serialized === undefined) {
				throw new CryptoError("INVALID_ARGUMENT", "The value is not JSON serializable.");
			}
			return utf8(serialized);
		},
		decode: (plaintext: Uint8Array): Value => {
			let parsed: unknown;
			try {
				parsed = JSON.parse(decodeUtf8(plaintext)) as unknown;
			} catch (error: unknown) {
				throw new CryptoError("CIPHER_FAILURE", "Decrypted bytes do not contain valid JSON.", {
					cause: error,
				});
			}
			return validate(parsed);
		},
	});
}
