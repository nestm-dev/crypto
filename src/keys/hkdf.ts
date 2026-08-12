import { hkdfSync } from "node:crypto";
import { CryptoError } from "../core/errors.js";

const SHA256_OUTPUT_BYTES = 32;
const MAX_OUTPUT_BYTES = 255 * SHA256_OUTPUT_BYTES;

/**
 * HKDF-SHA256 (RFC 5869) extract-and-expand. `salt` may be empty (RFC 5869 then
 * substitutes a string of `HashLen` zero bytes); `info` may be empty. Input keying
 * material must be non-empty, and the requested length is bounded by RFC 5869's
 * `255 * HashLen` ceiling.
 */
export function hkdfSha256(
	ikm: Uint8Array,
	salt: Uint8Array,
	info: Uint8Array,
	length: number,
): Uint8Array {
	if (!Number.isInteger(length) || length < 1 || length > MAX_OUTPUT_BYTES) {
		throw new CryptoError("INVALID_ARGUMENT", "The HKDF output length is out of range.");
	}
	if (ikm.byteLength === 0) {
		throw new CryptoError("INVALID_ARGUMENT", "HKDF input keying material must be non-empty.");
	}
	try {
		return new Uint8Array(hkdfSync("sha256", ikm, salt, info, length));
	} catch (error: unknown) {
		throw new CryptoError("CIPHER_FAILURE", "Key derivation failed.", { cause: error });
	}
}
