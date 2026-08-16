import { createHmac, timingSafeEqual, KeyObject } from "node:crypto";
import { CryptoError } from "../core/errors.js";

/** HMAC-SHA256 over the concatenation of `parts`. Callers that need unambiguous
 * separation between parts must frame them first — this helper does not. */
export function hmacSha256(
	key: KeyObject | Uint8Array,
	...parts: readonly Uint8Array[]
): Uint8Array {
	if (key instanceof KeyObject) {
		if (key.type !== "secret") {
			throw new CryptoError("INVALID_KEY", "An HMAC key must be a secret key.");
		}
	} else if (!(key instanceof Uint8Array)) {
		throw new CryptoError("INVALID_KEY", "An HMAC key must be bytes or a secret key.");
	}
	try {
		const mac = createHmac("sha256", key);
		for (const part of parts) {
			if (!(part instanceof Uint8Array)) {
				throw new TypeError("Every HMAC input must be bytes.");
			}
			mac.update(part);
		}
		return new Uint8Array(mac.digest());
	} catch (error: unknown) {
		if (error instanceof CryptoError) throw error;
		throw new CryptoError("CIPHER_FAILURE", "HMAC computation failed.", { cause: error });
	}
}

/**
 * Constant-time byte comparison that tolerates unequal lengths.
 *
 * Equal-length inputs go straight to `timingSafeEqual`. Node's `timingSafeEqual` throws
 * on a size mismatch, so unequal lengths are instead compared as fixed-width SHA-256
 * HMACs. The HMAC key is a fixed all-zero constant and is not a secret: it is only there
 * to reach a fixed-width comparison, and the length difference that triggers this branch
 * is already public through `byteLength`.
 */
export function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
	if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
		throw new CryptoError("INVALID_ARGUMENT", "Both comparison operands must be bytes.");
	}
	if (a.byteLength === b.byteLength) {
		return timingSafeEqual(a, b);
	}
	// Different lengths already leak through `byteLength`; hash both sides anyway so the
	// comparison itself stays a fixed-width operation rather than an early return.
	const key = new Uint8Array(32);
	return timingSafeEqual(hmacSha256(key, a), hmacSha256(key, b));
}
