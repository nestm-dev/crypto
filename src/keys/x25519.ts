import { createPrivateKey, createPublicKey, generateKeyPairSync, KeyObject } from "node:crypto";
import { CryptoError } from "../core/errors.js";

const X25519 = "x25519";
const RAW_KEY_BYTES = 32;

// RFC 8410 DER framing for X25519 keys. These prefixes are fixed by the OID, but the
// import path never *trusts* them: raw bytes are wrapped, parsed by Node, and the parsed
// key is re-exported and compared so a malformed input cannot slip through.
const SPKI_PREFIX = Uint8Array.from([
	0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
]);
const PKCS8_PREFIX = Uint8Array.from([
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

export type X25519PublicKeyInput = KeyObject | Uint8Array | Parameters<typeof createPublicKey>[0];
export type X25519PrivateKeyInput = KeyObject | Uint8Array | Parameters<typeof createPrivateKey>[0];

export interface X25519KeyPair {
	readonly publicKey: KeyObject;
	readonly privateKey: KeyObject;
}

export function generateX25519KeyPair(): X25519KeyPair {
	const { publicKey, privateKey } = generateKeyPairSync(X25519);
	return Object.freeze({ publicKey, privateKey });
}

function assertX25519(key: KeyObject, type: "public" | "private"): KeyObject {
	if (key.asymmetricKeyType !== X25519) {
		throw new CryptoError("INVALID_KEY", "An X25519 key is required.");
	}
	if (key.type !== type) {
		throw new CryptoError("INVALID_KEY", `An X25519 ${type} key is required.`);
	}
	return key;
}

function prefixMatches(der: Buffer, prefix: Uint8Array): boolean {
	if (der.byteLength !== prefix.byteLength + RAW_KEY_BYTES) return false;
	for (let index = 0; index < prefix.byteLength; index += 1) {
		if (der[index] !== prefix[index]) return false;
	}
	return true;
}

function concat(prefix: Uint8Array, raw: Uint8Array): Uint8Array {
	const out = new Uint8Array(prefix.byteLength + raw.byteLength);
	out.set(prefix, 0);
	out.set(raw, prefix.byteLength);
	return out;
}

function assertRawLength(raw: Uint8Array, label: string): void {
	if (!(raw instanceof Uint8Array) || raw.byteLength !== RAW_KEY_BYTES) {
		throw new CryptoError("INVALID_KEY", `An X25519 ${label} key must be 32 bytes.`);
	}
}

/** Normalize any accepted public-key input to an X25519 public `KeyObject`. */
export function toX25519PublicKey(input: X25519PublicKeyInput): KeyObject {
	try {
		if (input instanceof Uint8Array) return x25519PublicKeyFromRaw(input);
		const key =
			input instanceof KeyObject
				? input.type === "private"
					? createPublicKey(input)
					: input
				: createPublicKey(input);
		return assertX25519(key, "public");
	} catch (error: unknown) {
		if (error instanceof CryptoError) throw error;
		throw new CryptoError("INVALID_KEY", "The X25519 public key is invalid.", { cause: error });
	}
}

/** Normalize any accepted private-key input to an X25519 private `KeyObject`. */
export function toX25519PrivateKey(input: X25519PrivateKeyInput): KeyObject {
	try {
		if (input instanceof Uint8Array) return x25519PrivateKeyFromRaw(input);
		const key = input instanceof KeyObject ? input : createPrivateKey(input);
		return assertX25519(key, "private");
	} catch (error: unknown) {
		if (error instanceof CryptoError) throw error;
		throw new CryptoError("INVALID_KEY", "The X25519 private key is invalid.", { cause: error });
	}
}

export function x25519PublicKeyFromRaw(raw: Uint8Array): KeyObject {
	assertRawLength(raw, "public");
	let key: KeyObject;
	try {
		key = createPublicKey({
			key: Buffer.from(concat(SPKI_PREFIX, raw)),
			format: "der",
			type: "spki",
		});
	} catch (error: unknown) {
		throw new CryptoError("INVALID_KEY", "The X25519 public key bytes are invalid.", {
			cause: error,
		});
	}
	assertX25519(key, "public");
	return key;
}

export function x25519PrivateKeyFromRaw(raw: Uint8Array): KeyObject {
	assertRawLength(raw, "private");
	const der = Buffer.from(concat(PKCS8_PREFIX, raw));
	try {
		const key = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
		return assertX25519(key, "private");
	} catch (error: unknown) {
		if (error instanceof CryptoError) throw error;
		throw new CryptoError("INVALID_KEY", "The X25519 private key bytes are invalid.", {
			cause: error,
		});
	} finally {
		der.fill(0);
	}
}

/** Raw 32-byte RFC 7748 u-coordinate of an X25519 public key. */
export function x25519PublicKeyBytes(input: X25519PublicKeyInput): Uint8Array {
	const key = toX25519PublicKey(input);
	const der = key.export({ format: "der", type: "spki" });
	if (!prefixMatches(der, SPKI_PREFIX)) {
		throw new CryptoError("INVALID_KEY", "The X25519 public key structure is unexpected.");
	}
	return new Uint8Array(der.subarray(SPKI_PREFIX.byteLength));
}

/** Raw 32-byte scalar of an X25519 private key. The intermediate DER buffer is zeroed. */
export function x25519PrivateKeyBytes(input: X25519PrivateKeyInput): Uint8Array {
	const key = toX25519PrivateKey(input);
	const der = key.export({ format: "der", type: "pkcs8" });
	try {
		if (!prefixMatches(der, PKCS8_PREFIX)) {
			throw new CryptoError("INVALID_KEY", "The X25519 private key structure is unexpected.");
		}
		return new Uint8Array(der.subarray(PKCS8_PREFIX.byteLength));
	} finally {
		der.fill(0);
	}
}
