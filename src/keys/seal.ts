import { createSecretKey, diffieHellman, generateKeyPairSync, KeyObject } from "node:crypto";
import { Aes256GcmCipher } from "../core/aes-256-gcm.js";
import { aadBytes, frame, utf8 } from "../core/encoding.js";
import { authenticationFailed, CryptoError } from "../core/errors.js";
import type { CipherAad } from "../core/types.js";
import { hkdfSha256 } from "./hkdf.js";
import {
	toX25519PrivateKey,
	toX25519PublicKey,
	x25519PublicKeyBytes,
	x25519PublicKeyFromRaw,
	type X25519PrivateKeyInput,
	type X25519PublicKeyInput,
} from "./x25519.js";

/** Suite identifier: ephemeral-static X25519, HKDF-SHA256 key schedule, AES-256-GCM seal. */
export const SEAL_X25519_HKDF_SHA256_A256GCM = "X25519-HKDF-SHA256-A256GCM";

const SEAL_FORMAT_VERSION = 0x01;
const SEAL_SUITE_ID = 0x01;
const EPHEMERAL_PUBLIC_BYTES = 32;
const TAG_BYTES = 16;
const HEADER_BYTES = 2 + EPHEMERAL_PUBLIC_BYTES;

/** Fixed framing + tag overhead a sealed blob adds to its plaintext. */
export const SEALED_OVERHEAD_BYTES = HEADER_BYTES + TAG_BYTES;

const MAX_PLAINTEXT_BYTES = 64 * 1024;
const AES_KEY_BYTES = 32;
const NONCE_BYTES = 12;
const OKM_BYTES = AES_KEY_BYTES + NONCE_BYTES;
const INFO_LABEL = "nmc/seal/v1";
const EMPTY_SALT = new Uint8Array();

export interface SealOptions {
	/** Bound into the key schedule (protocol/domain context). Must match at open. */
	readonly info?: CipherAad;
	/** Bound as AES-GCM associated data (per-message binding). Must match at open. */
	readonly aad?: CipherAad;
}

export interface SealedInfo {
	readonly version: 1;
	readonly suite: string;
	readonly ephemeralPublicKey: Uint8Array;
	readonly ciphertextBytes: number;
	readonly authenticated: false;
}

interface ParsedSeal {
	readonly ephemeralPublicKey: Uint8Array;
	readonly ciphertext: Uint8Array;
	readonly tag: Uint8Array;
}

function messageBytes(plaintext: Uint8Array | KeyObject): { bytes: Uint8Array; owned: boolean } {
	if (plaintext instanceof KeyObject) {
		if (plaintext.type !== "secret") {
			throw new CryptoError("INVALID_ARGUMENT", "Only a secret key can be sealed.");
		}
		return { bytes: new Uint8Array(plaintext.export()), owned: true };
	}
	if (plaintext instanceof Uint8Array) {
		return { bytes: plaintext, owned: false };
	}
	throw new CryptoError("INVALID_ARGUMENT", "Sealed plaintext must be bytes or a secret key.");
}

function scheduleInfo(
	ephemeralPublicKey: Uint8Array,
	recipientPublicKey: Uint8Array,
	info?: CipherAad,
): Uint8Array {
	return frame(
		utf8(INFO_LABEL),
		utf8(SEAL_X25519_HKDF_SHA256_A256GCM),
		ephemeralPublicKey,
		recipientPublicKey,
		aadBytes(info),
	);
}

export function sealTo(
	recipientPublicKey: X25519PublicKeyInput,
	plaintext: Uint8Array | KeyObject,
	options?: SealOptions,
): Uint8Array {
	const recipient = toX25519PublicKey(recipientPublicKey);
	const { bytes: message, owned } = messageBytes(plaintext);
	try {
		if (message.byteLength === 0) {
			throw new CryptoError("INVALID_ARGUMENT", "Sealed plaintext must be non-empty.");
		}
		if (message.byteLength > MAX_PLAINTEXT_BYTES) {
			throw new CryptoError("LIMIT_EXCEEDED", "The sealed payload is too large.");
		}
		const ephemeral = generateKeyPairSync("x25519");
		const ephemeralPublicRaw = x25519PublicKeyBytes(ephemeral.publicKey);
		const recipientPublicRaw = x25519PublicKeyBytes(recipient);

		let shared: Buffer | undefined;
		let okm: Uint8Array | undefined;
		try {
			shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipient });
			okm = hkdfSha256(
				new Uint8Array(shared),
				EMPTY_SALT,
				scheduleInfo(ephemeralPublicRaw, recipientPublicRaw, options?.info),
				OKM_BYTES,
			);
			const key = createSecretKey(okm.subarray(0, AES_KEY_BYTES));
			const { ciphertext, tag } = new Aes256GcmCipher().encrypt({
				plaintext: message,
				key,
				nonce: okm.subarray(AES_KEY_BYTES, OKM_BYTES),
				aad: aadBytes(options?.aad),
			});

			const sealed = new Uint8Array(HEADER_BYTES + ciphertext.byteLength + TAG_BYTES);
			sealed[0] = SEAL_FORMAT_VERSION;
			sealed[1] = SEAL_SUITE_ID;
			sealed.set(ephemeralPublicRaw, 2);
			sealed.set(ciphertext, HEADER_BYTES);
			sealed.set(tag, HEADER_BYTES + ciphertext.byteLength);
			return sealed;
		} finally {
			shared?.fill(0);
			okm?.fill(0);
		}
	} finally {
		if (owned) message.fill(0);
	}
}

function parseSealed(sealed: Uint8Array): ParsedSeal {
	if (!(sealed instanceof Uint8Array)) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The sealed blob must be bytes.");
	}
	if (sealed.byteLength <= SEALED_OVERHEAD_BYTES) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The sealed blob is truncated.");
	}
	if (sealed.byteLength > MAX_PLAINTEXT_BYTES + SEALED_OVERHEAD_BYTES) {
		throw new CryptoError("LIMIT_EXCEEDED", "The sealed blob is too large.");
	}
	if (sealed[0] !== SEAL_FORMAT_VERSION) {
		throw new CryptoError("UNSUPPORTED_VERSION", "The sealed blob version is unsupported.");
	}
	if (sealed[1] !== SEAL_SUITE_ID) {
		throw new CryptoError("UNSUPPORTED_CIPHER", "The sealed blob suite is unsupported.");
	}
	const tagStart = sealed.byteLength - TAG_BYTES;
	return {
		ephemeralPublicKey: new Uint8Array(sealed.subarray(2, HEADER_BYTES)),
		ciphertext: new Uint8Array(sealed.subarray(HEADER_BYTES, tagStart)),
		tag: new Uint8Array(sealed.subarray(tagStart)),
	};
}

function openToBytes(
	recipientPrivateKey: X25519PrivateKeyInput,
	sealed: Uint8Array,
	options: SealOptions | undefined,
): Buffer {
	const recipient = toX25519PrivateKey(recipientPrivateKey);
	const parsed = parseSealed(sealed);
	const recipientPublicKey = x25519PublicKeyBytes(recipient);

	let ephemeral: KeyObject;
	try {
		ephemeral = x25519PublicKeyFromRaw(parsed.ephemeralPublicKey);
	} catch (error: unknown) {
		throw authenticationFailed({ cause: error });
	}

	let shared: Buffer | undefined;
	let okm: Uint8Array | undefined;
	try {
		try {
			shared = diffieHellman({ privateKey: recipient, publicKey: ephemeral });
		} catch (error: unknown) {
			// Node rejects a low-order / all-zero ephemeral key at derivation.
			throw authenticationFailed({ cause: error });
		}
		okm = hkdfSha256(
			new Uint8Array(shared),
			EMPTY_SALT,
			scheduleInfo(parsed.ephemeralPublicKey, recipientPublicKey, options?.info),
			OKM_BYTES,
		);
		const key = createSecretKey(okm.subarray(0, AES_KEY_BYTES));
		const plaintext = new Aes256GcmCipher().decrypt({
			ciphertext: parsed.ciphertext,
			key,
			nonce: okm.subarray(AES_KEY_BYTES, OKM_BYTES),
			tag: parsed.tag,
			aad: aadBytes(options?.aad),
		});
		return Buffer.from(plaintext);
	} finally {
		shared?.fill(0);
		okm?.fill(0);
	}
}

export function openFrom(
	recipientPrivateKey: X25519PrivateKeyInput,
	sealed: Uint8Array,
	options?: SealOptions,
): Buffer {
	return openToBytes(recipientPrivateKey, sealed, options);
}

/** Open a sealed secret straight into a `KeyObject` so the caller never holds raw bytes. */
export function openKeyFrom(
	recipientPrivateKey: X25519PrivateKeyInput,
	sealed: Uint8Array,
	options?: SealOptions,
): KeyObject {
	const raw = openToBytes(recipientPrivateKey, sealed, options);
	try {
		return createSecretKey(raw);
	} finally {
		raw.fill(0);
	}
}

/** Untrusted framing metadata. Nothing here is authenticated until `openFrom` succeeds. */
export function inspectSealed(sealed: Uint8Array): SealedInfo {
	const parsed = parseSealed(sealed);
	return Object.freeze({
		version: 1,
		suite: SEAL_X25519_HKDF_SHA256_A256GCM,
		ephemeralPublicKey: parsed.ephemeralPublicKey,
		ciphertextBytes: parsed.ciphertext.byteLength,
		authenticated: false,
	});
}
