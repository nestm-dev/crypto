import { createHash, createSecretKey, randomBytes, type KeyObject } from "node:crypto";
import { aadBytes, frame, utf8 } from "../core/encoding.js";
import { CryptoError } from "../core/errors.js";
import type { CipherAad } from "../core/types.js";
import { hkdfSha256 } from "../keys/hkdf.js";
import { timingSafeEqualBytes } from "../keys/hmac.js";

/** Prefix identifying a v1 account-recovery code. */
export const RECOVERY_CODE_PREFIX = "ASR1";

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/**
 * Five bytes encode to exactly eight base32 characters, so padding the payload to a
 * multiple of five bytes yields uniform groups with no ragged tail and no partial-byte
 * padding for the parser to second-guess.
 */
const GROUP_SIZE = 8;
const GROUP_BYTES = 5;
const DERIVED_KEY_BYTES = 32;
const MIN_SALT_BYTES = 16;
const MAX_SALT_BYTES = 1024;
const INFO_LABEL = "nmc/recovery/v1";

export interface GenerateRecoveryCodeOptions {
	readonly entropyBits?: 128 | 160;
}

export interface GeneratedRecoveryCode {
	/** Display-once value. Never persist this — store only a wrap derived from `secret`. */
	readonly code: string;
	readonly secret: Uint8Array;
}

/**
 * Checksum width is whatever it takes to pad the secret to a whole number of groups:
 * four bytes for a 128-bit secret, five for a 160-bit one. Both are far stronger than a
 * single byte, so a mistyped code is rejected on sight rather than sent to the KDF.
 */
function checksumBytesFor(secretBytes: number): number {
	const remainder = secretBytes % GROUP_BYTES;
	return remainder === 0 ? GROUP_BYTES : GROUP_BYTES - remainder;
}

function checksum(secret: Uint8Array, length: number): Uint8Array {
	return new Uint8Array(createHash("sha256").update(secret).digest().subarray(0, length));
}

function encodeBase32(bytes: Uint8Array): string {
	let output = "";
	let buffer = 0;
	let bits = 0;
	for (const byte of bytes) {
		buffer = (buffer << 8) | byte;
		bits += 8;
		while (bits >= 5) {
			output += ALPHABET[(buffer >>> (bits - 5)) & 0x1f];
			bits -= 5;
		}
	}
	if (bits > 0) {
		output += ALPHABET[(buffer << (5 - bits)) & 0x1f];
	}
	return output;
}

function decodeBase32(value: string, expectedBytes: number): Uint8Array {
	const output = new Uint8Array(expectedBytes);
	let buffer = 0;
	let bits = 0;
	let index = 0;
	for (const character of value) {
		const digit = ALPHABET.indexOf(character);
		if (digit === -1) {
			throw new CryptoError("INVALID_ARGUMENT", "The recovery code contains invalid characters.");
		}
		buffer = (buffer << 5) | digit;
		bits += 5;
		if (bits >= 8) {
			if (index >= expectedBytes) {
				throw new CryptoError("INVALID_ARGUMENT", "The recovery code is malformed.");
			}
			output[index] = (buffer >>> (bits - 8)) & 0xff;
			index += 1;
			bits -= 8;
		}
	}
	if (index !== expectedBytes) {
		throw new CryptoError("INVALID_ARGUMENT", "The recovery code is malformed.");
	}
	// Trailing bits exist only as zero padding; a non-zero remainder is not canonical.
	if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) {
		throw new CryptoError("INVALID_ARGUMENT", "The recovery code is not canonical.");
	}
	return output;
}

/**
 * Generate a display-once recovery code. The secret is full-entropy, so a memory-hard
 * KDF buys nothing over HKDF at {@link deriveRecoveryKey}.
 */
export function generateRecoveryCode(options?: GenerateRecoveryCodeOptions): GeneratedRecoveryCode {
	const entropyBits = options?.entropyBits ?? 128;
	if (entropyBits !== 128 && entropyBits !== 160) {
		throw new CryptoError("INVALID_ARGUMENT", "The recovery code entropy is unsupported.");
	}
	const secret = new Uint8Array(randomBytes(entropyBits / 8));
	const checksumLength = checksumBytesFor(secret.byteLength);
	const payload = new Uint8Array(secret.byteLength + checksumLength);
	payload.set(secret, 0);
	payload.set(checksum(secret, checksumLength), secret.byteLength);
	try {
		const encoded = encodeBase32(payload);
		const groups: string[] = [];
		for (let index = 0; index < encoded.length; index += GROUP_SIZE) {
			groups.push(encoded.slice(index, index + GROUP_SIZE));
		}
		return Object.freeze({ code: `${RECOVERY_CODE_PREFIX}-${groups.join("-")}`, secret });
	} finally {
		payload.fill(0);
	}
}

/** Parse and checksum-verify a user-entered recovery code. Fail-closed on any deviation. */
export function parseRecoveryCode(code: string): Uint8Array {
	if (typeof code !== "string" || code.length === 0 || code.length > 128) {
		throw new CryptoError("INVALID_ARGUMENT", "The recovery code is invalid.");
	}
	const normalized = code
		.trim()
		.toUpperCase()
		.replace(/[\s-]+/gu, "")
		// Crockford aliases: visually ambiguous characters map onto their canonical digit.
		.replace(/[IL]/gu, "1")
		.replace(/O/gu, "0");
	if (!normalized.startsWith(RECOVERY_CODE_PREFIX)) {
		throw new CryptoError("INVALID_ARGUMENT", "The recovery code prefix is unrecognized.");
	}
	const body = normalized.slice(RECOVERY_CODE_PREFIX.length);
	// 128-bit → 16 secret + 4 checksum = 20 bytes → 32 characters;
	// 160-bit → 20 secret + 5 checksum = 25 bytes → 40 characters.
	const secretBytes = body.length === 32 ? 16 : body.length === 40 ? 20 : undefined;
	if (secretBytes === undefined) {
		throw new CryptoError("INVALID_ARGUMENT", "The recovery code length is invalid.");
	}
	const checksumLength = checksumBytesFor(secretBytes);
	const payload = decodeBase32(body, secretBytes + checksumLength);
	try {
		const secret = new Uint8Array(payload.subarray(0, secretBytes));
		const actual = new Uint8Array(payload.subarray(secretBytes));
		if (!timingSafeEqualBytes(checksum(secret, checksumLength), actual)) {
			secret.fill(0);
			throw new CryptoError("INVALID_ARGUMENT", "The recovery code checksum does not match.");
		}
		return secret;
	} finally {
		payload.fill(0);
	}
}

/** Derive the recovery key-encryption key from a parsed recovery secret. */
export function deriveRecoveryKey(
	secret: Uint8Array,
	salt: Uint8Array,
	info?: CipherAad,
): KeyObject {
	if (!(secret instanceof Uint8Array) || secret.byteLength < 16) {
		throw new CryptoError("INVALID_ARGUMENT", "The recovery secret is invalid.");
	}
	if (
		!(salt instanceof Uint8Array) ||
		salt.byteLength < MIN_SALT_BYTES ||
		salt.byteLength > MAX_SALT_BYTES
	) {
		throw new CryptoError("INVALID_ARGUMENT", "The recovery salt length is out of range.");
	}
	let okm: Uint8Array | undefined;
	try {
		okm = hkdfSha256(secret, salt, frame(utf8(INFO_LABEL), aadBytes(info)), DERIVED_KEY_BYTES);
		return createSecretKey(okm);
	} finally {
		okm?.fill(0);
	}
}
