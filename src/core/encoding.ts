import { CryptoError } from "./errors.js";
import type { CipherAad } from "./types.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export function utf8(value: string): Uint8Array {
	return encoder.encode(value);
}

export function decodeUtf8(value: Uint8Array): string {
	try {
		return decoder.decode(value);
	} catch (error: unknown) {
		throw new CryptoError("CIPHER_FAILURE", "Decrypted text is not valid UTF-8.", {
			cause: error,
		});
	}
}

export function aadBytes(value?: CipherAad): Uint8Array {
	try {
		if (value === undefined) return new Uint8Array();
		if (typeof value === "string") return utf8(value);
		if (
			value instanceof Uint8Array &&
			ArrayBuffer.isView(value) &&
			!(value.buffer instanceof SharedArrayBuffer)
		) {
			return new Uint8Array(value);
		}
		throw new TypeError("Invalid authenticated data.");
	} catch (error: unknown) {
		throw new CryptoError("INVALID_ARGUMENT", "Authenticated data must be text or bytes.", {
			cause: error,
		});
	}
}

export function base64url(value: Uint8Array): string {
	return Buffer.from(value).toString("base64url");
}

export function parseBase64url(value: string, label: string): Uint8Array {
	if (!/^[A-Za-z0-9_-]*$/u.test(value)) {
		throw new CryptoError("MALFORMED_ENVELOPE", `The ${label} segment is malformed.`);
	}
	const parsed = Buffer.from(value, "base64url");
	if (parsed.toString("base64url") !== value) {
		throw new CryptoError("MALFORMED_ENVELOPE", `The ${label} segment is not canonical.`);
	}
	return new Uint8Array(parsed);
}

export function frame(...parts: readonly Uint8Array[]): Uint8Array {
	let total = 0;
	for (const part of parts) {
		if (part.byteLength > 0xffff_ffff) {
			throw new CryptoError("LIMIT_EXCEEDED", "An authenticated-data component is too large.");
		}
		total += 4 + part.byteLength;
	}
	const output = new Uint8Array(total);
	const view = new DataView(output.buffer);
	let offset = 0;
	for (const part of parts) {
		view.setUint32(offset, part.byteLength, false);
		offset += 4;
		output.set(part, offset);
		offset += part.byteLength;
	}
	return output;
}

export function assertSafeIdentifier(value: string, label: string, maxLength = 1024): void {
	if (
		value.length === 0 ||
		value.length > maxLength ||
		/\p{Cc}/u.test(value) ||
		value.trim() !== value
	) {
		throw new CryptoError("MALFORMED_ENVELOPE", `The ${label} is invalid.`);
	}
}
