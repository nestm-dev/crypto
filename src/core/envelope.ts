import { base64url, parseBase64url, utf8, decodeUtf8, assertSafeIdentifier } from "./encoding.js";
import { CryptoError } from "./errors.js";
import type { CipherEnvelopeInfo } from "./types.js";

export const ENVELOPE_PREFIX = "nmc1";
const HEADER_KEYS = ["v", "cipher", "provider", "key", "wrap"] as const;
const MAX_PROTECTED_SEGMENT_CHARACTERS = 8192;
const MAX_WRAPPED_KEY_BYTES = 65_536;
const MAX_NONCE_BYTES = 64;
const MAX_TAG_BYTES = 64;

/**
 * Cheap shape test: does `value` look like a `nmc1` envelope? Framing only — nothing is
 * parsed or authenticated. Use it to route legacy plaintext during a migration, never as
 * a validity check.
 */
export function isCipherEnvelope(value: string): boolean {
	return typeof value === "string" && value.startsWith(`${ENVELOPE_PREFIX}.`);
}

export interface ProtectedHeader {
	readonly v: 1;
	readonly cipher: string;
	readonly provider: string;
	readonly key: string;
	readonly wrap: string;
}

export interface ParsedEnvelope {
	readonly protectedSegment: string;
	readonly header: ProtectedHeader;
	readonly wrappedKey: Uint8Array;
	readonly nonce: Uint8Array;
	readonly ciphertext: Uint8Array;
	readonly tag: Uint8Array;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function canonicalHeader(header: ProtectedHeader): string {
	return JSON.stringify({
		v: header.v,
		cipher: header.cipher,
		provider: header.provider,
		key: header.key,
		wrap: header.wrap,
	});
}

export function encodeProtectedHeader(header: ProtectedHeader): string {
	validateHeader(header);
	return base64url(utf8(canonicalHeader(header)));
}

function validateHeader(header: ProtectedHeader): void {
	if (header.v !== 1)
		throw new CryptoError("UNSUPPORTED_VERSION", "The envelope version is unsupported.");
	assertSafeIdentifier(header.cipher, "cipher", 128);
	assertSafeIdentifier(header.provider, "provider", 128);
	assertSafeIdentifier(header.key, "key reference");
	assertSafeIdentifier(header.wrap, "wrapping algorithm", 128);
}

function parseHeader(segment: string): ProtectedHeader {
	let value: unknown;
	try {
		value = JSON.parse(decodeUtf8(parseBase64url(segment, "protected header"))) as unknown;
	} catch (error: unknown) {
		if (error instanceof CryptoError && error.code === "MALFORMED_ENVELOPE") throw error;
		throw new CryptoError("MALFORMED_ENVELOPE", "The protected header is malformed.", {
			cause: error,
		});
	}
	if (!isRecord(value) || Object.keys(value).join(",") !== HEADER_KEYS.join(",")) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The protected header has an invalid shape.");
	}
	if (
		typeof value.v !== "number" ||
		typeof value.cipher !== "string" ||
		typeof value.provider !== "string" ||
		typeof value.key !== "string" ||
		typeof value.wrap !== "string"
	) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The protected header has invalid values.");
	}
	if (value.v !== 1) {
		throw new CryptoError("UNSUPPORTED_VERSION", "The envelope version is unsupported.");
	}
	const header: ProtectedHeader = {
		v: 1,
		cipher: value.cipher,
		provider: value.provider,
		key: value.key,
		wrap: value.wrap,
	};
	validateHeader(header);
	if (encodeProtectedHeader(header) !== segment) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The protected header is not canonical.");
	}
	return Object.freeze(header);
}

function maxBase64urlCharacters(byteLength: number): number {
	const completeTriples = Math.floor(byteLength / 3);
	const remainder = byteLength % 3;
	const trailing = remainder === 0 ? 0 : remainder === 1 ? 2 : 3;
	const encoded = completeTriples * 4 + trailing;
	return Number.isSafeInteger(encoded) ? encoded : Number.MAX_SAFE_INTEGER;
}

function assertEncodedSegmentLimit(
	segment: string,
	label: string,
	maxBytes: number,
	code: "MALFORMED_ENVELOPE" | "LIMIT_EXCEEDED" = "MALFORMED_ENVELOPE",
): void {
	if (segment.length > maxBase64urlCharacters(maxBytes)) {
		throw new CryptoError(code, `The ${label} segment exceeds its configured limit.`);
	}
}

function maximumEnvelopeCharacters(maxPayloadBytes: number): number {
	const parts = [
		ENVELOPE_PREFIX.length,
		5,
		MAX_PROTECTED_SEGMENT_CHARACTERS,
		maxBase64urlCharacters(MAX_WRAPPED_KEY_BYTES),
		maxBase64urlCharacters(MAX_NONCE_BYTES),
		maxBase64urlCharacters(maxPayloadBytes),
		maxBase64urlCharacters(MAX_TAG_BYTES),
	];
	let total = 0;
	for (const part of parts) {
		if (part > Number.MAX_SAFE_INTEGER - total) return Number.MAX_SAFE_INTEGER;
		total += part;
	}
	return total;
}

function splitEnvelope(envelope: string): readonly string[] {
	const parts: string[] = [];
	let start = 0;
	for (let separator = 0; separator < 5; separator += 1) {
		const next = envelope.indexOf(".", start);
		if (next === -1) {
			throw new CryptoError("MALFORMED_ENVELOPE", "The ciphertext envelope is malformed.");
		}
		parts.push(envelope.slice(start, next));
		start = next + 1;
	}
	if (envelope.indexOf(".", start) !== -1) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The ciphertext envelope is malformed.");
	}
	parts.push(envelope.slice(start));
	return parts;
}

export function serializeEnvelope(input: ParsedEnvelope): string {
	return [
		ENVELOPE_PREFIX,
		input.protectedSegment,
		base64url(input.wrappedKey),
		base64url(input.nonce),
		base64url(input.ciphertext),
		base64url(input.tag),
	].join(".");
}

export function parseEnvelope(envelope: string, maxPayloadBytes: number): ParsedEnvelope {
	if (typeof envelope !== "string" || envelope.length === 0) {
		throw new CryptoError("INVALID_ARGUMENT", "A nonempty ciphertext envelope is required.");
	}
	if (envelope.length > maximumEnvelopeCharacters(maxPayloadBytes)) {
		throw new CryptoError(
			"LIMIT_EXCEEDED",
			"The ciphertext envelope exceeds the configured limit.",
		);
	}
	const parts = splitEnvelope(envelope);
	if (parts.length === 6 && /^nmc\d+$/u.test(parts[0] ?? "") && parts[0] !== ENVELOPE_PREFIX) {
		throw new CryptoError("UNSUPPORTED_VERSION", "The envelope version is unsupported.");
	}
	if (parts.length !== 6 || parts[0] !== ENVELOPE_PREFIX) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The ciphertext envelope is malformed.");
	}
	const protectedSegment = parts[1];
	if (
		protectedSegment === undefined ||
		protectedSegment.length > MAX_PROTECTED_SEGMENT_CHARACTERS
	) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The protected header is malformed.");
	}
	const wrappedKeySegment = parts[2];
	const nonceSegment = parts[3];
	const ciphertextSegment = parts[4];
	const tagSegment = parts[5];
	if (
		wrappedKeySegment === undefined ||
		nonceSegment === undefined ||
		ciphertextSegment === undefined ||
		tagSegment === undefined
	) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The ciphertext envelope is malformed.");
	}
	assertEncodedSegmentLimit(wrappedKeySegment, "wrapped key", MAX_WRAPPED_KEY_BYTES);
	assertEncodedSegmentLimit(nonceSegment, "nonce", MAX_NONCE_BYTES);
	assertEncodedSegmentLimit(ciphertextSegment, "ciphertext", maxPayloadBytes, "LIMIT_EXCEEDED");
	assertEncodedSegmentLimit(tagSegment, "authentication tag", MAX_TAG_BYTES);
	const wrappedKey = parseBase64url(wrappedKeySegment, "wrapped key");
	if (wrappedKey.byteLength === 0 || wrappedKey.byteLength > MAX_WRAPPED_KEY_BYTES) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The wrapped key has an invalid size.");
	}
	const ciphertext = parseBase64url(ciphertextSegment, "ciphertext");
	if (ciphertext.byteLength > maxPayloadBytes) {
		throw new CryptoError("LIMIT_EXCEEDED", "The ciphertext exceeds the configured limit.");
	}
	return Object.freeze({
		protectedSegment,
		header: parseHeader(protectedSegment),
		wrappedKey,
		nonce: parseBase64url(nonceSegment, "nonce"),
		ciphertext,
		tag: parseBase64url(tagSegment, "authentication tag"),
	});
}

export function envelopeInfo(parsed: ParsedEnvelope): CipherEnvelopeInfo {
	return Object.freeze({
		version: 1,
		cipher: parsed.header.cipher,
		provider: parsed.header.provider,
		keyReference: parsed.header.key,
		wrappingAlgorithm: parsed.header.wrap,
		ciphertextBytes: parsed.ciphertext.byteLength,
		authenticated: false,
	});
}
