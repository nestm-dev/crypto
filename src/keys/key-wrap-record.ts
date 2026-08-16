import {
	createCipheriv,
	createDecipheriv,
	createSecretKey,
	randomBytes,
	KeyObject,
} from "node:crypto";
import { aadBytes, decodeUtf8, frame, utf8 } from "../core/encoding.js";
import { authenticationFailed, CryptoError } from "../core/errors.js";
import type { CipherAad } from "../core/types.js";
import { openKeyFrom, sealTo, SEAL_X25519_HKDF_SHA256_A256GCM, type SealOptions } from "./seal.js";
import type { X25519PrivateKeyInput, X25519PublicKeyInput } from "./x25519.js";

/** AES-256-GCM key wrapping under a shared secret KEK. */
export const KEY_WRAP_A256GCMKW = "A256GCMKW";
/** Recipient-addressed key wrapping to an X25519 public key. */
export const KEY_WRAP_SEAL_X25519 = SEAL_X25519_HKDF_SHA256_A256GCM;

/** Matches a lone surrogate: a valid pair encodes as one non-surrogate code point. */
const LONE_SURROGATE = /\p{Surrogate}/u;

const RECORD_VERSION = 0x01;
const RECIPIENT_TYPE_SECRET = 0x01;
const RECIPIENT_TYPE_X25519 = 0x02;
const RECORD_HEADER_BYTES = 6;
const MAX_ALGORITHM_BYTES = 64;
const MAX_RECIPIENT_ID_BYTES = 255;
const MAX_WRAPPED_BYTES = 65_535;
/** One ceiling for both directions: the encoder never writes a list the decoder rejects. */
const MAX_RECORDS = 64;
const AAD_LABEL = "nmc/keywrap/v1";

const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const WRAP_VERSION = 0x01;
const MIN_KEY_BYTES = 16;
const MAX_KEY_BYTES = 512;

export type KeyWrapRecipientType = "secret" | "x25519";

export interface KeyWrapRecord {
	readonly version: 1;
	readonly algorithm: string;
	readonly recipientType: KeyWrapRecipientType;
	/** Authenticated recipient identity. A record cannot be moved between recipients. */
	readonly recipientId: string;
	readonly wrapped: Uint8Array;
}

export interface KeyWrapSecretOptions {
	readonly recipientId: string;
	readonly aad?: CipherAad;
}

export interface KeyWrapRecipientOptions {
	readonly recipientId: string;
	/** Bound into the seal key schedule. Must match at unwrap. */
	readonly info?: CipherAad;
	/** Bound as additional associated data. Must match at unwrap. */
	readonly aad?: CipherAad;
}

export interface KeyWrapUnwrapSecretOptions {
	readonly aad?: CipherAad;
	/** Require the recovered key to be exactly this many bytes. */
	readonly expectedKeyBytes?: number;
}

export interface KeyWrapUnwrapRecipientOptions {
	readonly info?: CipherAad;
	readonly aad?: CipherAad;
	/** Require the recovered key to be exactly this many bytes. */
	readonly expectedKeyBytes?: number;
}

export interface KeyWrapRecordMatch {
	readonly recipientType: KeyWrapRecipientType;
	readonly recipientId: string;
}

function typeByte(recipientType: KeyWrapRecipientType): number {
	return recipientType === "secret" ? RECIPIENT_TYPE_SECRET : RECIPIENT_TYPE_X25519;
}

/**
 * Recipient identifiers are the binding between a wrap and the principal it is for, so
 * they must be present and canonical. An empty identifier would bind nothing, and a lone
 * surrogate would be folded onto U+FFFD by UTF-8 encoding — collapsing distinct
 * recipients onto one identifier and breaking the encode/decode round trip.
 */
function assertRecipientId(recipientId: string): Uint8Array {
	if (
		typeof recipientId !== "string" ||
		recipientId.length === 0 ||
		recipientId.trim() !== recipientId ||
		// A lone surrogate would be folded onto U+FFFD by UTF-8 encoding.
		LONE_SURROGATE.test(recipientId)
	) {
		throw new CryptoError("INVALID_ARGUMENT", "The key-wrap recipient identifier is invalid.");
	}
	if (/\p{Cc}/u.test(recipientId)) {
		throw new CryptoError("INVALID_ARGUMENT", "The key-wrap recipient identifier is invalid.");
	}
	const bytes = utf8(recipientId);
	if (bytes.byteLength > MAX_RECIPIENT_ID_BYTES) {
		throw new CryptoError("LIMIT_EXCEEDED", "The key-wrap recipient identifier is too long.");
	}
	return bytes;
}

/** Recipient options are mandatory: there is no unbound wrap. */
function assertRecipientOptions(options: { readonly recipientId: string } | undefined): string {
	if (typeof options !== "object" || options === null) {
		throw new CryptoError("INVALID_ARGUMENT", "Key-wrap options are required.");
	}
	assertRecipientId(options.recipientId);
	return options.recipientId;
}

function assertAlgorithm(algorithm: string): Uint8Array {
	if (
		typeof algorithm !== "string" ||
		algorithm.length === 0 ||
		algorithm.trim() !== algorithm ||
		// eslint-disable-next-line no-control-regex
		!/^[\x20-\x7e]+$/u.test(algorithm)
	) {
		throw new CryptoError("INVALID_ARGUMENT", "The key-wrap algorithm is invalid.");
	}
	const bytes = utf8(algorithm);
	if (bytes.byteLength > MAX_ALGORITHM_BYTES) {
		throw new CryptoError("LIMIT_EXCEEDED", "The key-wrap algorithm is too long.");
	}
	return bytes;
}

/**
 * Identity-binding associated data. Both wrap flavours authenticate the algorithm,
 * recipient type, and recipient identifier, so a record produced for one recipient
 * cannot be replayed as a record for another even under the same wrapping key.
 */
function recordAad(
	algorithm: string,
	recipientType: KeyWrapRecipientType,
	recipientId: string,
	callerAad?: CipherAad,
): Uint8Array {
	return frame(
		utf8(AAD_LABEL),
		utf8(algorithm),
		Uint8Array.of(typeByte(recipientType)),
		utf8(recipientId),
		aadBytes(callerAad),
	);
}

function keyBytes(key: KeyObject | Uint8Array): { bytes: Uint8Array; owned: boolean } {
	if (key instanceof KeyObject) {
		if (key.type !== "secret") {
			throw new CryptoError("INVALID_ARGUMENT", "Only a secret key can be wrapped.");
		}
		return { bytes: new Uint8Array(key.export()), owned: true };
	}
	if (key instanceof Uint8Array) {
		return { bytes: key, owned: false };
	}
	throw new CryptoError("INVALID_ARGUMENT", "The wrapped key must be bytes or a secret key.");
}

function assertKeyLength(bytes: Uint8Array): void {
	if (bytes.byteLength < MIN_KEY_BYTES || bytes.byteLength > MAX_KEY_BYTES) {
		throw new CryptoError("INVALID_KEY", "The wrapped key length is out of range.");
	}
}

/**
 * Length-check a *recovered* key. An attacker who mints a record cannot be trusted to
 * have wrapped a key of a sane size, so the range is always enforced and callers that
 * know the exact size they expect can pin it.
 */
function assertRecoveredKeyLength(byteLength: number, expected: number | undefined): void {
	if (byteLength < MIN_KEY_BYTES || byteLength > MAX_KEY_BYTES) {
		throw new CryptoError("INVALID_KEY", "The unwrapped key length is out of range.");
	}
	if (expected === undefined) return;
	if (!Number.isInteger(expected) || expected < MIN_KEY_BYTES || expected > MAX_KEY_BYTES) {
		throw new CryptoError("INVALID_ARGUMENT", "The expected key length is out of range.");
	}
	if (byteLength !== expected) {
		throw new CryptoError("INVALID_KEY", "The unwrapped key is not the expected length.");
	}
}

function normalizeKek(kek: KeyObject | Uint8Array): KeyObject {
	if (kek instanceof KeyObject) {
		if (kek.type !== "secret" || kek.symmetricKeySize !== 32) {
			throw new CryptoError("INVALID_KEY", "A key-wrap KEK must contain 32 bytes.");
		}
		return kek;
	}
	if (!(kek instanceof Uint8Array) || kek.byteLength !== 32) {
		throw new CryptoError("INVALID_KEY", "A key-wrap KEK must contain 32 bytes.");
	}
	const copy = Buffer.from(kek);
	try {
		return createSecretKey(copy);
	} finally {
		copy.fill(0);
	}
}

/** Wrap a key under a shared 32-byte KEK. Wire: `0x01 ‖ nonce(12) ‖ ciphertext ‖ tag(16)`. */
export function wrapKeyWithSecret(
	kek: KeyObject | Uint8Array,
	key: KeyObject | Uint8Array,
	options: KeyWrapSecretOptions,
): KeyWrapRecord {
	const wrappingKey = normalizeKek(kek);
	const recipientId = assertRecipientOptions(options);
	const { bytes: raw, owned } = keyBytes(key);
	try {
		assertKeyLength(raw);
		const nonce = randomBytes(NONCE_BYTES);
		const aad = recordAad(KEY_WRAP_A256GCMKW, "secret", recipientId, options.aad);
		const cipher = createCipheriv("aes-256-gcm", wrappingKey, nonce, {
			authTagLength: TAG_BYTES,
		});
		cipher.setAAD(aad, { plaintextLength: raw.byteLength });
		const ciphertext = Buffer.concat([cipher.update(raw), cipher.final()]);
		try {
			const wrapped = new Uint8Array(1 + NONCE_BYTES + ciphertext.byteLength + TAG_BYTES);
			wrapped[0] = WRAP_VERSION;
			wrapped.set(nonce, 1);
			wrapped.set(ciphertext, 1 + NONCE_BYTES);
			wrapped.set(cipher.getAuthTag(), 1 + NONCE_BYTES + ciphertext.byteLength);
			return Object.freeze({
				version: 1,
				algorithm: KEY_WRAP_A256GCMKW,
				recipientType: "secret",
				recipientId,
				wrapped,
			}) satisfies KeyWrapRecord;
		} finally {
			ciphertext.fill(0);
		}
	} catch (error: unknown) {
		if (error instanceof CryptoError) throw error;
		throw new CryptoError("CIPHER_FAILURE", "Key wrapping failed.", { cause: error });
	} finally {
		if (owned) raw.fill(0);
	}
}

/** Unwrap a `secret` record produced by {@link wrapKeyWithSecret}. */
export function unwrapKeyWithSecret(
	kek: KeyObject | Uint8Array,
	record: KeyWrapRecord,
	options?: KeyWrapUnwrapSecretOptions,
): KeyObject {
	const wrappingKey = normalizeKek(kek);
	assertRecordShape(record);
	if (record.recipientType !== "secret") {
		throw new CryptoError("INVALID_ARGUMENT", "The key-wrap record is not a secret-KEK record.");
	}
	if (record.algorithm !== KEY_WRAP_A256GCMKW) {
		throw new CryptoError("INVALID_KEY", "The key-wrap algorithm is unsupported.");
	}
	const wrapped = record.wrapped;
	if (wrapped.byteLength < 1 + NONCE_BYTES + MIN_KEY_BYTES + TAG_BYTES) {
		throw authenticationFailed();
	}
	if (wrapped[0] !== WRAP_VERSION) {
		throw new CryptoError("UNSUPPORTED_VERSION", "The key-wrap record version is unsupported.");
	}
	const nonce = wrapped.subarray(1, 1 + NONCE_BYTES);
	const ciphertext = wrapped.subarray(1 + NONCE_BYTES, wrapped.byteLength - TAG_BYTES);
	const tag = wrapped.subarray(wrapped.byteLength - TAG_BYTES);
	let first: Buffer | undefined;
	let last: Buffer | undefined;
	let raw: Buffer | undefined;
	try {
		const aad = recordAad(record.algorithm, "secret", record.recipientId, options?.aad);
		const decipher = createDecipheriv("aes-256-gcm", wrappingKey, nonce, {
			authTagLength: TAG_BYTES,
		});
		decipher.setAAD(aad, { plaintextLength: ciphertext.byteLength });
		decipher.setAuthTag(tag);
		first = decipher.update(ciphertext);
		last = decipher.final();
		raw = Buffer.concat([first, last]);
		assertRecoveredKeyLength(raw.byteLength, options?.expectedKeyBytes);
		return createSecretKey(raw);
	} catch (error: unknown) {
		if (
			error instanceof CryptoError &&
			(error.code === "INVALID_KEY" || error.code === "INVALID_ARGUMENT")
		) {
			throw error;
		}
		throw authenticationFailed({ cause: error });
	} finally {
		first?.fill(0);
		last?.fill(0);
		raw?.fill(0);
	}
}

/** Seal a key to an X25519 public key. Wire: the `sealTo` blob, unchanged. */
export function wrapKeyToRecipient(
	publicKey: X25519PublicKeyInput,
	key: KeyObject | Uint8Array,
	options: KeyWrapRecipientOptions,
): KeyWrapRecord {
	const recipientId = assertRecipientOptions(options);
	const { bytes: raw, owned } = keyBytes(key);
	try {
		assertKeyLength(raw);
		const sealOptions: SealOptions = {
			...(options.info === undefined ? {} : { info: options.info }),
			aad: recordAad(KEY_WRAP_SEAL_X25519, "x25519", recipientId, options.aad),
		};
		return Object.freeze({
			version: 1,
			algorithm: KEY_WRAP_SEAL_X25519,
			recipientType: "x25519",
			recipientId,
			wrapped: sealTo(publicKey, raw, sealOptions),
		}) satisfies KeyWrapRecord;
	} finally {
		if (owned) raw.fill(0);
	}
}

/** Open an `x25519` record produced by {@link wrapKeyToRecipient}. */
export function unwrapKeyFromRecipient(
	privateKey: X25519PrivateKeyInput,
	record: KeyWrapRecord,
	options?: KeyWrapUnwrapRecipientOptions,
): KeyObject {
	assertRecordShape(record);
	if (record.recipientType !== "x25519") {
		throw new CryptoError("INVALID_ARGUMENT", "The key-wrap record is not a recipient record.");
	}
	if (record.algorithm !== KEY_WRAP_SEAL_X25519) {
		throw new CryptoError("INVALID_KEY", "The key-wrap algorithm is unsupported.");
	}
	const key = openKeyFrom(privateKey, record.wrapped, {
		...(options?.info === undefined ? {} : { info: options.info }),
		aad: recordAad(record.algorithm, "x25519", record.recipientId, options?.aad),
	});
	assertRecoveredKeyLength(key.symmetricKeySize ?? 0, options?.expectedKeyBytes);
	return key;
}

function assertRecordShape(record: KeyWrapRecord): void {
	if (typeof record !== "object" || record === null) {
		throw new CryptoError("INVALID_ARGUMENT", "A key-wrap record is required.");
	}
	if (record.version !== 1) {
		throw new CryptoError("UNSUPPORTED_VERSION", "The key-wrap record version is unsupported.");
	}
	if (record.recipientType !== "secret" && record.recipientType !== "x25519") {
		throw new CryptoError("INVALID_ARGUMENT", "The key-wrap recipient type is invalid.");
	}
	assertAlgorithm(record.algorithm);
	assertRecipientId(record.recipientId);
	if (!(record.wrapped instanceof Uint8Array) || record.wrapped.byteLength === 0) {
		throw new CryptoError("INVALID_ARGUMENT", "The key-wrap record payload is invalid.");
	}
	if (record.wrapped.byteLength > MAX_WRAPPED_BYTES) {
		throw new CryptoError("LIMIT_EXCEEDED", "The key-wrap record payload is too large.");
	}
}

/** Serialized size of a record, without encoding it. */
export function keyWrapRecordLength(record: KeyWrapRecord): number {
	assertRecordShape(record);
	return (
		RECORD_HEADER_BYTES +
		utf8(record.algorithm).byteLength +
		utf8(record.recipientId).byteLength +
		record.wrapped.byteLength
	);
}

export function encodeKeyWrapRecord(record: KeyWrapRecord): Uint8Array {
	assertRecordShape(record);
	const algorithm = assertAlgorithm(record.algorithm);
	const recipientId = assertRecipientId(record.recipientId);
	const output = new Uint8Array(
		RECORD_HEADER_BYTES + algorithm.byteLength + recipientId.byteLength + record.wrapped.byteLength,
	);
	const view = new DataView(output.buffer);
	output[0] = RECORD_VERSION;
	output[1] = typeByte(record.recipientType);
	output[2] = algorithm.byteLength;
	output[3] = recipientId.byteLength;
	view.setUint16(4, record.wrapped.byteLength, false);
	let offset = RECORD_HEADER_BYTES;
	output.set(algorithm, offset);
	offset += algorithm.byteLength;
	output.set(recipientId, offset);
	offset += recipientId.byteLength;
	output.set(record.wrapped, offset);
	return output;
}

/** Decode record text, mapping any UTF-8 failure onto a parsing error. */
function decodeRecordText(bytes: Uint8Array): string {
	try {
		return decodeUtf8(bytes);
	} catch (error: unknown) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The key-wrap record is malformed.", {
			cause: error,
		});
	}
}

function decodeRecordAt(bytes: Uint8Array, start: number): { record: KeyWrapRecord; end: number } {
	if (bytes.byteLength - start < RECORD_HEADER_BYTES) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The key-wrap record is truncated.");
	}
	if (bytes[start] !== RECORD_VERSION) {
		throw new CryptoError("UNSUPPORTED_VERSION", "The key-wrap record version is unsupported.");
	}
	const rawType = bytes[start + 1];
	if (rawType !== RECIPIENT_TYPE_SECRET && rawType !== RECIPIENT_TYPE_X25519) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The key-wrap recipient type is unknown.");
	}
	const algorithmLength = bytes[start + 2] ?? 0;
	const recipientIdLength = bytes[start + 3] ?? 0;
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	const wrappedLength = view.getUint16(start + 4, false);
	if (algorithmLength === 0 || wrappedLength === 0) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The key-wrap record is malformed.");
	}
	if (recipientIdLength === 0) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The key-wrap recipient identifier is missing.");
	}
	const end = start + RECORD_HEADER_BYTES + algorithmLength + recipientIdLength + wrappedLength;
	if (end > bytes.byteLength) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The key-wrap record is truncated.");
	}
	let offset = start + RECORD_HEADER_BYTES;
	// Hostile wire bytes are a parsing failure, not a decryption failure.
	const algorithm = decodeRecordText(bytes.subarray(offset, offset + algorithmLength));
	offset += algorithmLength;
	const recipientId = decodeRecordText(bytes.subarray(offset, offset + recipientIdLength));
	offset += recipientIdLength;
	const wrapped = new Uint8Array(bytes.subarray(offset, offset + wrappedLength));
	const record: KeyWrapRecord = Object.freeze({
		version: 1,
		algorithm,
		recipientType: rawType === RECIPIENT_TYPE_SECRET ? "secret" : "x25519",
		recipientId,
		wrapped,
	});
	try {
		assertRecordShape(record);
	} catch (error: unknown) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The key-wrap record is malformed.", {
			cause: error,
		});
	}
	return { record, end };
}

/**
 * Decode exactly `count` records starting at `start`, returning the end offset.
 *
 * @internal Used by container formats that carry records inline and already know the
 * count from their own header. Not part of the published surface.
 */
export function decodeKeyWrapRecordSequence(
	bytes: Uint8Array,
	start: number,
	count: number,
): { records: readonly KeyWrapRecord[]; end: number } {
	if (count > MAX_RECORDS) {
		throw new CryptoError("MALFORMED_ENVELOPE", "Too many key-wrap records.");
	}
	const records: KeyWrapRecord[] = [];
	let offset = start;
	for (let index = 0; index < count; index += 1) {
		const decoded = decodeRecordAt(bytes, offset);
		records.push(decoded.record);
		offset = decoded.end;
	}
	return { records: Object.freeze(records), end: offset };
}

export function decodeKeyWrapRecord(bytes: Uint8Array): KeyWrapRecord {
	if (!(bytes instanceof Uint8Array)) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The key-wrap record must be bytes.");
	}
	const { record, end } = decodeRecordAt(bytes, 0);
	if (end !== bytes.byteLength) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The key-wrap record has trailing bytes.");
	}
	return record;
}

export function encodeKeyWrapRecords(records: readonly KeyWrapRecord[]): Uint8Array {
	if (!Array.isArray(records)) {
		throw new CryptoError("INVALID_ARGUMENT", "A key-wrap record list is required.");
	}
	if (records.length > MAX_RECORDS) {
		throw new CryptoError("LIMIT_EXCEEDED", "Too many key-wrap records.");
	}
	const encoded = records.map((record) => encodeKeyWrapRecord(record));
	let total = 2;
	for (const record of encoded) total += record.byteLength;
	const output = new Uint8Array(total);
	new DataView(output.buffer).setUint16(0, records.length, false);
	let offset = 2;
	for (const record of encoded) {
		output.set(record, offset);
		offset += record.byteLength;
	}
	return output;
}

export function decodeKeyWrapRecords(
	bytes: Uint8Array,
	maxRecords = MAX_RECORDS,
): readonly KeyWrapRecord[] {
	if (!(bytes instanceof Uint8Array)) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The key-wrap record list must be bytes.");
	}
	if (!Number.isInteger(maxRecords) || maxRecords < 0) {
		throw new CryptoError("INVALID_ARGUMENT", "The key-wrap record limit is invalid.");
	}
	if (bytes.byteLength < 2) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The key-wrap record list is truncated.");
	}
	const count = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(0, false);
	if (count > maxRecords) {
		throw new CryptoError("LIMIT_EXCEEDED", "Too many key-wrap records.");
	}
	const records: KeyWrapRecord[] = [];
	let offset = 2;
	for (let index = 0; index < count; index += 1) {
		const { record, end } = decodeRecordAt(bytes, offset);
		records.push(record);
		offset = end;
	}
	if (offset !== bytes.byteLength) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The key-wrap record list has trailing bytes.");
	}
	return Object.freeze(records);
}

/** First record addressed to `match`, or `undefined`. Nothing is authenticated here. */
export function selectKeyWrapRecord(
	records: readonly KeyWrapRecord[],
	match: KeyWrapRecordMatch,
): KeyWrapRecord | undefined {
	if (!Array.isArray(records)) {
		throw new CryptoError("INVALID_ARGUMENT", "A key-wrap record list is required.");
	}
	return records.find(
		(record) =>
			record.recipientType === match.recipientType && record.recipientId === match.recipientId,
	);
}
