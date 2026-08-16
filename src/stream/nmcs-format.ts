import { createSecretKey, createHash, randomBytes, KeyObject } from "node:crypto";
import { aadBytes, decodeUtf8, frame, utf8 } from "../core/encoding.js";
import { CryptoError } from "../core/errors.js";
import type { CipherAad } from "../core/types.js";
import { hkdfSha256 } from "../keys/hkdf.js";
import {
	decodeKeyWrapRecordSequence,
	encodeKeyWrapRecords,
	type KeyWrapRecord,
} from "../keys/key-wrap-record.js";

/** Magic prefix of the chunked stream container. */
export const NMCS_MAGIC = "nmcs";
/** Suite identifier: AES-256-GCM chunks with an HKDF-SHA256 key schedule. */
export const NMCS_SUITE_AES256GCM_HKDF_SHA256 = 0x01;
/** Default plaintext chunk size exponent (2^20 = 1 MiB). */
export const NMCS_DEFAULT_CHUNK_SIZE_LOG2 = 20;
/** Fixed on-the-wire header size, including its authentication tag. */
export const NMCS_HEADER_BYTES = 512;

/** Authenticated header content: everything the header tag covers. */
export const HEADER_CONTENT_BYTES = 496;
export const TAG_BYTES = 16;
export const CHUNK_LENGTH_PREFIX_BYTES = 4;
/** Per-chunk framing overhead: the length prefix plus the AEAD tag. */
export const CHUNK_OVERHEAD_BYTES = CHUNK_LENGTH_PREFIX_BYTES + TAG_BYTES;

export const NMCS_VERSION = 0x01;
export const MIN_CHUNK_SIZE_LOG2 = 16;
/** Largest exponent the wire format can express. Requires an explicit opt-in on both sides. */
export const MAX_CHUNK_SIZE_LOG2 = 26;
/**
 * Default policy ceiling, applied symmetrically to sealing and opening so the library
 * never writes an object it would refuse to read back.
 */
export const DEFAULT_MAX_CHUNK_SIZE_LOG2 = 24;
/**
 * Exclusive upper bound on the chunk index: the policy caps an object at 2^20
 * chunks, so valid indices are `0 .. MAX_CHUNK_INDEX - 1`. The u32 index field
 * bounds it at 2^32 regardless.
 */
export const MAX_CHUNK_INDEX = 0x10_0000;

const FILE_ID_BYTES = 16;
const FLAG_WRAP_RECORDS = 0b0000_0001;
const FLAG_PLAINTEXT_LENGTH = 0b0000_0010;
const KNOWN_FLAGS = FLAG_WRAP_RECORDS | FLAG_PLAINTEXT_LENGTH;
const UNDECLARED_LENGTH = 0xffff_ffff_ffff_ffffn;

/** Matches a lone surrogate: a valid pair encodes as one non-surrogate code point. */
const LONE_SURROGATE = /\p{Surrogate}/u;

const MAGIC_BYTES = utf8(NMCS_MAGIC);
const HDR_INFO_LABEL = "nmcs/v1/hdr";
const CHUNK_INFO_LABEL = "nmcs/v1/chunk";
const AES_KEY_BYTES = 32;
const NONCE_BYTES = 12;
const NONCE_PREFIX_BYTES = 7;
const HDR_OKM_BYTES = AES_KEY_BYTES + NONCE_BYTES;
const CHUNK_OKM_BYTES = AES_KEY_BYTES + NONCE_PREFIX_BYTES;

// Fixed field offsets inside the header content.
const OFF_VERSION = 4;
const OFF_SUITE = 5;
const OFF_FLAGS = 6;
const OFF_CHUNK_LOG2 = 7;
const OFF_FILE_ID = 8;
const OFF_PLAINTEXT_LENGTH = 24;
const OFF_KEY_REF_LENGTH = 32;
const OFF_CONTEXT_AAD_LENGTH = 34;
const OFF_WRAP_COUNT = 36;
const OFF_VARIABLE = 38;

export interface ChunkedHeaderInfo {
	readonly version: 1;
	readonly suite: number;
	readonly chunkSize: number;
	readonly fileId: Uint8Array;
	readonly keyReference: string;
	readonly contextAad: Uint8Array;
	readonly wrapRecords: readonly KeyWrapRecord[];
	readonly plaintextLength?: number;
	readonly headerBytes: number;
	readonly authenticated: false;
}

export interface HeaderFields {
	readonly chunkSizeLog2: number;
	readonly fileId: Uint8Array;
	readonly keyReference: string;
	readonly contextAad: Uint8Array;
	readonly wrapRecords: readonly KeyWrapRecord[];
	readonly plaintextLength?: number;
}

/**
 * Validate a chunk-size exponent against the format range and a policy ceiling.
 *
 * `ceiling` defaults to the widest the format can express because the pure size helpers
 * allocate nothing; the seal and open paths pass {@link DEFAULT_MAX_CHUNK_SIZE_LOG2}
 * unless the caller opts in to a larger one on *both* sides.
 */
export function assertChunkSizeLog2(value: number, ceiling: number = MAX_CHUNK_SIZE_LOG2): number {
	if (!Number.isInteger(value) || value < MIN_CHUNK_SIZE_LOG2 || value > MAX_CHUNK_SIZE_LOG2) {
		throw new CryptoError("INVALID_ARGUMENT", "The chunk size exponent is out of range.");
	}
	if (value > ceiling) {
		throw new CryptoError("LIMIT_EXCEEDED", "The chunk size exponent exceeds the limit.");
	}
	return value;
}

/** Validate an opt-in chunk-size ceiling supplied by a caller. */
export function assertChunkSizeCeiling(value: number | undefined): number {
	if (value === undefined) return DEFAULT_MAX_CHUNK_SIZE_LOG2;
	if (!Number.isInteger(value) || value < MIN_CHUNK_SIZE_LOG2 || value > MAX_CHUNK_SIZE_LOG2) {
		throw new CryptoError("INVALID_ARGUMENT", "The chunk size limit is out of range.");
	}
	return value;
}

/** Validate an optional byte budget. `NaN` and friends must never disable a bound. */
export function assertByteLimit(value: number | undefined): number | undefined {
	if (value === undefined) return undefined;
	if (!Number.isSafeInteger(value) || value < 0) {
		throw new CryptoError("INVALID_ARGUMENT", "The byte limit must be a non-negative integer.");
	}
	return value;
}

export function normalizeStreamKey(key: KeyObject | Uint8Array): KeyObject {
	if (key instanceof KeyObject) {
		if (key.type !== "secret" || key.symmetricKeySize !== AES_KEY_BYTES) {
			throw new CryptoError("INVALID_KEY", "A chunked stream key must contain 32 bytes.");
		}
		return key;
	}
	if (!(key instanceof Uint8Array) || key.byteLength !== AES_KEY_BYTES) {
		throw new CryptoError("INVALID_KEY", "A chunked stream key must contain 32 bytes.");
	}
	const copy = Buffer.from(key);
	try {
		return createSecretKey(copy);
	} finally {
		copy.fill(0);
	}
}

/**
 * Canonical form of a header key reference. Lone surrogates are rejected because UTF-8
 * encoding would silently fold them onto U+FFFD, collapsing distinct references onto one
 * and breaking the encode/decode round trip.
 */
function isCanonicalKeyReference(keyReference: string): boolean {
	return (
		typeof keyReference === "string" &&
		keyReference.length > 0 &&
		keyReference.trim() === keyReference &&
		// A lone surrogate would be folded onto U+FFFD by UTF-8 encoding.
		!LONE_SURROGATE.test(keyReference) &&
		!/\p{Cc}/u.test(keyReference)
	);
}

function assertKeyReference(keyReference: string): Uint8Array {
	if (!isCanonicalKeyReference(keyReference)) {
		throw new CryptoError("INVALID_ARGUMENT", "The key reference is invalid.");
	}
	const bytes = utf8(keyReference);
	if (bytes.byteLength > 0xffff) {
		throw new CryptoError("LIMIT_EXCEEDED", "The key reference is too long.");
	}
	return bytes;
}

/** Decode header text, mapping any UTF-8 failure onto a parsing error. */
function decodeHeaderText(bytes: Uint8Array): string {
	try {
		return decodeUtf8(bytes);
	} catch (error: unknown) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream header is malformed.", {
			cause: error,
		});
	}
}

/** Build the 496-byte authenticated header content. Padding is verified on parse. */
export function encodeHeaderContent(fields: HeaderFields): Uint8Array {
	const keyReference = assertKeyReference(fields.keyReference);
	const contextAad = fields.contextAad;
	const wrapRecords = fields.wrapRecords;
	const encodedRecords = wrapRecords.length > 0 ? encodeKeyWrapRecords(wrapRecords) : undefined;
	if (contextAad.byteLength > 0xffff) {
		throw new CryptoError("LIMIT_EXCEEDED", "The context associated data is too long.");
	}

	const content = new Uint8Array(HEADER_CONTENT_BYTES);
	const view = new DataView(content.buffer);
	content.set(MAGIC_BYTES, 0);
	content[OFF_VERSION] = NMCS_VERSION;
	content[OFF_SUITE] = NMCS_SUITE_AES256GCM_HKDF_SHA256;
	content[OFF_FLAGS] =
		(encodedRecords === undefined ? 0 : FLAG_WRAP_RECORDS) |
		(fields.plaintextLength === undefined ? 0 : FLAG_PLAINTEXT_LENGTH);
	content[OFF_CHUNK_LOG2] = fields.chunkSizeLog2;
	content.set(fields.fileId, OFF_FILE_ID);
	view.setBigUint64(
		OFF_PLAINTEXT_LENGTH,
		fields.plaintextLength === undefined ? UNDECLARED_LENGTH : BigInt(fields.plaintextLength),
		false,
	);
	view.setUint16(OFF_KEY_REF_LENGTH, keyReference.byteLength, false);
	view.setUint16(OFF_CONTEXT_AAD_LENGTH, contextAad.byteLength, false);
	view.setUint16(OFF_WRAP_COUNT, wrapRecords.length, false);

	// The record list carries its own u16 count; only the records themselves are appended
	// so the header stays a single canonical encoding of the same information.
	const recordBody = encodedRecords?.subarray(2) ?? new Uint8Array();
	const variable =
		OFF_VARIABLE + keyReference.byteLength + contextAad.byteLength + recordBody.byteLength;
	if (variable > HEADER_CONTENT_BYTES) {
		throw new CryptoError("LIMIT_EXCEEDED", "The chunked stream header is too large.");
	}
	let offset = OFF_VARIABLE;
	content.set(keyReference, offset);
	offset += keyReference.byteLength;
	content.set(contextAad, offset);
	offset += contextAad.byteLength;
	content.set(recordBody, offset);
	return content;
}

export function decodeHeaderContent(content: Uint8Array, maxChunkSizeLog2: number): HeaderFields {
	if (content.byteLength !== HEADER_CONTENT_BYTES) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream header is malformed.");
	}
	for (let index = 0; index < MAGIC_BYTES.byteLength; index += 1) {
		if (content[index] !== MAGIC_BYTES[index]) {
			throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream magic is invalid.");
		}
	}
	if (content[OFF_VERSION] !== NMCS_VERSION) {
		throw new CryptoError("UNSUPPORTED_VERSION", "The chunked stream version is unsupported.");
	}
	if (content[OFF_SUITE] !== NMCS_SUITE_AES256GCM_HKDF_SHA256) {
		throw new CryptoError("UNSUPPORTED_CIPHER", "The chunked stream suite is unsupported.");
	}
	const flags = content[OFF_FLAGS] ?? 0;
	if ((flags & ~KNOWN_FLAGS) !== 0) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream header sets reserved flags.");
	}
	const chunkSizeLog2 = content[OFF_CHUNK_LOG2] ?? 0;
	if (chunkSizeLog2 < MIN_CHUNK_SIZE_LOG2 || chunkSizeLog2 > MAX_CHUNK_SIZE_LOG2) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream chunk size is invalid.");
	}
	if (chunkSizeLog2 > maxChunkSizeLog2) {
		throw new CryptoError("LIMIT_EXCEEDED", "The chunked stream chunk size exceeds the limit.");
	}

	const view = new DataView(content.buffer, content.byteOffset, content.byteLength);
	const fileId = new Uint8Array(content.subarray(OFF_FILE_ID, OFF_FILE_ID + FILE_ID_BYTES));
	const rawLength = view.getBigUint64(OFF_PLAINTEXT_LENGTH, false);
	const declared = (flags & FLAG_PLAINTEXT_LENGTH) !== 0;
	if (!declared && rawLength !== UNDECLARED_LENGTH) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream length flag is inconsistent.");
	}
	if (declared && rawLength > BigInt(Number.MAX_SAFE_INTEGER)) {
		throw new CryptoError("LIMIT_EXCEEDED", "The chunked stream declares an unusable length.");
	}
	const keyReferenceLength = view.getUint16(OFF_KEY_REF_LENGTH, false);
	const contextAadLength = view.getUint16(OFF_CONTEXT_AAD_LENGTH, false);
	const wrapCount = view.getUint16(OFF_WRAP_COUNT, false);
	if (wrapCount > 0 !== ((flags & FLAG_WRAP_RECORDS) !== 0)) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream wrap flag is inconsistent.");
	}
	if (keyReferenceLength === 0) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream key reference is missing.");
	}

	let offset = OFF_VARIABLE;
	if (offset + keyReferenceLength + contextAadLength > HEADER_CONTENT_BYTES) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream header is malformed.");
	}
	const keyReference = decodeHeaderText(content.subarray(offset, offset + keyReferenceLength));
	if (!isCanonicalKeyReference(keyReference)) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream key reference is invalid.");
	}
	offset += keyReferenceLength;
	const contextAad = new Uint8Array(content.subarray(offset, offset + contextAadLength));
	offset += contextAadLength;

	let wrapRecords: readonly KeyWrapRecord[] = [];
	if (wrapCount > 0) {
		// Records are self-delimiting and the count is already authenticated by the header tag.
		const decoded = decodeKeyWrapRecordSequence(content, offset, wrapCount);
		wrapRecords = decoded.records;
		offset = decoded.end;
	}

	for (let index = offset; index < HEADER_CONTENT_BYTES; index += 1) {
		if (content[index] !== 0) {
			throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream header padding is not zero.");
		}
	}

	return {
		chunkSizeLog2,
		fileId,
		keyReference,
		contextAad,
		wrapRecords,
		...(declared ? { plaintextLength: Number(rawLength) } : {}),
	};
}

export interface StreamKeySchedule {
	readonly headerKey: KeyObject;
	readonly headerNonce: Uint8Array;
}

/** Header-tag key schedule: bound to the data key and the per-object file id. */
export function deriveHeaderSchedule(key: KeyObject, fileId: Uint8Array): StreamKeySchedule {
	// `export()` already hands back a private copy; do not clone it again — every extra
	// copy of the data key is one more buffer that has to be wiped.
	const ikm = key.export();
	let okm: Uint8Array | undefined;
	try {
		okm = hkdfSha256(ikm, fileId, frame(utf8(HDR_INFO_LABEL)), HDR_OKM_BYTES);
		return {
			headerKey: createSecretKey(okm.subarray(0, AES_KEY_BYTES)),
			headerNonce: new Uint8Array(okm.subarray(AES_KEY_BYTES, HDR_OKM_BYTES)),
		};
	} finally {
		ikm.fill(0);
		okm?.fill(0);
	}
}

export interface ChunkKeySchedule {
	readonly chunkKey: KeyObject;
	readonly noncePrefix: Uint8Array;
}

/**
 * Chunk key schedule. The whole authenticated header is hashed into the HKDF info, so
 * any header change — key reference, chunk size, context, wrap records — yields a
 * different chunk key and every chunk fails to authenticate.
 */
export function deriveChunkSchedule(key: KeyObject, headerContent: Uint8Array): ChunkKeySchedule {
	const fileId = headerContent.subarray(OFF_FILE_ID, OFF_FILE_ID + FILE_ID_BYTES);
	const headerHash = new Uint8Array(createHash("sha256").update(headerContent).digest());
	const ikm = key.export();
	let okm: Uint8Array | undefined;
	try {
		okm = hkdfSha256(
			ikm,
			fileId,
			frame(utf8(CHUNK_INFO_LABEL), Uint8Array.of(NMCS_SUITE_AES256GCM_HKDF_SHA256), headerHash),
			CHUNK_OKM_BYTES,
		);
		return {
			chunkKey: createSecretKey(okm.subarray(0, AES_KEY_BYTES)),
			noncePrefix: new Uint8Array(okm.subarray(AES_KEY_BYTES, CHUNK_OKM_BYTES)),
		};
	} finally {
		ikm.fill(0);
		okm?.fill(0);
	}
}

/** `noncePrefix(7) ‖ u32BE(index) ‖ final(1)` — no counter is ever persisted. */
export function chunkNonce(noncePrefix: Uint8Array, index: number, final: boolean): Uint8Array {
	const nonce = new Uint8Array(NONCE_BYTES);
	nonce.set(noncePrefix, 0);
	new DataView(nonce.buffer).setUint32(NONCE_PREFIX_BYTES, index, false);
	nonce[NONCE_BYTES - 1] = final ? 0x01 : 0x00;
	return nonce;
}

function u32(value: number): Uint8Array {
	const bytes = new Uint8Array(4);
	new DataView(bytes.buffer).setUint32(0, value, false);
	return bytes;
}

/** Per-chunk AAD authenticates the framing the parser has not yet trusted. */
export function chunkAad(index: number, final: boolean, ciphertextLength: number): Uint8Array {
	return frame(u32(index), Uint8Array.of(final ? 0x01 : 0x00), u32(ciphertextLength));
}

export function generateFileId(): Uint8Array {
	return new Uint8Array(randomBytes(FILE_ID_BYTES));
}

export function assertFileId(fileId: Uint8Array): Uint8Array {
	if (!(fileId instanceof Uint8Array) || fileId.byteLength !== FILE_ID_BYTES) {
		throw new CryptoError("INVALID_ARGUMENT", "The file identifier must be 16 bytes.");
	}
	return new Uint8Array(fileId);
}

/**
 * Test-only override for the per-object file identifier.
 *
 * The file identifier is the *sole* source of per-object randomness in the key schedule:
 * reusing one under the same data key repeats the chunk key and nonce prefix, which
 * reveals the XOR of two plaintexts and leaks the header GMAC subkey. It is therefore
 * deliberately unreachable from {@link ChunkedSealOptions}; only `@nestm/crypto/testing`
 * can attach it, and only to freeze format vectors.
 *
 * @internal
 */
export const FILE_ID_OVERRIDE: unique symbol = Symbol("@nestm/crypto/nmcs.fileId");

/** Read a test-seam file identifier, if one was attached by `@nestm/crypto/testing`. */
export function readFileIdOverride(options: object): Uint8Array | undefined {
	const value = (options as Record<symbol, unknown>)[FILE_ID_OVERRIDE];
	if (value === undefined) return undefined;
	return assertFileId(value as Uint8Array);
}

export function contextAadBytes(aad?: CipherAad): Uint8Array {
	return aadBytes(aad);
}

export function headerInfo(fields: HeaderFields): ChunkedHeaderInfo {
	return Object.freeze({
		version: 1,
		suite: NMCS_SUITE_AES256GCM_HKDF_SHA256,
		chunkSize: 2 ** fields.chunkSizeLog2,
		fileId: fields.fileId,
		keyReference: fields.keyReference,
		contextAad: fields.contextAad,
		wrapRecords: fields.wrapRecords,
		...(fields.plaintextLength === undefined ? {} : { plaintextLength: fields.plaintextLength }),
		headerBytes: NMCS_HEADER_BYTES,
		authenticated: false,
	}) satisfies ChunkedHeaderInfo;
}
