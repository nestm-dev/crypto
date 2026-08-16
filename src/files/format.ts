import { createHash, timingSafeEqual } from "node:crypto";
import { CryptoError } from "../core/errors.js";
import type { FileHeaderInfo } from "./types.js";

export const NMF1_MAGIC = "NMF1";
export const NMF1_VERSION = 1;
export const NMF1_SUITE_ID = 0x01;
export const NMF1_SUITE = "A256GCM-SHA256-CHUNKED";
export const NMF1_HEADER_BYTES = 52;
export const NMF1_CHUNK_BYTES = 1_048_576;
export const NMF1_DATA_FRAME_HEADER_BYTES = 12;
export const NMF1_FINAL_FRAME_HEADER_BYTES = 16;
export const NMF1_TAG_BYTES = 16;
export const NMF1_DATA_FRAME_TYPE = 0x01;
export const NMF1_FINAL_FRAME_TYPE = 0x02;
export const NMF1_MAX_DATA_FRAMES = 0xffff_ffff;
export const NMF1_FORMAT_MAX_PLAINTEXT_BYTES =
	BigInt(NMF1_MAX_DATA_FRAMES) * BigInt(NMF1_CHUNK_BYTES);
export const NMF1_EMPTY_FILE_BYTES = 84n;
export const NMF1_MAX_FILE_AAD_BYTES = 4_096;

const UINT32_MAX = 0xffff_ffff;
const UINT64_MAX = 0xffff_ffff_ffff_ffffn;
const textEncoder = new TextEncoder();
const magicBytes = textEncoder.encode(NMF1_MAGIC);
const fileAadDigestLabel = textEncoder.encode("nestm:nmf1:file-aad-digest:v1\0");
const fileKeyContextLabel = textEncoder.encode("nestm:nmf1:file-key-context:v1\0");
const frameAadLabel = textEncoder.encode("nestm:nmf1:frame-aad:v1\0");

export interface ParsedDataFrameHeader {
	readonly frameIndex: number;
	readonly plaintextLength: number;
}

export interface ParsedFinalFrameHeader {
	readonly dataFrameCount: number;
	readonly totalPlaintextLength: bigint;
}

export function isStableFileBytes(value: unknown): value is Uint8Array {
	try {
		if (!(value instanceof Uint8Array) || !ArrayBuffer.isView(value)) return false;
		const prototype: unknown = Object.getPrototypeOf(value);
		if (prototype !== Uint8Array.prototype && prototype !== Buffer.prototype) return false;
		return !(value.buffer instanceof SharedArrayBuffer) && Number.isSafeInteger(value.byteLength);
	} catch {
		return false;
	}
}

export function copyFileBytes(value: unknown, label: string): Uint8Array {
	if (!isStableFileBytes(value)) {
		throw new CryptoError("INVALID_ARGUMENT", `${label} must be bytes.`);
	}
	return new Uint8Array(value);
}

export function captureFileAad(value: unknown): Uint8Array {
	const aad = copyFileBytes(value, "File authenticated data");
	if (aad.byteLength > NMF1_MAX_FILE_AAD_BYTES) {
		aad.fill(0);
		throw new CryptoError("LIMIT_EXCEEDED", "File authenticated data exceeds the NMF1 limit.");
	}
	return aad;
}

export function concatFileBytes(...parts: readonly Uint8Array[]): Uint8Array {
	let total = 0;
	for (const part of parts) {
		if (
			!Number.isSafeInteger(part.byteLength) ||
			part.byteLength > Number.MAX_SAFE_INTEGER - total
		) {
			throw new CryptoError("LIMIT_EXCEEDED", "An NMF1 byte sequence is too large.");
		}
		total += part.byteLength;
	}
	const output = new Uint8Array(total);
	let offset = 0;
	for (const part of parts) {
		output.set(part, offset);
		offset += part.byteLength;
	}
	return output;
}

export function encodeFileLengthPrefix(bytes: Uint8Array): Uint8Array {
	if (bytes.byteLength > UINT32_MAX) {
		throw new CryptoError("LIMIT_EXCEEDED", "An NMF1 framed component is too large.");
	}
	const output = new Uint8Array(4 + bytes.byteLength);
	new DataView(output.buffer).setUint32(0, bytes.byteLength, false);
	output.set(bytes, 4);
	return output;
}

export function sha256FileBytes(bytes: Uint8Array): Uint8Array {
	return new Uint8Array(createHash("sha256").update(bytes).digest());
}

export function sha256FileHex(bytes: Uint8Array): string {
	return createHash("sha256").update(bytes).digest("hex");
}

export function equalFileBytes(left: Uint8Array, right: Uint8Array): boolean {
	if (left.byteLength !== right.byteLength) return false;
	return timingSafeEqual(left, right);
}

export function fileContextDigest(fileAad: Uint8Array): Uint8Array {
	return sha256FileBytes(concatFileBytes(fileAadDigestLabel, encodeFileLengthPrefix(fileAad)));
}

export function encodeFileHeader(noncePrefix: Uint8Array, fileAad: Uint8Array): Uint8Array {
	if (!isStableFileBytes(noncePrefix) || noncePrefix.byteLength !== 8) {
		throw new CryptoError("CIPHER_FAILURE", "The NMF1 nonce source returned an invalid prefix.");
	}
	const output = new Uint8Array(NMF1_HEADER_BYTES);
	const view = new DataView(output.buffer);
	output.set(magicBytes, 0);
	output[4] = NMF1_SUITE_ID;
	output[5] = 0;
	view.setUint16(6, NMF1_HEADER_BYTES, false);
	view.setUint32(8, NMF1_CHUNK_BYTES, false);
	output.set(noncePrefix, 12);
	output.set(fileContextDigest(fileAad), 20);
	return output;
}

export function parseFileHeader(header: Uint8Array): FileHeaderInfo {
	if (!isStableFileBytes(header) || header.byteLength < NMF1_HEADER_BYTES) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The NMF1 file header is truncated.");
	}
	const prefix = header.subarray(0, NMF1_HEADER_BYTES);
	if (
		prefix[0] !== magicBytes[0] ||
		prefix[1] !== magicBytes[1] ||
		prefix[2] !== magicBytes[2] ||
		prefix[3] !== magicBytes[3]
	) {
		if (prefix[0] === 0x4e && prefix[1] === 0x4d && prefix[2] === 0x46) {
			throw new CryptoError("UNSUPPORTED_VERSION", "The NMF file version is unsupported.");
		}
		throw new CryptoError("MALFORMED_ENVELOPE", "The NMF1 file magic is invalid.");
	}
	if (prefix[4] !== NMF1_SUITE_ID) {
		throw new CryptoError("UNSUPPORTED_CIPHER", "The NMF1 cipher suite is unsupported.");
	}
	const view = new DataView(prefix.buffer, prefix.byteOffset, prefix.byteLength);
	if (
		prefix[5] !== 0 ||
		view.getUint16(6, false) !== NMF1_HEADER_BYTES ||
		view.getUint32(8, false) !== NMF1_CHUNK_BYTES
	) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The NMF1 file header is malformed.");
	}
	return Object.freeze({
		format: NMF1_MAGIC,
		version: NMF1_VERSION,
		suite: NMF1_SUITE,
		chunkSize: NMF1_CHUNK_BYTES,
		noncePrefix: new Uint8Array(prefix.subarray(12, 20)),
		fileContextDigest: new Uint8Array(prefix.subarray(20, 52)),
		authenticated: false,
	});
}

export function assertFileContext(header: FileHeaderInfo, fileAad: Uint8Array): void {
	const expected = fileContextDigest(fileAad);
	if (!equalFileBytes(header.fileContextDigest, expected)) {
		throw new CryptoError("AUTHENTICATION_FAILED", "Ciphertext authentication failed.");
	}
}

export function providerWrappingContext(fileAad: Uint8Array, header: Uint8Array): Uint8Array {
	if (header.byteLength !== NMF1_HEADER_BYTES) {
		throw new CryptoError("INVALID_ARGUMENT", "The NMF1 provider context header is invalid.");
	}
	return concatFileBytes(
		fileKeyContextLabel,
		encodeFileLengthPrefix(fileAad),
		encodeFileLengthPrefix(header),
	);
}

export function wrappingContextDigest(context: Uint8Array): string {
	return sha256FileHex(context);
}

export function encodeDataFrameHeader(frameIndex: number, plaintextLength: number): Uint8Array {
	if (!Number.isInteger(frameIndex) || frameIndex < 0 || frameIndex >= NMF1_MAX_DATA_FRAMES) {
		throw new CryptoError("LIMIT_EXCEEDED", "The NMF1 data-frame counter is exhausted.");
	}
	if (
		!Number.isInteger(plaintextLength) ||
		plaintextLength < 1 ||
		plaintextLength > NMF1_CHUNK_BYTES
	) {
		throw new CryptoError("INVALID_ARGUMENT", "The NMF1 data-frame length is invalid.");
	}
	const output = new Uint8Array(NMF1_DATA_FRAME_HEADER_BYTES);
	const view = new DataView(output.buffer);
	output[0] = NMF1_DATA_FRAME_TYPE;
	output[1] = 0;
	view.setUint16(2, NMF1_DATA_FRAME_HEADER_BYTES, false);
	view.setUint32(4, frameIndex, false);
	view.setUint32(8, plaintextLength, false);
	return output;
}

export function parseDataFrameHeader(header: Uint8Array): ParsedDataFrameHeader {
	if (!isStableFileBytes(header) || header.byteLength !== NMF1_DATA_FRAME_HEADER_BYTES) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The NMF1 data-frame header is truncated.");
	}
	const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
	const plaintextLength = view.getUint32(8, false);
	if (
		header[0] !== NMF1_DATA_FRAME_TYPE ||
		header[1] !== 0 ||
		view.getUint16(2, false) !== NMF1_DATA_FRAME_HEADER_BYTES ||
		view.getUint32(4, false) === NMF1_MAX_DATA_FRAMES ||
		plaintextLength < 1 ||
		plaintextLength > NMF1_CHUNK_BYTES
	) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The NMF1 data-frame header is malformed.");
	}
	return Object.freeze({
		frameIndex: view.getUint32(4, false),
		plaintextLength,
	});
}

export function encodeFinalFrameHeader(
	dataFrameCount: number,
	totalPlaintextLength: bigint,
): Uint8Array {
	if (
		!Number.isInteger(dataFrameCount) ||
		dataFrameCount < 0 ||
		dataFrameCount > NMF1_MAX_DATA_FRAMES
	) {
		throw new CryptoError("LIMIT_EXCEEDED", "The NMF1 final-frame count is invalid.");
	}
	if (totalPlaintextLength < 0n || totalPlaintextLength > UINT64_MAX) {
		throw new CryptoError("LIMIT_EXCEEDED", "The NMF1 final plaintext length is invalid.");
	}
	const output = new Uint8Array(NMF1_FINAL_FRAME_HEADER_BYTES);
	const view = new DataView(output.buffer);
	output[0] = NMF1_FINAL_FRAME_TYPE;
	output[1] = 0;
	view.setUint16(2, NMF1_FINAL_FRAME_HEADER_BYTES, false);
	view.setUint32(4, dataFrameCount, false);
	view.setBigUint64(8, totalPlaintextLength, false);
	return output;
}

export function parseFinalFrameHeader(header: Uint8Array): ParsedFinalFrameHeader {
	if (!isStableFileBytes(header) || header.byteLength !== NMF1_FINAL_FRAME_HEADER_BYTES) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The NMF1 final-frame header is truncated.");
	}
	const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
	if (
		header[0] !== NMF1_FINAL_FRAME_TYPE ||
		header[1] !== 0 ||
		view.getUint16(2, false) !== NMF1_FINAL_FRAME_HEADER_BYTES
	) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The NMF1 final-frame header is malformed.");
	}
	return Object.freeze({
		dataFrameCount: view.getUint32(4, false),
		totalPlaintextLength: view.getBigUint64(8, false),
	});
}

export function frameNonce(noncePrefix: Uint8Array, counter: number): Uint8Array {
	if (
		!isStableFileBytes(noncePrefix) ||
		noncePrefix.byteLength !== 8 ||
		!Number.isInteger(counter) ||
		counter < 0 ||
		counter > UINT32_MAX
	) {
		throw new CryptoError("INVALID_ARGUMENT", "The NMF1 frame nonce is invalid.");
	}
	const nonce = new Uint8Array(12);
	nonce.set(noncePrefix, 0);
	new DataView(nonce.buffer).setUint32(8, counter, false);
	return nonce;
}

export function frameAuthenticatedData(
	fileHeader: Uint8Array,
	fileAad: Uint8Array,
	frameHeader: Uint8Array,
): Uint8Array {
	return concatFileBytes(
		frameAadLabel,
		encodeFileLengthPrefix(fileHeader),
		encodeFileLengthPrefix(fileAad),
		encodeFileLengthPrefix(frameHeader),
	);
}

export function nmf1EncryptedFileSize(plaintextBytes: bigint): bigint {
	if (plaintextBytes < 0n) {
		throw new CryptoError("INVALID_ARGUMENT", "The plaintext length must not be negative.");
	}
	if (plaintextBytes > NMF1_FORMAT_MAX_PLAINTEXT_BYTES) {
		throw new CryptoError("LIMIT_EXCEEDED", "The plaintext length exceeds the NMF1 format limit.");
	}
	const chunkBytes = BigInt(NMF1_CHUNK_BYTES);
	const frames = plaintextBytes === 0n ? 0n : (plaintextBytes + chunkBytes - 1n) / chunkBytes;
	return plaintextBytes + NMF1_EMPTY_FILE_BYTES + 28n * frames;
}

export function assertNmf1PlaintextLimit(value: bigint, configuredMaximum: bigint): void {
	if (typeof value !== "bigint" || value < 0n) {
		throw new CryptoError("INVALID_ARGUMENT", "The plaintext length is invalid.");
	}
	if (value > NMF1_FORMAT_MAX_PLAINTEXT_BYTES || value > configuredMaximum) {
		throw new CryptoError("LIMIT_EXCEEDED", "The plaintext length exceeds the configured limit.");
	}
}

export function isLowercaseSha256(value: unknown): value is string {
	return typeof value === "string" && /^[0-9a-f]{64}$/u.test(value);
}
