import { describe, expect, it } from "vitest";
import { CryptoError, type CryptoErrorCode } from "../../src/core/index.js";
import {
	NMF1_CHUNK_BYTES,
	NMF1_DATA_FRAME_HEADER_BYTES,
	NMF1_EMPTY_FILE_BYTES,
	NMF1_FINAL_FRAME_HEADER_BYTES,
	NMF1_FORMAT_MAX_PLAINTEXT_BYTES,
	NMF1_HEADER_BYTES,
	NMF1_MAX_DATA_FRAMES,
	NMF1_MAX_FILE_AAD_BYTES,
	NMF1_TAG_BYTES,
	assertFileContext,
	assertNmf1PlaintextLimit,
	captureFileAad,
	encodeDataFrameHeader,
	encodeFileHeader,
	encodeFinalFrameHeader,
	frameAuthenticatedData,
	frameNonce,
	isLowercaseSha256,
	nmf1EncryptedFileSize,
	parseDataFrameHeader,
	parseFileHeader,
	parseFinalFrameHeader,
	providerWrappingContext,
	wrappingContextDigest,
} from "../../src/files/index.js";

const NONCE_PREFIX = Uint8Array.from([0, 1, 2, 3, 4, 5, 6, 7]);
const FILE_AAD = Uint8Array.from([0xaa, 0xbb]);
const HEADER_HEX =
	"4e4d463101000034001000000001020304050607" +
	"0260b904d2e76ef8f831f95fccd2e8f2beff848c772af48adcdba58dfced3a73";
const FRAME_AAD_HEX =
	"6e6573746d3a6e6d66313a6672616d652d6161643a763100" +
	"00000034" +
	HEADER_HEX +
	"00000002aabb" +
	"0000000c0100000c0102030400000005";
const WRAPPING_CONTEXT_HEX =
	"6e6573746d3a6e6d66313a66696c652d6b65792d636f6e746578743a763100" +
	"00000002aabb" +
	"00000034" +
	HEADER_HEX;

function hex(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("hex");
}

function expectCryptoCode(operation: () => unknown, code: CryptoErrorCode): void {
	let captured: unknown;
	try {
		operation();
	} catch (error: unknown) {
		captured = error;
	}
	expect(captured).toBeInstanceOf(CryptoError);
	expect(captured).toMatchObject({ code });
}

function mutated(bytes: Uint8Array, mutate: (copy: Uint8Array) => void): Uint8Array {
	const copy = new Uint8Array(bytes);
	mutate(copy);
	return copy;
}

describe("NMF1 pure format", () => {
	it("encodes the exact header constants and inspects only unauthenticated metadata", () => {
		expect(NMF1_HEADER_BYTES).toBe(52);
		expect(NMF1_CHUNK_BYTES).toBe(1_048_576);
		expect(NMF1_DATA_FRAME_HEADER_BYTES).toBe(12);
		expect(NMF1_FINAL_FRAME_HEADER_BYTES).toBe(16);
		expect(NMF1_TAG_BYTES).toBe(16);
		expect(NMF1_EMPTY_FILE_BYTES).toBe(84n);

		const headerBytes = encodeFileHeader(NONCE_PREFIX, FILE_AAD);
		expect(hex(headerBytes)).toBe(HEADER_HEX);

		const inspected = parseFileHeader(new Uint8Array([...headerBytes, 0xff, 0xff]));
		expect(inspected).toEqual({
			format: "NMF1",
			version: 1,
			suite: "A256GCM-SHA256-CHUNKED",
			chunkSize: 1_048_576,
			noncePrefix: NONCE_PREFIX,
			fileContextDigest: new Uint8Array(
				Buffer.from("0260b904d2e76ef8f831f95fccd2e8f2beff848c772af48adcdba58dfced3a73", "hex"),
			),
			authenticated: false,
		});
		expect(() => assertFileContext(inspected, FILE_AAD)).not.toThrow();
		expectCryptoCode(
			() => assertFileContext(inspected, Uint8Array.from([0xaa, 0xbc])),
			"AUTHENTICATION_FAILED",
		);
	});

	it("calculates the exact canonical encrypted sizes and rejects invalid bounds", () => {
		expect(nmf1EncryptedFileSize(0n)).toBe(84n);
		expect(nmf1EncryptedFileSize(1n)).toBe(113n);
		expect(nmf1EncryptedFileSize(1_048_575n)).toBe(1_048_687n);
		expect(nmf1EncryptedFileSize(1_048_576n)).toBe(1_048_688n);
		expect(nmf1EncryptedFileSize(1_048_577n)).toBe(1_048_717n);
		expect(NMF1_FORMAT_MAX_PLAINTEXT_BYTES).toBe(4_503_599_626_321_920n);
		expect(nmf1EncryptedFileSize(NMF1_FORMAT_MAX_PLAINTEXT_BYTES)).toBe(4_503_719_885_406_264n);

		expectCryptoCode(() => nmf1EncryptedFileSize(-1n), "INVALID_ARGUMENT");
		expectCryptoCode(
			() => nmf1EncryptedFileSize(NMF1_FORMAT_MAX_PLAINTEXT_BYTES + 1n),
			"LIMIT_EXCEEDED",
		);
		expect(() => assertNmf1PlaintextLimit(8n, 8n)).not.toThrow();
		expectCryptoCode(() => assertNmf1PlaintextLimit(9n, 8n), "LIMIT_EXCEEDED");
	});

	it("round trips exact data and final frame headers at their boundaries", () => {
		const dataHeader = encodeDataFrameHeader(0x0102_0304, 5);
		expect(hex(dataHeader)).toBe("0100000c0102030400000005");
		expect(parseDataFrameHeader(dataHeader)).toEqual({
			frameIndex: 0x0102_0304,
			plaintextLength: 5,
		});
		expect(parseDataFrameHeader(encodeDataFrameHeader(0, 1))).toEqual({
			frameIndex: 0,
			plaintextLength: 1,
		});
		expect(
			parseDataFrameHeader(encodeDataFrameHeader(NMF1_MAX_DATA_FRAMES - 1, NMF1_CHUNK_BYTES)),
		).toEqual({
			frameIndex: 0xffff_fffe,
			plaintextLength: NMF1_CHUNK_BYTES,
		});

		const finalHeader = encodeFinalFrameHeader(2, 1_048_577n);
		expect(hex(finalHeader)).toBe("02000010000000020000000000100001");
		expect(parseFinalFrameHeader(finalHeader)).toEqual({
			dataFrameCount: 2,
			totalPlaintextLength: 1_048_577n,
		});
		expect(parseFinalFrameHeader(encodeFinalFrameHeader(0, 0n))).toEqual({
			dataFrameCount: 0,
			totalPlaintextLength: 0n,
		});
		expect(
			parseFinalFrameHeader(
				encodeFinalFrameHeader(NMF1_MAX_DATA_FRAMES, NMF1_FORMAT_MAX_PLAINTEXT_BYTES),
			),
		).toEqual({
			dataFrameCount: NMF1_MAX_DATA_FRAMES,
			totalPlaintextLength: NMF1_FORMAT_MAX_PLAINTEXT_BYTES,
		});
	});

	it("uses the exact nonce, frame-AAD, and provider-context labels and framing", () => {
		const header = encodeFileHeader(NONCE_PREFIX, FILE_AAD);
		const frameHeader = encodeDataFrameHeader(0x0102_0304, 5);

		expect(hex(frameNonce(NONCE_PREFIX, 0x0102_0304))).toBe("000102030405060701020304");
		expect(hex(frameAuthenticatedData(header, FILE_AAD, frameHeader))).toBe(FRAME_AAD_HEX);

		const context = providerWrappingContext(FILE_AAD, header);
		expect(hex(context)).toBe(WRAPPING_CONTEXT_HEX);
		expect(wrappingContextDigest(context)).toBe(
			"92a62ea4c2f8ccd592279e89687874d59ae8f2c003c06d84a73b33fa5ebbdca5",
		);
		expect(isLowercaseSha256(wrappingContextDigest(context))).toBe(true);
		expect(isLowercaseSha256(wrappingContextDigest(context).toUpperCase())).toBe(false);
	});

	it("classifies unsupported NMF versions and cipher suites separately", () => {
		const header = encodeFileHeader(NONCE_PREFIX, FILE_AAD);
		expectCryptoCode(
			() => parseFileHeader(mutated(header, (copy) => (copy[3] = 0x32))),
			"UNSUPPORTED_VERSION",
		);
		expectCryptoCode(
			() => parseFileHeader(mutated(header, (copy) => (copy[4] = 0x02))),
			"UNSUPPORTED_CIPHER",
		);
	});

	it("maps every pure-format structural failure category to the RFC error taxonomy", () => {
		const header = encodeFileHeader(NONCE_PREFIX, FILE_AAD);
		const dataHeader = encodeDataFrameHeader(0, 1);
		const finalHeader = encodeFinalFrameHeader(0, 0n);

		expectCryptoCode(() => encodeFileHeader(new Uint8Array(7), FILE_AAD), "CIPHER_FAILURE");
		expectCryptoCode(() => captureFileAad("not bytes"), "INVALID_ARGUMENT");
		expectCryptoCode(
			() => captureFileAad(new Uint8Array(NMF1_MAX_FILE_AAD_BYTES + 1)),
			"LIMIT_EXCEEDED",
		);
		expectCryptoCode(() => parseFileHeader(header.subarray(0, 51)), "MALFORMED_ENVELOPE");
		expectCryptoCode(
			() => parseFileHeader(mutated(header, (copy) => (copy[0] = (copy[0] ?? 0) ^ 0xff))),
			"MALFORMED_ENVELOPE",
		);
		for (const malformed of [
			mutated(header, (copy) => (copy[5] = 1)),
			mutated(header, (copy) => (copy[7] = 51)),
			mutated(header, (copy) => (copy[11] = 1)),
		]) {
			expectCryptoCode(() => parseFileHeader(malformed), "MALFORMED_ENVELOPE");
		}

		expectCryptoCode(() => encodeDataFrameHeader(-1, 1), "LIMIT_EXCEEDED");
		expectCryptoCode(() => encodeDataFrameHeader(NMF1_MAX_DATA_FRAMES, 1), "LIMIT_EXCEEDED");
		expectCryptoCode(() => encodeDataFrameHeader(0, 0), "INVALID_ARGUMENT");
		expectCryptoCode(() => encodeDataFrameHeader(0, NMF1_CHUNK_BYTES + 1), "INVALID_ARGUMENT");
		expectCryptoCode(() => parseDataFrameHeader(dataHeader.subarray(0, 11)), "MALFORMED_ENVELOPE");
		for (const malformed of [
			mutated(dataHeader, (copy) => (copy[0] = 2)),
			mutated(dataHeader, (copy) => (copy[1] = 1)),
			mutated(dataHeader, (copy) => (copy[3] = 11)),
			mutated(dataHeader, (copy) => copy.fill(0xff, 4, 8)),
			mutated(dataHeader, (copy) => copy.fill(0, 8, 12)),
		]) {
			expectCryptoCode(() => parseDataFrameHeader(malformed), "MALFORMED_ENVELOPE");
		}

		expectCryptoCode(() => encodeFinalFrameHeader(NMF1_MAX_DATA_FRAMES + 1, 0n), "LIMIT_EXCEEDED");
		expectCryptoCode(() => encodeFinalFrameHeader(0, -1n), "LIMIT_EXCEEDED");
		expectCryptoCode(() => encodeFinalFrameHeader(0, 0x1_0000_0000_0000_0000n), "LIMIT_EXCEEDED");
		expectCryptoCode(
			() => parseFinalFrameHeader(finalHeader.subarray(0, 15)),
			"MALFORMED_ENVELOPE",
		);
		for (const malformed of [
			mutated(finalHeader, (copy) => (copy[0] = 1)),
			mutated(finalHeader, (copy) => (copy[1] = 1)),
			mutated(finalHeader, (copy) => (copy[3] = 15)),
		]) {
			expectCryptoCode(() => parseFinalFrameHeader(malformed), "MALFORMED_ENVELOPE");
		}

		expectCryptoCode(
			() => providerWrappingContext(FILE_AAD, header.subarray(0, 51)),
			"INVALID_ARGUMENT",
		);
		expectCryptoCode(() => frameNonce(new Uint8Array(7), 0), "INVALID_ARGUMENT");
		expectCryptoCode(() => frameNonce(NONCE_PREFIX, -1), "INVALID_ARGUMENT");
	});
});
