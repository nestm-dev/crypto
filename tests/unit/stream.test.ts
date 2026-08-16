import { createSecretKey, randomBytes } from "node:crypto";
import {
	generateX25519KeyPair,
	selectKeyWrapRecord,
	unwrapKeyFromRecipient,
	wrapKeyToRecipient,
	wrapKeyWithSecret,
} from "../../src/keys/index.js";
import {
	chunkedChunkRange,
	chunkedCiphertextLength,
	chunkedPlaintextLength,
	createChunkedOpenStream,
	createChunkedSealStream,
	inspectChunked,
	openChunked,
	sealChunked,
	NMCS_DEFAULT_CHUNK_SIZE_LOG2,
	NMCS_HEADER_BYTES,
	NMCS_SUITE_AES256GCM_HKDF_SHA256,
	type ChunkedSealOptions,
} from "../../src/stream/index.js";
import { withFixedFileId } from "../../src/testing/index.js";

const hex = (value: Uint8Array): string => Buffer.from(value).toString("hex");

const KEY_REFERENCE = "ws:1f9e:e1";
// 64 KiB chunks keep multi-chunk fixtures small enough to run quickly.
const SMALL_LOG2 = 16;
const SMALL_CHUNK = 2 ** SMALL_LOG2;

const key = (): ReturnType<typeof createSecretKey> => createSecretKey(randomBytes(32));

async function pipe(
	input: Uint8Array,
	transform: TransformStream<Uint8Array, Uint8Array>,
	sliceSize = 7_000,
): Promise<Uint8Array> {
	const source = new ReadableStream<Uint8Array>({
		start(controller) {
			for (let offset = 0; offset < input.byteLength; offset += sliceSize) {
				controller.enqueue(input.subarray(offset, Math.min(offset + sliceSize, input.byteLength)));
			}
			controller.close();
		},
	});
	const parts: Uint8Array[] = [];
	const reader = source.pipeThrough(transform).getReader();
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		parts.push(value);
	}
	let total = 0;
	for (const part of parts) total += part.byteLength;
	const output = new Uint8Array(total);
	let cursor = 0;
	for (const part of parts) {
		output.set(part, cursor);
		cursor += part.byteLength;
	}
	return output;
}

describe("sealChunked / openChunked", () => {
	it("round-trips payloads across chunk boundaries", () => {
		const dek = key();
		const sizes = [0, 1, 1024, SMALL_CHUNK - 1, SMALL_CHUNK, SMALL_CHUNK + 1, SMALL_CHUNK * 3];
		for (const size of sizes) {
			const plaintext = randomBytes(size);
			const sealed = sealChunked(dek, plaintext, {
				keyReference: KEY_REFERENCE,
				chunkSizeLog2: SMALL_LOG2,
			});
			expect(sealed.byteLength).toBe(chunkedCiphertextLength(size, SMALL_LOG2));
			expect(hex(openChunked(dek, sealed))).toBe(hex(plaintext));
		}
	});

	it("uses a 1 MiB chunk and a 512-byte header by default", () => {
		const dek = key();
		const sealed = sealChunked(dek, randomBytes(10), { keyReference: KEY_REFERENCE });
		expect(sealed.byteLength).toBe(NMCS_HEADER_BYTES + 10 + 20);
		expect(inspectChunked(sealed).chunkSize).toBe(2 ** NMCS_DEFAULT_CHUNK_SIZE_LOG2);
	});

	it("keeps ciphertext indistinguishable and unique per seal", () => {
		const dek = key();
		const plaintext = Buffer.from("# Q3 Launch Plan\n- pricing draft");
		const a = sealChunked(dek, plaintext, { keyReference: KEY_REFERENCE });
		const b = sealChunked(dek, plaintext, { keyReference: KEY_REFERENCE });

		expect(hex(a)).not.toBe(hex(b));
		expect(a.subarray(NMCS_HEADER_BYTES).includes(plaintext[0]!)).toBeDefined();
		expect(Buffer.from(a).includes("Q3 Launch")).toBe(false);
		expect(Buffer.from(a.subarray(0, 4)).toString()).toBe("nmcs");
	});

	it("binds aad and the key reference", () => {
		const dek = key();
		const plaintext = randomBytes(64);
		const sealed = sealChunked(dek, plaintext, { keyReference: KEY_REFERENCE, aad: "org:1|ws:2" });

		expect(hex(openChunked(dek, sealed, { aad: "org:1|ws:2" }))).toBe(hex(plaintext));
		expect(() => openChunked(dek, sealed, { aad: "org:1|ws:3" })).toThrowError(
			/authentication failed/i,
		);
		expect(() => openChunked(dek, sealed)).toThrowError(/authentication failed/i);
		expect(() =>
			openChunked(dek, sealed, { aad: "org:1|ws:2", expectedKeyReference: "ws:other" }),
		).toThrowError(/authentication failed/i);
		expect(
			hex(openChunked(dek, sealed, { aad: "org:1|ws:2", expectedKeyReference: KEY_REFERENCE })),
		).toBe(hex(plaintext));
	});

	it("cannot be opened with the wrong key", () => {
		const sealed = sealChunked(key(), randomBytes(64), { keyReference: KEY_REFERENCE });
		expect(() => openChunked(key(), sealed)).toThrowError(/authentication failed/i);
	});

	it("carries inline wrap records", () => {
		const dek = key();
		const record = wrapKeyWithSecret(randomBytes(32), dek, { recipientId: "ws:1" });
		const sealed = sealChunked(dek, randomBytes(32), {
			keyReference: KEY_REFERENCE,
			wrapRecords: [record],
		});
		const info = inspectChunked(sealed);
		expect(info.wrapRecords).toHaveLength(1);
		expect(info.wrapRecords[0]?.recipientId).toBe("ws:1");
		expect(hex(info.wrapRecords[0]!.wrapped)).toBe(hex(record.wrapped));
	});

	it("reports untrusted header metadata", () => {
		const dek = key();
		const sealed = sealChunked(dek, randomBytes(200), {
			keyReference: KEY_REFERENCE,
			aad: "ctx",
			chunkSizeLog2: SMALL_LOG2,
		});
		expect(inspectChunked(sealed)).toMatchObject({
			version: 1,
			suite: NMCS_SUITE_AES256GCM_HKDF_SHA256,
			chunkSize: SMALL_CHUNK,
			keyReference: KEY_REFERENCE,
			plaintextLength: 200,
			headerBytes: NMCS_HEADER_BYTES,
			authenticated: false,
		});
	});

	it("rejects oversized payloads and out-of-range chunk sizes", () => {
		const dek = key();
		expect(() =>
			sealChunked(dek, randomBytes(64), { keyReference: KEY_REFERENCE, maxPlaintextBytes: 32 }),
		).toThrowError(/exceeds the configured limit/i);
		expect(() =>
			sealChunked(dek, randomBytes(8), { keyReference: KEY_REFERENCE, chunkSizeLog2: 15 }),
		).toThrowError(/out of range/i);
		expect(() =>
			sealChunked(dek, randomBytes(8), { keyReference: KEY_REFERENCE, chunkSizeLog2: 27 }),
		).toThrowError(/out of range/i);
		expect(() => sealChunked(dek, randomBytes(8), { keyReference: "" })).toThrowError(
			/key reference is invalid/i,
		);
	});

	it("rejects a header whose content does not fit", () => {
		expect(() =>
			sealChunked(key(), randomBytes(8), { keyReference: "k".repeat(500) }),
		).toThrowError(/too large/i);
	});
});

describe("nmcs1 tamper resistance", () => {
	const dek = key();
	const plaintext = randomBytes(SMALL_CHUNK * 2 + 100);
	const options: ChunkedSealOptions = {
		keyReference: KEY_REFERENCE,
		chunkSizeLog2: SMALL_LOG2,
	};
	const sealed = sealChunked(dek, plaintext, options);

	it("rejects a bit flip anywhere in the header", () => {
		for (let offset = 0; offset < NMCS_HEADER_BYTES; offset += 1) {
			const tampered = Uint8Array.from(sealed);
			tampered[offset] = (tampered[offset] ?? 0) ^ 0x01;
			expect(() => openChunked(dek, tampered)).toThrow();
		}
	});

	it("rejects a bit flip in the chunk body", () => {
		const tampered = Uint8Array.from(sealed);
		const target = NMCS_HEADER_BYTES + 8;
		tampered[target] = (tampered[target] ?? 0) ^ 0x01;
		expect(() => openChunked(dek, tampered)).toThrowError(/authentication failed/i);
	});

	it("rejects truncation of the final chunk and of trailing bytes", () => {
		const stride = SMALL_CHUNK + 20;
		// Dropping whole chunks leaves a full non-final chunk carrying the final flag: the
		// reader requires a final-flagged chunk to terminate, so the tag check fails.
		expect(() => openChunked(dek, sealed.subarray(0, NMCS_HEADER_BYTES + stride * 2))).toThrowError(
			/authentication failed/i,
		);
		// Dropping bytes mid-chunk is caught by framing before any tag is checked.
		expect(() => openChunked(dek, sealed.subarray(0, sealed.byteLength - 1))).toThrowError(
			/truncated/i,
		);
		expect(() => openChunked(dek, sealed.subarray(0, NMCS_HEADER_BYTES))).toThrowError(
			/truncated/i,
		);
	});

	it("rejects reordered chunks", () => {
		const stride = SMALL_CHUNK + 20;
		const reordered = Uint8Array.from(sealed);
		const first = sealed.subarray(NMCS_HEADER_BYTES, NMCS_HEADER_BYTES + stride);
		const second = sealed.subarray(NMCS_HEADER_BYTES + stride, NMCS_HEADER_BYTES + stride * 2);
		reordered.set(second, NMCS_HEADER_BYTES);
		reordered.set(first, NMCS_HEADER_BYTES + stride);
		expect(() => openChunked(dek, reordered)).toThrowError(/authentication failed/i);
	});

	it("rejects a chunk spliced in from another object", () => {
		const other = sealChunked(dek, randomBytes(SMALL_CHUNK * 2 + 100), options);
		const stride = SMALL_CHUNK + 20;
		const spliced = Uint8Array.from(sealed);
		spliced.set(other.subarray(NMCS_HEADER_BYTES, NMCS_HEADER_BYTES + stride), NMCS_HEADER_BYTES);
		expect(() => openChunked(dek, spliced)).toThrowError(/authentication failed/i);
	});

	it("rejects a header transplanted from another object", () => {
		const other = sealChunked(dek, plaintext, options);
		const swapped = Uint8Array.from(sealed);
		swapped.set(other.subarray(0, NMCS_HEADER_BYTES), 0);
		expect(() => openChunked(dek, swapped)).toThrowError(/authentication failed/i);
	});

	it("rejects reserved flag bits, bad padding, and hostile chunk sizes", () => {
		const withFlags = Uint8Array.from(sealed);
		withFlags[6] = (withFlags[6] ?? 0) | 0b1000_0000;
		expect(() => inspectChunked(withFlags)).toThrowError(/reserved flags/i);

		const withPadding = Uint8Array.from(sealed);
		withPadding[480] = 0x01;
		expect(() => inspectChunked(withPadding)).toThrowError(/padding is not zero/i);

		const badChunk = Uint8Array.from(sealed);
		badChunk[7] = 40;
		expect(() => inspectChunked(badChunk)).toThrowError(/chunk size is invalid/i);

		const bigChunk = sealChunked(key(), randomBytes(4), {
			keyReference: KEY_REFERENCE,
			chunkSizeLog2: 26,
			maxChunkSizeLog2: 26,
		});
		expect(() => openChunked(key(), bigChunk, { maxChunkSizeLog2: 20 })).toThrowError(
			/exceeds the limit/i,
		);
	});

	it("never writes a chunk size its own default reader would refuse", () => {
		const dekLocal = key();
		// The seal ceiling and the open ceiling are the same number, so a default writer
		// cannot produce an object that a default reader (or inspector) rejects.
		for (const chunkSizeLog2 of [25, 26]) {
			expect(() =>
				sealChunked(dekLocal, randomBytes(4), { keyReference: KEY_REFERENCE, chunkSizeLog2 }),
			).toThrowError(/exceeds the limit/i);
		}

		const optedIn = sealChunked(dekLocal, randomBytes(4), {
			keyReference: KEY_REFERENCE,
			chunkSizeLog2: 25,
			maxChunkSizeLog2: 25,
		});
		// Opting in on the write side alone is not enough: the reader must opt in too.
		expect(() => openChunked(dekLocal, optedIn)).toThrowError(/exceeds the limit/i);
		expect(() => inspectChunked(optedIn)).toThrowError(/exceeds the limit/i);
		expect(inspectChunked(optedIn, { maxChunkSizeLog2: 25 }).chunkSize).toBe(2 ** 25);
		expect(openChunked(dekLocal, optedIn, { maxChunkSizeLog2: 25 })).toHaveLength(4);
	});

	it("requires a whole header before reporting on one", () => {
		// 496 bytes is the authenticated content but not a complete header; reporting on it
		// would describe an object no reader could ever authenticate.
		expect(() => inspectChunked(sealed.subarray(0, NMCS_HEADER_BYTES - 1))).toThrowError(
			/truncated/i,
		);
		expect(inspectChunked(sealed.subarray(0, NMCS_HEADER_BYTES)).keyReference).toBe(KEY_REFERENCE);
	});

	it("rejects unknown versions and suites", () => {
		const badVersion = Uint8Array.from(sealed);
		badVersion[4] = 0x02;
		expect(() => inspectChunked(badVersion)).toThrowError(/version is unsupported/i);

		const badSuite = Uint8Array.from(sealed);
		badSuite[5] = 0x02;
		expect(() => inspectChunked(badSuite)).toThrowError(/suite is unsupported/i);

		const badMagic = Uint8Array.from(sealed);
		badMagic[0] = 0x78;
		expect(() => inspectChunked(badMagic)).toThrowError(/magic is invalid/i);
	});

	it("refuses to seal a declared length that disagrees with the payload", () => {
		const dekLocal = key();
		// Emitting the object would produce ciphertext whose own header makes it
		// permanently unopenable, so the contradiction is rejected up front.
		expect(() =>
			sealChunked(dekLocal, randomBytes(100), {
				keyReference: KEY_REFERENCE,
				chunkSizeLog2: SMALL_LOG2,
				plaintextLength: 99,
			}),
		).toThrowError(/declared plaintext length does not match/i);
	});
});

describe("chunked streams", () => {
	it("produces bytes identical to the buffered seal when the length is declared", async () => {
		const dek = key();
		const plaintext = randomBytes(SMALL_CHUNK * 2 + 511);
		// The file identifier is drawn fresh per seal, so byte identity is only observable
		// when both paths are pinned to the same one through the testing seam.
		const options: ChunkedSealOptions = withFixedFileId(
			{
				keyReference: KEY_REFERENCE,
				chunkSizeLog2: SMALL_LOG2,
				aad: "ctx",
				plaintextLength: plaintext.byteLength,
			},
			randomBytes(16),
		);

		const buffered = sealChunked(dek, plaintext, options);
		const streamed = await pipe(plaintext, createChunkedSealStream(dek, options));
		expect(hex(streamed)).toBe(hex(buffered));
	});

	it("differs from the buffered seal only in the length flag when undeclared", async () => {
		const dek = key();
		const plaintext = randomBytes(SMALL_CHUNK + 7);
		const options: ChunkedSealOptions = withFixedFileId(
			{ keyReference: KEY_REFERENCE, chunkSizeLog2: SMALL_LOG2 },
			randomBytes(16),
		);

		// `sealChunked` always knows the length and declares it; a stream cannot.
		const buffered = sealChunked(dek, plaintext, options);
		const streamed = await pipe(plaintext, createChunkedSealStream(dek, options));

		expect(inspectChunked(buffered).plaintextLength).toBe(plaintext.byteLength);
		expect(inspectChunked(streamed).plaintextLength).toBeUndefined();
		expect(streamed.byteLength).toBe(buffered.byteLength);
		// Byte 6 is the flag field; the declared-length bit and the length field are the
		// only header differences, and the chunk keys diverge because the header is hashed.
		expect(buffered[6]! ^ streamed[6]!).toBe(0b0000_0010);
		expect(hex(buffered.subarray(0, 6))).toBe(hex(streamed.subarray(0, 6)));
		expect(hex(openChunked(dek, streamed))).toBe(hex(plaintext));
	});

	it("round-trips through both stream directions", async () => {
		const dek = key();
		for (const size of [0, 1, SMALL_CHUNK, SMALL_CHUNK + 1, SMALL_CHUNK * 3 + 7]) {
			const plaintext = randomBytes(size);
			const sealed = await pipe(
				plaintext,
				createChunkedSealStream(dek, {
					keyReference: KEY_REFERENCE,
					chunkSizeLog2: SMALL_LOG2,
				}),
			);
			expect(sealed.byteLength).toBe(chunkedCiphertextLength(size, SMALL_LOG2));
			expect(hex(await pipe(sealed, createChunkedOpenStream(dek)))).toBe(hex(plaintext));
			expect(hex(openChunked(dek, sealed))).toBe(hex(plaintext));
		}
	});

	it("opens a buffered seal and seals for a buffered open", async () => {
		const dek = key();
		const plaintext = randomBytes(SMALL_CHUNK + 128);
		const options: ChunkedSealOptions = {
			keyReference: KEY_REFERENCE,
			chunkSizeLog2: SMALL_LOG2,
		};
		const buffered = sealChunked(dek, plaintext, options);
		expect(hex(await pipe(buffered, createChunkedOpenStream(dek), 999))).toBe(hex(plaintext));

		const streamed = await pipe(plaintext, createChunkedSealStream(dek, options), 999);
		expect(hex(openChunked(dek, streamed))).toBe(hex(plaintext));
	});

	it("omits the declared length when the size is unknown up front", async () => {
		const dek = key();
		const sealed = await pipe(
			randomBytes(300),
			createChunkedSealStream(dek, { keyReference: KEY_REFERENCE, chunkSizeLog2: SMALL_LOG2 }),
		);
		expect(inspectChunked(sealed).plaintextLength).toBeUndefined();
		expect(openChunked(dek, sealed).byteLength).toBe(300);
	});

	it("fails a stream truncated before its final chunk", async () => {
		const dek = key();
		const sealed = sealChunked(dek, randomBytes(SMALL_CHUNK * 2), {
			keyReference: KEY_REFERENCE,
			chunkSizeLog2: SMALL_LOG2,
		});
		await expect(
			pipe(sealed.subarray(0, sealed.byteLength - 40), createChunkedOpenStream(dek)),
		).rejects.toThrow();
		await expect(
			pipe(sealed.subarray(0, NMCS_HEADER_BYTES - 1), createChunkedOpenStream(dek)),
		).rejects.toThrowError(/truncated/i);
	});

	it("rejects a declared length that disagrees with the streamed payload", async () => {
		const dek = key();
		await expect(
			pipe(
				randomBytes(100),
				createChunkedSealStream(dek, { keyReference: KEY_REFERENCE, plaintextLength: 99 }),
			),
		).rejects.toThrowError(/does not match/i);
	});
});

describe("chunked size math", () => {
	it("inverts exactly across chunk boundaries", () => {
		for (const log2 of [SMALL_LOG2, NMCS_DEFAULT_CHUNK_SIZE_LOG2]) {
			const chunk = 2 ** log2;
			const sizes = [0, 1, 2, chunk - 1, chunk, chunk + 1, chunk * 2, chunk * 2 + 1, chunk * 5];
			for (const size of sizes) {
				expect(chunkedPlaintextLength(chunkedCiphertextLength(size, log2), log2)).toBe(size);
			}
		}
	});

	it("returns undefined for sizes outside the format image", () => {
		expect(chunkedPlaintextLength(0, SMALL_LOG2)).toBeUndefined();
		expect(chunkedPlaintextLength(NMCS_HEADER_BYTES, SMALL_LOG2)).toBeUndefined();
		expect(chunkedPlaintextLength(NMCS_HEADER_BYTES + 19, SMALL_LOG2)).toBeUndefined();
		expect(chunkedPlaintextLength(-1, SMALL_LOG2)).toBeUndefined();
		// One byte past a full single chunk cannot exist: it would need a second chunk's overhead.
		expect(
			chunkedPlaintextLength(NMCS_HEADER_BYTES + SMALL_CHUNK + 21, SMALL_LOG2),
		).toBeUndefined();
	});

	it("computes chunk ciphertext ranges", () => {
		const stride = SMALL_CHUNK + 20;
		expect(chunkedChunkRange(0, SMALL_LOG2)).toEqual({
			start: NMCS_HEADER_BYTES,
			end: NMCS_HEADER_BYTES + stride,
		});
		expect(chunkedChunkRange(2, SMALL_LOG2)).toEqual({
			start: NMCS_HEADER_BYTES + stride * 2,
			end: NMCS_HEADER_BYTES + stride * 3,
		});
		expect(() => chunkedChunkRange(-1, SMALL_LOG2)).toThrowError(/out of range/i);
	});

	it("caps the chunk count at 2^20 (index is an exclusive bound)", () => {
		// The policy allows 2^20 chunks, i.e. indices 0 .. 2^20 - 1. The last valid index
		// resolves; the 2^20th index does not (off-by-one guard).
		const maxIndex = 0x10_0000;
		expect(chunkedChunkRange(maxIndex - 1, SMALL_LOG2)).toBeDefined();
		expect(() => chunkedChunkRange(maxIndex, SMALL_LOG2)).toThrowError(/out of range/i);
	});
});

describe("integration: sealed data key + chunked object", () => {
	it("round-trips the full storage-adapter path", () => {
		// 1. A random per-object data key, sealed to the workspace public key.
		const workspace = generateX25519KeyPair();
		const dek = createSecretKey(randomBytes(32));
		const wrap = wrapKeyToRecipient(workspace.publicKey, dek, {
			recipientId: "ws:1f9e",
			info: "wsk.seal",
		});

		// 2. The object is encrypted under that key with the wrap carried inline.
		const plaintext = randomBytes(SMALL_CHUNK * 2 + 42);
		const sealed = sealChunked(dek, plaintext, {
			keyReference: "ws:1f9e:e1",
			aad: "org:acme|ws:1f9e",
			chunkSizeLog2: SMALL_LOG2,
			wrapRecords: [wrap],
		});

		// 3. A reader holding only the workspace private key recovers the object.
		const header = inspectChunked(sealed.subarray(0, NMCS_HEADER_BYTES));
		const found = selectKeyWrapRecord(header.wrapRecords, {
			recipientType: "x25519",
			recipientId: "ws:1f9e",
		});
		expect(found).toBeDefined();
		const recovered = unwrapKeyFromRecipient(workspace.privateKey, found!, { info: "wsk.seal" });
		expect(hex(openChunked(recovered, sealed, { aad: "org:acme|ws:1f9e" }))).toBe(hex(plaintext));

		// 4. Someone without the workspace key cannot get the data key at all.
		const stranger = generateX25519KeyPair();
		expect(() =>
			unwrapKeyFromRecipient(stranger.privateKey, found!, { info: "wsk.seal" }),
		).toThrowError(/authentication failed/i);
	});
});

describe("nmcs1 hardening regressions", () => {
	const dek = key();
	const sealed = sealChunked(dek, randomBytes(SMALL_CHUNK + 32), {
		keyReference: KEY_REFERENCE,
		chunkSizeLog2: SMALL_LOG2,
	});

	it("gives callers no way to pin the file identifier", () => {
		// The file identifier is the only per-object randomness in the key schedule, so a
		// public seam would let a caller repeat a chunk key and nonce prefix. It exists only
		// on `@nestm/crypto/testing`, and the public options type must not accept it.
		const options: ChunkedSealOptions = {
			keyReference: KEY_REFERENCE,
			// @ts-expect-error -- fileId is deliberately absent from ChunkedSealOptions.
			fileId: new Uint8Array(16),
		};
		const a = sealChunked(dek, Buffer.from("same"), options);
		const b = sealChunked(dek, Buffer.from("same"), options);
		// An ignored stray property must not make two seals share a file identifier.
		expect(hex(a.subarray(8, 24))).not.toBe(hex(b.subarray(8, 24)));
		expect(hex(a)).not.toBe(hex(b));
	});

	it("keeps the keystream distinct across seals of identical input", () => {
		const plaintext = randomBytes(SMALL_CHUNK);
		const a = sealChunked(dek, plaintext, {
			keyReference: KEY_REFERENCE,
			chunkSizeLog2: SMALL_LOG2,
		});
		const b = sealChunked(dek, plaintext, {
			keyReference: KEY_REFERENCE,
			chunkSizeLog2: SMALL_LOG2,
		});
		const bodyA = a.subarray(NMCS_HEADER_BYTES + 4, NMCS_HEADER_BYTES + 4 + plaintext.byteLength);
		const bodyB = b.subarray(NMCS_HEADER_BYTES + 4, NMCS_HEADER_BYTES + 4 + plaintext.byteLength);
		// Equal keystreams would make ct_a XOR ct_b equal pt_a XOR pt_b, i.e. all zeroes here.
		expect(bodyA.some((byte, index) => (byte ^ (bodyB[index] as number)) !== 0)).toBe(true);
	});

	it("validates byte limits instead of letting NaN disable them", () => {
		for (const bad of [Number.NaN, -1, 1.5, Number.POSITIVE_INFINITY]) {
			expect(() =>
				sealChunked(dek, randomBytes(8), { keyReference: KEY_REFERENCE, maxPlaintextBytes: bad }),
			).toThrowError(/non-negative integer/i);
			expect(() => openChunked(dek, sealed, { maxPlaintextBytes: bad })).toThrowError(
				/non-negative integer/i,
			);
		}
		expect(() => createChunkedOpenStream(dek, { maxChunkSizeLog2: Number.NaN })).toThrowError(
			/out of range/i,
		);
	});

	it("rejects unstable byte views at the bulk boundaries", () => {
		const shared = new Uint8Array(new SharedArrayBuffer(16));
		expect(() => sealChunked(dek, shared, { keyReference: KEY_REFERENCE })).toThrowError(
			/must be bytes/i,
		);
		expect(() => openChunked(dek, shared)).toThrowError(/must be bytes/i);

		class Exotic extends Uint8Array {}
		expect(() => sealChunked(dek, new Exotic(16), { keyReference: KEY_REFERENCE })).toThrowError(
			/must be bytes/i,
		);
	});

	it("rejects a header whose text is not valid UTF-8 as malformed", () => {
		const tampered = Uint8Array.from(sealed);
		// Byte 38 begins the key reference; a bare continuation byte is not valid UTF-8.
		tampered[38] = 0x80;
		expect(() => inspectChunked(tampered)).toThrowError(/malformed/i);
		expect(() => openChunked(dek, tampered)).toThrowError(/malformed/i);
	});

	it("rejects a header key reference carrying control characters", () => {
		const tampered = Uint8Array.from(sealed);
		tampered[38] = 0x07;
		expect(() => inspectChunked(tampered)).toThrowError(/key reference is invalid/i);
	});

	it("fills the header content region exactly", () => {
		// 38 fixed bytes + key reference must be able to reach the 496-byte boundary and no
		// further; one byte more is a header that cannot be encoded.
		const fitting = "k".repeat(496 - 38);
		expect(() => sealChunked(key(), randomBytes(4), { keyReference: fitting })).not.toThrow();
		expect(() => sealChunked(key(), randomBytes(4), { keyReference: `${fitting}k` })).toThrowError(
			/too large/i,
		);
	});

	it("bounds streaming work by the plaintext budget before buffering a whole chunk", async () => {
		const big = sealChunked(dek, randomBytes(SMALL_CHUNK + 64), {
			keyReference: KEY_REFERENCE,
			chunkSizeLog2: SMALL_LOG2,
		});
		// Feeding a byte at a time must trip the limit almost immediately rather than after a
		// full chunk has accumulated in memory.
		await expect(
			pipe(big, createChunkedOpenStream(dek, { maxPlaintextBytes: 32 }), 1),
		).rejects.toThrow(/exceeds the configured limit/i);
		await expect(
			pipe(big, createChunkedOpenStream(dek, { maxPlaintextBytes: 32 })),
		).rejects.toThrow(/exceeds the configured limit/i);
	});

	it("produces identical output whatever the source write sizes are", async () => {
		const plaintext = randomBytes(SMALL_CHUNK + 13);
		const options = withFixedFileId(
			{ keyReference: KEY_REFERENCE, chunkSizeLog2: SMALL_LOG2 },
			randomBytes(16),
		);
		const oneByteAtATime = await pipe(plaintext, createChunkedSealStream(dek, options), 1);
		const allAtOnce = await pipe(
			plaintext,
			createChunkedSealStream(dek, options),
			plaintext.byteLength,
		);
		expect(hex(oneByteAtATime)).toBe(hex(allAtOnce));
		expect(hex(await pipe(oneByteAtATime, createChunkedOpenStream(dek), 1))).toBe(hex(plaintext));
	});
});
