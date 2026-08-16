import { createSecretKey } from "node:crypto";
import vectors from "./vectors/format-vectors.json" with { type: "json" };
import {
	decodeKeyWrapRecord,
	unwrapKeyFromRecipient,
	unwrapKeyWithSecret,
	wrapKeyWithSecret,
	encodeKeyWrapRecord,
	x25519PrivateKeyFromRaw,
} from "../../src/keys/index.js";
import {
	createChunkedSealStream,
	inspectChunked,
	openChunked,
	sealChunked,
} from "../../src/stream/index.js";
import { withFixedFileId } from "../../src/testing/index.js";

/**
 * Format-stability gate. These vectors were produced once with fixed keys and a fixed
 * file identifier; a change here means previously written objects can no longer be read.
 * If a test in this file fails, the wire format changed — bump the version, do not
 * regenerate the fixture.
 */

const b64 = (value: Uint8Array): string => Buffer.from(value).toString("base64");
const fromB64 = (value: string): Uint8Array => new Uint8Array(Buffer.from(value, "base64"));
const hex = (value: Uint8Array): string => Buffer.from(value).toString("hex");

const dek = createSecretKey(Buffer.from(vectors.nmcs1.key, "hex"));
const fileId = new Uint8Array(Buffer.from(vectors.nmcs1.fileId, "hex"));
const { keyReference, chunkSizeLog2 } = vectors.nmcs1;
const CHUNK = 2 ** chunkSizeLog2;

const fill = (length: number): Uint8Array => {
	const bytes = new Uint8Array(length);
	for (let index = 0; index < length; index += 1) bytes[index] = index % 251;
	return bytes;
};

describe("nmcs1 frozen vectors", () => {
	const cases: readonly [name: keyof typeof vectors.nmcs1, plaintext: Uint8Array, aad?: string][] =
		[
			["empty", new Uint8Array(0)],
			["oneByte", Uint8Array.of(0x41)],
			["exactChunk", fill(CHUNK)],
			["multiChunk", fill(CHUNK + 17)],
			["withAad", fill(64), "org:acme|ws:1"],
		];

	it.each(cases)("re-seals %s to the frozen bytes", (name, plaintext, aad) => {
		const sealed = sealChunked(
			dek,
			plaintext,
			withFixedFileId(
				{ keyReference, chunkSizeLog2, ...(aad === undefined ? {} : { aad }) },
				fileId,
			),
		);
		expect(b64(sealed)).toBe(vectors.nmcs1[name]);
	});

	it.each(cases)("opens the frozen %s vector", (name, plaintext, aad) => {
		const opened = openChunked(
			dek,
			fromB64(vectors.nmcs1[name] as string),
			aad === undefined ? undefined : { aad },
		);
		expect(hex(opened)).toBe(hex(plaintext));
	});
});

describe("key-wrap record frozen vectors", () => {
	it("decodes and unwraps the frozen secret record", () => {
		const kek = new Uint8Array(Buffer.from(vectors.keyWrapRecord.kek, "hex"));
		const record = decodeKeyWrapRecord(fromB64(vectors.keyWrapRecord.secret));

		expect(record).toMatchObject({
			version: 1,
			algorithm: "A256GCMKW",
			recipientType: "secret",
			recipientId: "user:vector",
		});
		expect(hex(unwrapKeyWithSecret(kek, record).export())).toBe(hex(dek.export()));
	});

	it("re-encodes a record to a byte-stable layout", () => {
		// The wrap itself is randomized by its nonce, so the framing is what is frozen:
		// header + algorithm + recipient id + a 61-byte AES-GCM wrap.
		const kek = new Uint8Array(Buffer.from(vectors.keyWrapRecord.kek, "hex"));
		const encoded = encodeKeyWrapRecord(
			wrapKeyWithSecret(kek, dek, { recipientId: "user:vector" }),
		);
		const frozen = fromB64(vectors.keyWrapRecord.secret);
		expect(encoded.byteLength).toBe(frozen.byteLength);
		// Everything up to the wrapped payload is deterministic.
		const prefix = 6 + "A256GCMKW".length + "user:vector".length;
		expect(hex(encoded.subarray(0, prefix))).toBe(hex(frozen.subarray(0, prefix)));
	});
});

describe("nmcs1 frozen flag coverage", () => {
	// The flag byte selects the header layout, so every combination the writers can emit
	// needs a frozen witness: 0b00 from a stream, 0b10 from a buffered seal (above), and
	// 0b11 when wrap records ride inline.
	const inlineRecord = {
		version: 1,
		algorithm: "A256GCMKW",
		recipientType: "secret",
		recipientId: "ws:vector",
		wrapped: new Uint8Array(61).map((_, index) => (index * 7 + 1) % 256),
	} as const;

	it("freezes the undeclared-length header a stream writes", async () => {
		const frozen = fromB64(vectors.nmcs1.undeclaredLength);
		expect(frozen[6]).toBe(0b0000_0000);
		expect(inspectChunked(frozen).plaintextLength).toBeUndefined();
		expect(Buffer.from(openChunked(dek, frozen)).toString()).toBe("streamed payload");

		const source = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(Buffer.from("streamed payload"));
				controller.close();
			},
		});
		const parts: Uint8Array[] = [];
		const reader = source
			.pipeThrough(
				createChunkedSealStream(dek, withFixedFileId({ keyReference, chunkSizeLog2 }, fileId)),
			)
			.getReader();
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			parts.push(value);
		}
		expect(b64(new Uint8Array(Buffer.concat(parts.map((part) => Buffer.from(part)))))).toBe(
			vectors.nmcs1.undeclaredLength,
		);
	});

	it("freezes a header carrying an inline wrap record", () => {
		const frozen = fromB64(vectors.nmcs1.withWrapRecord);
		expect(frozen[6]).toBe(0b0000_0011);
		const info = inspectChunked(frozen);
		expect(info.wrapRecords).toHaveLength(1);
		expect(info.wrapRecords[0]?.recipientId).toBe("ws:vector");
		expect(Buffer.from(openChunked(dek, frozen)).toString()).toBe("wrapped");

		const resealed = sealChunked(
			dek,
			Buffer.from("wrapped"),
			withFixedFileId({ keyReference, chunkSizeLog2, wrapRecords: [inlineRecord] }, fileId),
		);
		expect(b64(resealed)).toBe(vectors.nmcs1.withWrapRecord);
	});

	it("freezes a record of each recipient type", () => {
		expect(b64(encodeKeyWrapRecord(inlineRecord))).toBe(vectors.keyWrapRecord.inlineSecret);

		const privateKey = x25519PrivateKeyFromRaw(
			new Uint8Array(Buffer.from(vectors.keyWrapRecord.x25519RecipientPrivateKey, "hex")),
		);
		const record = decodeKeyWrapRecord(fromB64(vectors.keyWrapRecord.x25519));
		expect(record).toMatchObject({
			version: 1,
			algorithm: "X25519-HKDF-SHA256-A256GCM",
			recipientType: "x25519",
			recipientId: "user:vector",
		});
		expect(hex(unwrapKeyFromRecipient(privateKey, record).export())).toBe(hex(dek.export()));
	});
});
