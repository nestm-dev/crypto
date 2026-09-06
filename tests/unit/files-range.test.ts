import { createSecretKey } from "node:crypto";
import { describe, expect, it } from "vitest";
import { AesKeyRingProvider } from "../../src/core/index.js";
import {
	FileCipherEngine,
	NMF1_CHUNK_BYTES,
	NMF1_HEADER_BYTES,
	type FileDecryptRangeInput,
	type FileRangeSource,
} from "../../src/files/index.js";

function stream(bytes: Uint8Array): ReadableStream<Uint8Array> {
	return new ReadableStream({
		start(controller) {
			controller.enqueue(bytes);
			controller.close();
		},
	});
}

async function collect(source: ReadableStream<Uint8Array>): Promise<Uint8Array> {
	const chunks: Uint8Array[] = [];
	for await (const chunk of source) chunks.push(chunk);
	return new Uint8Array(Buffer.concat(chunks));
}

async function fixture(size = 4 * NMF1_CHUNK_BYTES + 31) {
	const engine = new FileCipherEngine({
		defaultProvider: "files",
		providers: [
			{
				name: "files",
				provider: new AesKeyRingProvider({
					activeKeyId: "test-only",
					keys: { "test-only": createSecretKey(Buffer.alloc(32, 7)) },
				}),
			},
		],
		maxPlaintextBytes: 100n * BigInt(NMF1_CHUNK_BYTES),
	});
	const plaintext = Uint8Array.from({ length: size }, (_, index) => (index * 17 + 11) % 256);
	const aad = new TextEncoder().encode("test-files/workspace-one/payload-one");
	const encrypted = await engine.encrypt(stream(plaintext), { aad });
	const bytes = await collect(encrypted.encrypted);
	const summary = await encrypted.completion;
	const reads: Array<{ start: bigint; end?: bigint }> = [];
	const source: FileRangeSource = async (range) => {
		reads.push(range);
		return stream(
			bytes.slice(
				Number(range.start),
				range.end === undefined ? undefined : Number(range.end + 1n),
			),
		);
	};
	const input: FileDecryptRangeInput = {
		aad,
		detachedKey: encrypted.detachedKey,
		allowedProviders: ["files"],
		expectedHeaderBytes: encrypted.headerBytes,
		expectedPlaintextBytes: summary.plaintextBytes,
		expectedCiphertextBytes: summary.ciphertextBytes,
		offset: 0n,
		length: Math.min(size, 100),
		maxRangeBytes: 2 * NMF1_CHUNK_BYTES,
	};
	return { engine, plaintext, bytes, reads, source, input };
}

describe("authenticated NMF1 ranges", () => {
	it("reads just the header, final frame and selected data frame for a late window", async () => {
		const f = await fixture();
		try {
			const offset = 3 * NMF1_CHUNK_BYTES + 103;
			const result = await f.engine.decryptRange(f.source, {
				...f.input,
				offset: BigInt(offset),
				length: 4096,
			});
			expect(result).toEqual(f.plaintext.slice(offset, offset + 4096));
			expect(f.reads).toHaveLength(3);
			expect(f.reads[0]).toEqual({ start: 0n, end: 51n });
			expect(f.reads[1]).toEqual({ start: BigInt(f.bytes.length - 32) });
			expect(f.reads[2]?.start).toBe(BigInt(NMF1_HEADER_BYTES + 3 * (NMF1_CHUNK_BYTES + 28)));
		} finally {
			await f.engine.close();
		}
	});

	it("supports cross-frame windows, the short final frame and exact empty ranges", async () => {
		const f = await fixture();
		try {
			for (const [offset, length] of [
				[NMF1_CHUNK_BYTES - 7, 19],
				[f.plaintext.length - 10, 10],
				[f.plaintext.length, 0],
			]) {
				const result = await f.engine.decryptRange(f.source, {
					...f.input,
					offset: BigInt(offset!),
					length: length!,
				});
				expect(result).toEqual(f.plaintext.slice(offset, offset! + length!));
			}
		} finally {
			await f.engine.close();
		}
		const empty = await fixture(0);
		try {
			expect(await empty.engine.decryptRange(empty.source, empty.input)).toEqual(new Uint8Array());
			expect(empty.reads).toHaveLength(2);
		} finally {
			await empty.engine.close();
		}
	});

	it.each([
		["header", 12],
		["selected frame header", NMF1_HEADER_BYTES + 4],
		["selected ciphertext", NMF1_HEADER_BYTES + 20],
		["final frame header", -25],
		["final frame tag", -1],
	] as const)(
		"rejects tampered %s before returning any requested plaintext",
		async (_label, location) => {
			const f = await fixture();
			try {
				const index = location < 0 ? f.bytes.length + location : location;
				f.bytes[index] = f.bytes[index]! ^ 1;
				await expect(f.engine.decryptRange(f.source, f.input)).rejects.toBeDefined();
			} finally {
				await f.engine.close();
			}
		},
	);

	it("verifies selected data without claiming integrity of unread frames", async () => {
		const f = await fixture();
		try {
			const unrelated = NMF1_HEADER_BYTES + 2 * (NMF1_CHUNK_BYTES + 28) + 20;
			f.bytes[unrelated] = f.bytes[unrelated]! ^ 1;
			expect(await f.engine.decryptRange(f.source, f.input)).toEqual(
				f.plaintext.slice(0, f.input.length),
			);
			await expect(
				f.engine.decryptRange(f.source, { ...f.input, offset: 2n * BigInt(NMF1_CHUNK_BYTES) }),
			).rejects.toBeDefined();
		} finally {
			await f.engine.close();
		}
	});

	it("rejects truncation, trailing bytes and a source which ignores ranges", async () => {
		const f = await fixture();
		try {
			for (const object of [
				f.bytes.slice(0, -1),
				new Uint8Array(Buffer.concat([f.bytes, Buffer.from([1])])),
			]) {
				const source: FileRangeSource = async (range) =>
					stream(
						object.slice(
							Number(range.start),
							range.end === undefined ? undefined : Number(range.end + 1n),
						),
					);
				await expect(f.engine.decryptRange(source, f.input)).rejects.toMatchObject({
					code: "MALFORMED_ENVELOPE",
				});
			}
			await expect(
				f.engine.decryptRange(async () => stream(f.bytes), f.input),
			).rejects.toMatchObject({ code: "MALFORMED_ENVELOPE" });
		} finally {
			await f.engine.close();
		}
	});

	it("rejects wrong workspace AAD, detached key, provider, pinned header and lengths", async () => {
		const f = await fixture();
		try {
			for (const input of [
				{ ...f.input, aad: new Uint8Array([99]) },
				{ ...f.input, allowedProviders: ["other"] },
				{ ...f.input, expectedHeaderBytes: new Uint8Array(NMF1_HEADER_BYTES) },
				{ ...f.input, expectedPlaintextBytes: f.input.expectedPlaintextBytes + 1n },
				{ ...f.input, expectedCiphertextBytes: f.input.expectedCiphertextBytes + 1n },
				{ ...f.input, detachedKey: { ...f.input.detachedKey, wrappedKey: new Uint8Array([1]) } },
			])
				await expect(f.engine.decryptRange(f.source, input)).rejects.toBeDefined();
		} finally {
			await f.engine.close();
		}
	});

	it("rejects invalid ranges and byte budgets before reading or allocating a body", async () => {
		const f = await fixture(40);
		try {
			for (const input of [
				{ ...f.input, offset: -1n },
				{ ...f.input, length: -1 },
				{ ...f.input, length: 41 },
				{ ...f.input, maxRangeBytes: 1 },
				{ ...f.input, maxRangeBytes: 0 },
				{ ...f.input, offset: 41n, length: 0 },
			])
				await expect(f.engine.decryptRange(f.source, input)).rejects.toMatchObject({
					code: "INVALID_ARGUMENT",
				});
			expect(f.reads).toHaveLength(0);
		} finally {
			await f.engine.close();
		}
	});

	it("cancels a pending read when the caller aborts or the engine closes", async () => {
		for (const mode of ["caller", "engine"]) {
			const f = await fixture(40);
			const controller = new AbortController();
			const pending = f.engine.decryptRange(
				(_range, signal) =>
					new Promise((_resolve, reject) => {
						signal.addEventListener("abort", () => reject(new Error("aborted test read")), {
							once: true,
						});
					}),
				{ ...f.input, signal: controller.signal },
			);
			const rejected = expect(pending).rejects.toBeDefined();
			if (mode === "caller") controller.abort();
			else await f.engine.close();
			await rejected;
			await f.engine.close();
		}
	});

	it("cancels and releases a byte source arriving after caller cancellation", async () => {
		const f = await fixture(40);
		const controller = new AbortController();
		let deliver!: (value: ReadableStream<Uint8Array>) => void;
		const pending = f.engine.decryptRange(
			() =>
				new Promise((resolve) => {
					deliver = resolve;
				}),
			{ ...f.input, signal: controller.signal },
		);
		const rejected = expect(pending).rejects.toBeDefined();
		controller.abort();
		await rejected;
		let cancelled = false;
		const late = new ReadableStream<Uint8Array>({
			cancel() {
				cancelled = true;
			},
		});
		deliver(late);
		await new Promise<void>((resolve) => setTimeout(resolve, 0));
		expect(cancelled).toBe(true);
		expect(late.locked).toBe(false);
		await f.engine.close();
	});
});
