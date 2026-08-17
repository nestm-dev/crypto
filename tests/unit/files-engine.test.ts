import { readFileSync } from "node:fs";
import { createHash, createSecretKey, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	AesKeyRingProvider,
	authenticationFailed,
	CryptoError,
	type DataKeyContext,
	type DataKeyProvider,
	type GeneratedDataKey,
	type WrappedDataKey,
} from "../../src/core/index.js";
import {
	FileCipherEngine,
	NMF1_CHUNK_BYTES,
	NMF1_HEADER_BYTES,
	concatFileBytes,
	type DetachedFileKey,
	type FileDecryptInput,
} from "../../src/files/index.js";

interface FixtureVector {
	readonly name: string;
	readonly plaintext: Uint8Array;
	readonly aad: Uint8Array;
	readonly dek: Uint8Array;
	readonly noncePrefix: Uint8Array;
	readonly wrappedKey: Uint8Array;
	readonly provider: string;
	readonly keyReference: string;
	readonly wrappingAlgorithm: string;
	readonly expectedHeader: Uint8Array;
	readonly expectedNmf1: Uint8Array | undefined;
	readonly expectedCiphertextBytes: bigint;
	readonly expectedDataFrameCount: number;
	readonly wrappingContextDigest: string;
	readonly ciphertextSha256: string;
}

interface WebSourceProbe {
	readonly stream: ReadableStream<Uint8Array>;
	readonly pulls: () => number;
	readonly cancelled: () => boolean;
}

interface Latch {
	readonly promise: Promise<void>;
	release(): void;
}

const DEFAULT_AAD = Uint8Array.from([0x10, 0x20, 0x30]);
const DEFAULT_NONCE_PREFIX = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);
const DEFAULT_DEK = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const DEFAULT_WRAPPER = Uint8Array.from({ length: 61 }, (_, index) => (index * 7 + 3) & 0xff);

function bytes(hex: string): Uint8Array {
	return new Uint8Array(Buffer.from(hex, "hex"));
}

function record(value: unknown, label: string): Record<string, unknown> {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new TypeError(`${label} is not an object.`);
	}
	return Object.fromEntries(Object.entries(value));
}

function text(value: unknown, label: string): string {
	if (typeof value !== "string") throw new TypeError(`${label} is not text.`);
	return value;
}

function integer(value: unknown, label: string): number {
	if (typeof value !== "number" || !Number.isSafeInteger(value)) {
		throw new TypeError(`${label} is not a safe integer.`);
	}
	return value;
}

function vectorPlaintext(input: Record<string, unknown>): Uint8Array {
	if (typeof input["plaintextHex"] === "string") return bytes(input["plaintextHex"]);
	const generator = record(input["plaintextGenerator"], "plaintext generator");
	if (text(generator["algorithm"], "plaintext generator algorithm") !== "affine-byte-v1") {
		throw new TypeError("Unsupported plaintext generator.");
	}
	const length = Number(BigInt(text(generator["length"], "plaintext generator length")));
	if (!Number.isSafeInteger(length) || length < 0) {
		throw new TypeError("Plaintext generator length is invalid.");
	}
	if (
		integer(generator["multiplier"], "plaintext generator multiplier") !== 131 ||
		integer(generator["increment"], "plaintext generator increment") !== 17
	) {
		throw new TypeError("Plaintext generator parameters are non-canonical.");
	}
	return pattern(length);
}

function loadVector(filename: string): FixtureVector {
	const parsed: unknown = JSON.parse(
		readFileSync(new URL(`../vectors/nmf1/${filename}`, import.meta.url), "utf8"),
	);
	const root = record(parsed, "vector");
	const input = record(root["input"], "vector input");
	const expected = record(root["expected"], "vector expected");
	const nmf1Hex = expected["nmf1Hex"];
	return {
		name: text(root["name"], "vector name"),
		plaintext: vectorPlaintext(input),
		aad: bytes(text(input["fileAadHex"], "AAD")),
		dek: bytes(text(input["dekHex"], "DEK")),
		noncePrefix: bytes(text(input["noncePrefixHex"], "nonce prefix")),
		wrappedKey: bytes(text(expected["wrappedKeyHex"], "wrapped key")),
		provider: text(input["provider"], "provider"),
		keyReference: text(input["keyReference"], "key reference"),
		wrappingAlgorithm: text(expected["wrappingAlgorithm"], "wrapping algorithm"),
		expectedHeader: bytes(text(expected["headerHex"], "header")),
		expectedNmf1: typeof nmf1Hex === "string" ? bytes(nmf1Hex) : undefined,
		expectedCiphertextBytes: BigInt(text(expected["ciphertextBytes"], "ciphertext bytes")),
		expectedDataFrameCount: integer(expected["dataFrameCount"], "data frame count"),
		wrappingContextDigest: text(expected["wrappingContextDigest"], "context digest"),
		ciphertextSha256: text(expected["ciphertextSha256"], "ciphertext digest"),
	};
}

function latch(): Latch {
	let release!: () => void;
	const promise = new Promise<void>((resolve) => {
		release = resolve;
	});
	return { promise, release };
}

class FixedDataKeyProvider implements DataKeyProvider {
	readonly #key: KeyObject;
	readonly #wrappedKey: Uint8Array;
	readonly #keyReference: string;
	readonly #wrappingAlgorithm: string;
	#lastContext: Uint8Array | undefined;
	#closed = false;
	#generateCalls = 0;
	#unwrapCalls = 0;

	constructor(options: {
		readonly dek?: Uint8Array;
		readonly wrappedKey?: Uint8Array;
		readonly keyReference?: string;
		readonly wrappingAlgorithm?: string;
	}) {
		this.#key = createSecretKey(options.dek ?? DEFAULT_DEK);
		this.#wrappedKey = new Uint8Array(options.wrappedKey ?? DEFAULT_WRAPPER);
		this.#keyReference = options.keyReference ?? "fixture-key";
		this.#wrappingAlgorithm = options.wrappingAlgorithm ?? "TEST-WRAP";
	}

	get generateCalls(): number {
		return this.#generateCalls;
	}

	get unwrapCalls(): number {
		return this.#unwrapCalls;
	}

	get closed(): boolean {
		return this.#closed;
	}

	generateDataKey(context: DataKeyContext): Promise<GeneratedDataKey> {
		this.#generateCalls += 1;
		this.#lastContext = new Uint8Array(context.wrappingContext);
		return Promise.resolve({
			plaintextKey: this.#key,
			wrappedKey: new Uint8Array(this.#wrappedKey),
			keyReference: this.#keyReference,
			wrappingAlgorithm: this.#wrappingAlgorithm,
		});
	}

	unwrapDataKey(dataKey: WrappedDataKey, context: DataKeyContext): Promise<KeyObject> {
		this.#unwrapCalls += 1;
		if (
			dataKey.keyReference !== this.#keyReference ||
			dataKey.wrappingAlgorithm !== this.#wrappingAlgorithm ||
			!Buffer.from(dataKey.wrappedKey).equals(this.#wrappedKey) ||
			this.#lastContext === undefined ||
			!Buffer.from(context.wrappingContext).equals(this.#lastContext)
		) {
			return Promise.reject(authenticationFailed());
		}
		return Promise.resolve(this.#key);
	}

	close(): void {
		this.#closed = true;
		this.#lastContext?.fill(0);
	}
}

class BlockingDataKeyProvider implements DataKeyProvider {
	readonly #key = createSecretKey(DEFAULT_DEK);
	readonly #generateEntered = latch();
	readonly #generateRelease = latch();
	readonly #unwrapEntered = latch();
	readonly #unwrapRelease = latch();
	#closed = false;

	get generateEntered(): Promise<void> {
		return this.#generateEntered.promise;
	}

	get unwrapEntered(): Promise<void> {
		return this.#unwrapEntered.promise;
	}

	get closed(): boolean {
		return this.#closed;
	}

	releaseGenerate(): void {
		this.#generateRelease.release();
	}

	releaseUnwrap(): void {
		this.#unwrapRelease.release();
	}

	async generateDataKey(_context: DataKeyContext): Promise<GeneratedDataKey> {
		this.#generateEntered.release();
		await this.#generateRelease.promise;
		return {
			plaintextKey: this.#key,
			wrappedKey: new Uint8Array(DEFAULT_WRAPPER),
			keyReference: "fixture-key",
			wrappingAlgorithm: "TEST-WRAP",
		};
	}

	async unwrapDataKey(_dataKey: WrappedDataKey, _context: DataKeyContext): Promise<KeyObject> {
		this.#unwrapEntered.release();
		await this.#unwrapRelease.promise;
		return this.#key;
	}

	close(): void {
		this.#closed = true;
	}
}

class RecordingDataKeyProvider implements DataKeyProvider {
	readonly #delegate: DataKeyProvider;
	readonly #generatedKeyFingerprints: string[] = [];

	constructor(delegate: DataKeyProvider) {
		this.#delegate = delegate;
	}

	get generatedKeyFingerprints(): readonly string[] {
		return this.#generatedKeyFingerprints;
	}

	async generateDataKey(context: DataKeyContext): Promise<GeneratedDataKey> {
		const generated = await this.#delegate.generateDataKey(context);
		const raw = Buffer.from(generated.plaintextKey.export());
		try {
			this.#generatedKeyFingerprints.push(createHash("sha256").update(raw).digest("hex"));
		} finally {
			raw.fill(0);
		}
		return generated;
	}

	unwrapDataKey(dataKey: WrappedDataKey, context: DataKeyContext): Promise<KeyObject> {
		return this.#delegate.unwrapDataKey(dataKey, context);
	}
}

function harness(
	options: {
		readonly providerName?: string;
		readonly dek?: Uint8Array;
		readonly wrappedKey?: Uint8Array;
		readonly keyReference?: string;
		readonly wrappingAlgorithm?: string;
		readonly noncePrefix?: Uint8Array;
		readonly maxPlaintextBytes?: bigint;
	} = {},
): { readonly engine: FileCipherEngine; readonly provider: FixedDataKeyProvider } {
	const providerName = options.providerName ?? "fixture";
	const provider = new FixedDataKeyProvider(options);
	const noncePrefix = new Uint8Array(options.noncePrefix ?? DEFAULT_NONCE_PREFIX);
	const engine = new FileCipherEngine({
		providers: [{ name: providerName, provider }],
		defaultProvider: providerName,
		maxPlaintextBytes: options.maxPlaintextBytes ?? BigInt(NMF1_CHUNK_BYTES * 4),
		randomBytes: (length) => {
			if (length !== 8) throw new Error("Unexpected random-byte request.");
			return new Uint8Array(noncePrefix);
		},
	});
	return { engine, provider };
}

async function* fragmented(
	value: Uint8Array,
	widths: readonly number[] = [0, 1, 7, 31, 4_099, 65_537],
): AsyncGenerator<Uint8Array> {
	let offset = 0;
	let index = 0;
	while (offset < value.byteLength) {
		const width = widths[index % widths.length] ?? 1;
		index += 1;
		if (width === 0) {
			yield new Uint8Array();
			continue;
		}
		const end = Math.min(value.byteLength, offset + width);
		yield new Uint8Array(value.subarray(offset, end));
		offset = end;
	}
	if (value.byteLength === 0) yield new Uint8Array();
}

async function* seededFragments(value: Uint8Array, seed: number): AsyncGenerator<Uint8Array> {
	let state = seed >>> 0;
	let offset = 0;
	let first = true;
	yield new Uint8Array();
	while (offset < value.byteLength) {
		state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
		if ((state & 7) === 0) yield new Uint8Array();
		const randomWidth = 1 + (state % 131_071);
		const width =
			first && value.byteLength > 1 ? Math.min(randomWidth, value.byteLength - 1) : randomWidth;
		const end = Math.min(value.byteLength, offset + width);
		yield value.subarray(offset, end);
		offset = end;
		first = false;
	}
}

async function* splitAt(value: Uint8Array, split: number): AsyncGenerator<Uint8Array> {
	yield value.subarray(0, split);
	yield value.subarray(split);
}

async function* merged(
	value: Uint8Array,
	onNext: () => void = () => undefined,
): AsyncGenerator<Uint8Array> {
	onNext();
	yield value;
	onNext();
}

async function* byteFragments(value: Uint8Array): AsyncGenerator<Uint8Array> {
	for (let index = 0; index < value.byteLength; index += 1) {
		yield value.subarray(index, index + 1);
	}
}

async function* failingSource(): AsyncGenerator<Uint8Array> {
	yield Uint8Array.of(1, 2, 3);
	throw new Error("source sentinel");
}

async function* failingAfter(value: Uint8Array): AsyncGenerator<Uint8Array> {
	yield value;
	throw new Error("retry sentinel");
}

function webSource(chunks: readonly Uint8Array[]): WebSourceProbe {
	let index = 0;
	let pullCount = 0;
	let wasCancelled = false;
	return {
		stream: new ReadableStream<Uint8Array>(
			{
				pull(controller) {
					pullCount += 1;
					const chunk = chunks[index];
					index += 1;
					if (chunk === undefined) controller.close();
					else controller.enqueue(new Uint8Array(chunk));
				},
				cancel() {
					wasCancelled = true;
				},
			},
			{ highWaterMark: 0 },
		),
		pulls: () => pullCount,
		cancelled: () => wasCancelled,
	};
}

function pattern(length: number): Uint8Array {
	return Uint8Array.from({ length }, (_, index) => (index * 131 + 17) & 0xff);
}

async function readAll(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
	const reader = stream.getReader();
	const parts: Uint8Array[] = [];
	try {
		for (;;) {
			const result = await reader.read();
			if (result.done) return concatFileBytes(...parts);
			parts.push(new Uint8Array(result.value));
		}
	} finally {
		reader.releaseLock();
	}
}

function decryptInput(
	detachedKey: DetachedFileKey,
	overrides: Partial<FileDecryptInput> = {},
): FileDecryptInput {
	return {
		aad: DEFAULT_AAD,
		detachedKey,
		allowedProviders: [detachedKey.provider],
		...overrides,
	};
}

function flip(source: Uint8Array, index: number): Uint8Array {
	const copy = new Uint8Array(source);
	copy[index] = (copy[index] ?? 0) ^ 0x80;
	return copy;
}

function overwrite(source: Uint8Array, offset: number, values: readonly number[]): Uint8Array {
	const copy = new Uint8Array(source);
	copy.set(values, offset);
	return copy;
}

function deterministicBytes(length: number, seed: number): Uint8Array {
	let state = seed >>> 0;
	const output = new Uint8Array(length);
	for (let index = 0; index < length; index += 1) {
		state = (Math.imul(state, 1_103_515_245) + 12_345) >>> 0;
		output[index] = state >>> 24;
	}
	return output;
}

async function expectStreamFailure(
	engine: FileCipherEngine,
	ciphertext: Uint8Array,
	input: FileDecryptInput,
	code: string,
): Promise<void> {
	const result = await engine.decrypt(fragmented(ciphertext), input);
	await expect(readAll(result.plaintext)).rejects.toMatchObject({ code });
	await expect(result.verification).rejects.toMatchObject({ code });
}

describe("FileCipherEngine", () => {
	it.each([
		"V01-empty.json",
		"V02-one-byte.json",
		"V03-mixed-binary.json",
		"V04-chunk-minus-one.json",
		"V05-exact-chunk.json",
		"V06-chunk-plus-one.json",
		"V07-two-chunks-plus-seventeen.json",
		"V08-null-workspace.json",
		"V09a-owner-context-a.json",
		"V09b-owner-context-b.json",
	])("matches and opens exact conformance vector %s", async (filename) => {
		const vector = loadVector(filename);
		const { engine, provider } = harness({
			providerName: vector.provider,
			dek: vector.dek,
			wrappedKey: vector.wrappedKey,
			keyReference: vector.keyReference,
			wrappingAlgorithm: vector.wrappingAlgorithm,
			noncePrefix: vector.noncePrefix,
		});
		const encrypted = await engine.encrypt(seededFragments(vector.plaintext, 0x4e4d_4631), {
			aad: vector.aad,
			expectedPlaintextBytes: BigInt(vector.plaintext.byteLength),
		});
		expect(encrypted.headerBytes).toEqual(vector.expectedHeader);
		expect(encrypted.detachedKey.wrappedKey).toEqual(vector.wrappedKey);
		expect(encrypted.wrappingContextDigest).toBe(vector.wrappingContextDigest);
		const ciphertext = await readAll(encrypted.encrypted);
		if (vector.expectedNmf1 !== undefined) expect(ciphertext).toEqual(vector.expectedNmf1);
		expect(BigInt(ciphertext.byteLength)).toBe(vector.expectedCiphertextBytes);
		expect(createHash("sha256").update(ciphertext).digest("hex")).toBe(vector.ciphertextSha256);
		await expect(encrypted.completion).resolves.toMatchObject({
			plaintextBytes: BigInt(vector.plaintext.byteLength),
			ciphertextBytes: vector.expectedCiphertextBytes,
			dataFrameCount: vector.expectedDataFrameCount,
			ciphertextSha256: vector.ciphertextSha256,
		});

		const decrypted = await engine.decrypt(seededFragments(ciphertext, 0x9e37_79b9), {
			aad: vector.aad,
			detachedKey: encrypted.detachedKey,
			allowedProviders: [vector.provider],
			expectedHeaderBytes: vector.expectedHeader,
			expectedPlaintextBytes: BigInt(vector.plaintext.byteLength),
			expectedCiphertextBytes: BigInt(ciphertext.byteLength),
			expectedCiphertextSha256: vector.ciphertextSha256,
		});
		expect(await readAll(decrypted.plaintext)).toEqual(vector.plaintext);
		await expect(decrypted.verification).resolves.toMatchObject({
			authenticated: true,
			ciphertextSha256: vector.ciphertextSha256,
		});
		expect(provider.generateCalls).toBe(1);
		expect(provider.unwrapCalls).toBe(1);
		await engine.close();
	});

	it.each(["V01-empty.json", "V02-one-byte.json", "V03-mixed-binary.json"])(
		"accepts every source and ciphertext split point for %s",
		async (filename) => {
			const vector = loadVector(filename);
			if (vector.expectedNmf1 === undefined) throw new Error("Small vector lacks exact bytes.");
			for (let split = 0; split <= vector.plaintext.byteLength; split += 1) {
				const { engine } = harness({
					providerName: vector.provider,
					dek: vector.dek,
					wrappedKey: vector.wrappedKey,
					keyReference: vector.keyReference,
					wrappingAlgorithm: vector.wrappingAlgorithm,
					noncePrefix: vector.noncePrefix,
				});
				const encrypted = await engine.encrypt(splitAt(vector.plaintext, split), {
					aad: vector.aad,
				});
				expect(await readAll(encrypted.encrypted)).toEqual(vector.expectedNmf1);
				await encrypted.completion;
				await engine.close();
			}

			for (let split = 0; split <= vector.expectedNmf1.byteLength; split += 1) {
				const { engine } = harness({
					providerName: vector.provider,
					dek: vector.dek,
					wrappedKey: vector.wrappedKey,
					keyReference: vector.keyReference,
					wrappingAlgorithm: vector.wrappingAlgorithm,
					noncePrefix: vector.noncePrefix,
				});
				const primed = await engine.encrypt(splitAt(new Uint8Array(), 0), { aad: vector.aad });
				await readAll(primed.encrypted);
				await primed.completion;
				const decrypted = await engine.decrypt(splitAt(vector.expectedNmf1, split), {
					aad: vector.aad,
					detachedKey: {
						version: 1,
						provider: vector.provider,
						keyReference: vector.keyReference,
						wrappingAlgorithm: vector.wrappingAlgorithm,
						wrappedKey: vector.wrappedKey,
					},
					allowedProviders: [vector.provider],
					expectedHeaderBytes: vector.expectedHeader,
				});
				expect(await readAll(decrypted.plaintext)).toEqual(vector.plaintext);
				await decrypted.verification;
				await engine.close();
			}
		},
	);

	it("V10 uses fresh production randomness for every retry attempt", async () => {
		const provider = new RecordingDataKeyProvider(
			new AesKeyRingProvider({
				activeKeyId: "domain-key-v1",
				keys: { "domain-key-v1": Uint8Array.from({ length: 32 }, (_, index) => index + 1) },
			}),
		);
		const engine = new FileCipherEngine({
			providers: [{ name: "nestm-domain", provider }],
			defaultProvider: "nestm-domain",
			maxPlaintextBytes: BigInt(NMF1_CHUNK_BYTES),
		});
		const plaintext = pattern(4_097);
		const failed = await engine.encrypt(failingAfter(plaintext), { aad: DEFAULT_AAD });
		await expect(readAll(failed.encrypted)).rejects.toMatchObject({ code: "CIPHER_FAILURE" });
		await expect(failed.completion).rejects.toMatchObject({ code: "CIPHER_FAILURE" });
		const first = await engine.encrypt(fragmented(plaintext), { aad: DEFAULT_AAD });
		const firstCiphertext = await readAll(first.encrypted);
		await first.completion;
		const second = await engine.encrypt(fragmented(plaintext), { aad: DEFAULT_AAD });
		const secondCiphertext = await readAll(second.encrypted);
		await second.completion;

		expect(provider.generatedKeyFingerprints).toHaveLength(3);
		expect(new Set(provider.generatedKeyFingerprints).size).toBe(3);
		const attempts = [failed, first, second] as const;
		expect(
			new Set(attempts.map((attempt) => Buffer.from(attempt.header.noncePrefix).toString("hex")))
				.size,
		).toBe(3);
		expect(
			new Set(
				attempts.map((attempt) =>
					Buffer.from(attempt.detachedKey.wrappedKey.subarray(1, 33)).toString("hex"),
				),
			).size,
		).toBe(3);
		for (const attempt of attempts) expect(attempt.detachedKey.wrappedKey).toHaveLength(81);
		expect(
			new Set(
				attempts.map((attempt) => Buffer.from(attempt.detachedKey.wrappedKey).toString("hex")),
			).size,
		).toBe(3);
		expect(firstCiphertext).not.toEqual(secondCiphertext);
		for (const [ciphertext, result] of [
			[firstCiphertext, first],
			[secondCiphertext, second],
		] as const) {
			const decrypted = await engine.decrypt(fragmented(ciphertext), {
				aad: DEFAULT_AAD,
				detachedKey: result.detachedKey,
				allowedProviders: ["nestm-domain"],
				expectedHeaderBytes: result.headerBytes,
			});
			expect(await readAll(decrypted.plaintext)).toEqual(plaintext);
			await decrypted.verification;
		}
		await engine.close();
	});

	it.each([
		["empty AsyncIterable", 0, false],
		["small fragmented AsyncIterable", 333, false],
		["C-1 Web stream", NMF1_CHUNK_BYTES - 1, true],
		["C Web stream", NMF1_CHUNK_BYTES, true],
		["C+1 Web stream", NMF1_CHUNK_BYTES + 1, true],
	] as const)("round trips %s", async (_name, length, useWebStream) => {
		const plaintext = pattern(length);
		const { engine } = harness();
		const web = webSource([
			plaintext.subarray(0, Math.min(17, plaintext.byteLength)),
			plaintext.subarray(Math.min(17, plaintext.byteLength)),
		]);
		const source = useWebStream ? web.stream : fragmented(plaintext);
		const encrypted = await engine.encrypt(source, {
			aad: DEFAULT_AAD,
			expectedPlaintextBytes: BigInt(length),
		});
		const ciphertext = await readAll(encrypted.encrypted);
		const summary = await encrypted.completion;
		expect(summary.plaintextBytes).toBe(BigInt(length));
		expect(summary.ciphertextBytes).toBe(engine.encryptedFileSize(BigInt(length)));
		expect(summary.dataFrameCount).toBe(length === 0 ? 0 : Math.ceil(length / NMF1_CHUNK_BYTES));

		const encryptedWeb = webSource([
			ciphertext.subarray(0, 19),
			ciphertext.subarray(19, Math.min(70_003, ciphertext.byteLength)),
			ciphertext.subarray(Math.min(70_003, ciphertext.byteLength)),
		]);
		const decrypted = await engine.decrypt(encryptedWeb.stream, {
			...decryptInput(encrypted.detachedKey),
			expectedHeaderBytes: encrypted.headerBytes,
			expectedPlaintextBytes: BigInt(length),
			expectedCiphertextBytes: BigInt(ciphertext.byteLength),
			expectedCiphertextSha256: summary.ciphertextSha256,
		});
		expect(await readAll(decrypted.plaintext)).toEqual(plaintext);
		await expect(decrypted.verification).resolves.toEqual(summary);
		await engine.close();
	});

	it("keeps operation bytes independent from caller mutations", async () => {
		const vector = loadVector("V02-one-byte.json");
		const { engine } = harness({
			providerName: vector.provider,
			dek: vector.dek,
			wrappedKey: vector.wrappedKey,
			keyReference: vector.keyReference,
			wrappingAlgorithm: vector.wrappingAlgorithm,
			noncePrefix: vector.noncePrefix,
		});
		const encrypted = await engine.encrypt(fragmented(vector.plaintext), { aad: vector.aad });
		encrypted.headerBytes.fill(0xff);
		encrypted.header.noncePrefix.fill(0xff);
		encrypted.header.fileContextDigest.fill(0xff);
		encrypted.detachedKey.wrappedKey.fill(0xff);
		expect(await readAll(encrypted.encrypted)).toEqual(vector.expectedNmf1);
		await expect(encrypted.completion).resolves.toMatchObject({ authenticated: true });
		await engine.close();
	});

	it("enforces expected header, plaintext size, ciphertext size, and ciphertext digest", async () => {
		const { engine } = harness();
		const encrypted = await engine.encrypt(fragmented(Uint8Array.from([4, 5, 6])), {
			aad: DEFAULT_AAD,
		});
		const ciphertext = await readAll(encrypted.encrypted);
		const summary = await encrypted.completion;

		await expect(
			engine.decrypt(fragmented(ciphertext), {
				...decryptInput(encrypted.detachedKey),
				expectedHeaderBytes: flip(encrypted.headerBytes, 0),
			}),
		).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
		await expectStreamFailure(
			engine,
			ciphertext,
			decryptInput(encrypted.detachedKey, { expectedPlaintextBytes: 4n }),
			"AUTHENTICATION_FAILED",
		);
		await expectStreamFailure(
			engine,
			ciphertext,
			decryptInput(encrypted.detachedKey, {
				expectedCiphertextBytes: BigInt(ciphertext.byteLength + 1),
			}),
			"AUTHENTICATION_FAILED",
		);
		await expectStreamFailure(
			engine,
			ciphertext,
			decryptInput(encrypted.detachedKey, {
				expectedCiphertextSha256: `${summary.ciphertextSha256.slice(0, 63)}0`,
			}),
			"AUTHENTICATION_FAILED",
		);
		await engine.close();
	});

	it("rejects AAD, wrapper, frame, final, trailing, truncation, and reordering tamper", async () => {
		const { engine } = harness();
		const plaintext = pattern(NMF1_CHUNK_BYTES + 1);
		const encrypted = await engine.encrypt(fragmented(plaintext, [NMF1_CHUNK_BYTES, 1]), {
			aad: DEFAULT_AAD,
		});
		const ciphertext = await readAll(encrypted.encrypted);
		await encrypted.completion;

		await expect(
			engine.decrypt(
				fragmented(ciphertext),
				decryptInput(encrypted.detachedKey, { aad: Uint8Array.from([0x10, 0x20, 0x31]) }),
			),
		).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
		const wrongWrapper: DetachedFileKey = {
			...encrypted.detachedKey,
			wrappedKey: flip(encrypted.detachedKey.wrappedKey, 1),
		};
		await expect(
			engine.decrypt(fragmented(ciphertext), decryptInput(wrongWrapper)),
		).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });

		await expectStreamFailure(
			engine,
			flip(ciphertext, NMF1_HEADER_BYTES + 7),
			decryptInput(encrypted.detachedKey),
			"MALFORMED_ENVELOPE",
		);
		await expectStreamFailure(
			engine,
			flip(ciphertext, NMF1_HEADER_BYTES + 12),
			decryptInput(encrypted.detachedKey),
			"AUTHENTICATION_FAILED",
		);
		await expectStreamFailure(
			engine,
			flip(ciphertext, ciphertext.byteLength - 1),
			decryptInput(encrypted.detachedKey),
			"AUTHENTICATION_FAILED",
		);
		await expectStreamFailure(
			engine,
			concatFileBytes(ciphertext, Uint8Array.of(0)),
			decryptInput(encrypted.detachedKey),
			"MALFORMED_ENVELOPE",
		);
		await expectStreamFailure(
			engine,
			ciphertext.subarray(0, ciphertext.byteLength - 1),
			decryptInput(encrypted.detachedKey),
			"MALFORMED_ENVELOPE",
		);

		const firstEnd = NMF1_HEADER_BYTES + 12 + NMF1_CHUNK_BYTES + 16;
		const secondEnd = firstEnd + 12 + 1 + 16;
		const reordered = concatFileBytes(
			ciphertext.subarray(0, NMF1_HEADER_BYTES),
			ciphertext.subarray(firstEnd, secondEnd),
			ciphertext.subarray(NMF1_HEADER_BYTES, firstEnd),
			ciphertext.subarray(secondEnd),
		);
		await expectStreamFailure(
			engine,
			reordered,
			decryptInput(encrypted.detachedKey),
			"MALFORMED_ENVELOPE",
		);
		await engine.close();
	});

	it("fails closed under bounded deterministic parser mutation and fragmentation fuzzing", async () => {
		const { engine } = harness();
		const plaintext = pattern(8_193);
		const encrypted = await engine.encrypt(fragmented(plaintext), { aad: DEFAULT_AAD });
		const ciphertext = await readAll(encrypted.encrypted);
		const summary = await encrypted.completion;
		const candidates: Uint8Array[] = [];
		for (let index = 0; index < 24; index += 1) {
			const length = (index * 8_191) % 65_537;
			candidates.push(deterministicBytes(length, 0x6d2b_79f5 ^ index));
		}
		for (let index = 0; index < 48; index += 1) {
			const tailLength = (index * 4_093) % 65_537;
			candidates.push(
				concatFileBytes(encrypted.headerBytes, deterministicBytes(tailLength, 0x85eb_ca6b ^ index)),
			);
		}
		for (let index = 0; index < 48; index += 1) {
			const position = (Math.imul(index + 1, 2_654_435_761) >>> 0) % ciphertext.byteLength;
			candidates.push(flip(ciphertext, position));
		}
		const dataHeaderOffset = NMF1_HEADER_BYTES;
		const finalHeaderOffset = NMF1_HEADER_BYTES + 12 + plaintext.byteLength + 16;
		for (let offset = dataHeaderOffset; offset < dataHeaderOffset + 12; offset += 1) {
			candidates.push(flip(ciphertext, offset));
		}
		for (let offset = finalHeaderOffset; offset < finalHeaderOffset + 16; offset += 1) {
			candidates.push(flip(ciphertext, offset));
		}
		candidates.push(
			overwrite(ciphertext, dataHeaderOffset + 8, [0xff, 0xff, 0xff, 0xff]),
			overwrite(ciphertext, finalHeaderOffset + 4, [0xff, 0xff, 0xff, 0xff]),
			overwrite(
				ciphertext,
				finalHeaderOffset + 8,
				[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
			),
		);
		for (const [index, candidate] of candidates.entries()) {
			let result;
			try {
				result = await engine.decrypt(seededFragments(candidate, 0xa5a5_0000 ^ index), {
					...decryptInput(encrypted.detachedKey),
					...(index < 24 ? {} : { expectedHeaderBytes: encrypted.headerBytes }),
					expectedPlaintextBytes: BigInt(plaintext.byteLength),
					expectedCiphertextBytes: BigInt(ciphertext.byteLength),
					expectedCiphertextSha256: summary.ciphertextSha256,
				});
			} catch (error: unknown) {
				expect(error).toBeInstanceOf(CryptoError);
				continue;
			}
			await expect(readAll(result.plaintext)).rejects.toBeInstanceOf(CryptoError);
			await expect(result.verification).rejects.toBeInstanceOf(CryptoError);
		}
		await engine.close();
	});

	it("emits an authenticated full-frame prefix but withholds success and the last frame", async () => {
		const { engine } = harness();
		const plaintext = pattern(NMF1_CHUNK_BYTES + 1);
		const encrypted = await engine.encrypt(fragmented(plaintext, [NMF1_CHUNK_BYTES, 1]), {
			aad: DEFAULT_AAD,
		});
		const ciphertext = await readAll(encrypted.encrypted);
		await encrypted.completion;
		const damagedFinal = flip(ciphertext, ciphertext.byteLength - 1);
		const decrypted = await engine.decrypt(
			fragmented(damagedFinal),
			decryptInput(encrypted.detachedKey),
		);
		const reader = decrypted.plaintext.getReader();
		const first = await reader.read();
		expect(first.done).toBe(false);
		expect(first.value).toEqual(plaintext.subarray(0, NMF1_CHUNK_BYTES));
		await expect(reader.read()).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
		await expect(decrypted.verification).rejects.toMatchObject({
			code: "AUTHENTICATION_FAILED",
		});
		reader.releaseLock();
		await engine.close();
	});

	it("keeps internal buffering bounded across merged frames and one-byte fragments", async () => {
		const { engine } = harness();
		const plaintext = pattern(2 * NMF1_CHUNK_BYTES + 17);
		const original = new Uint8Array(plaintext);
		let sourceNextCalls = 0;
		const encrypted = await engine.encrypt(
			merged(plaintext, () => {
				sourceNextCalls += 1;
			}),
			{ aad: DEFAULT_AAD },
		);
		const reader = encrypted.encrypted.getReader();
		const ciphertextParts: Uint8Array[] = [];
		try {
			for (const expectedBytes of [
				NMF1_HEADER_BYTES,
				NMF1_CHUNK_BYTES + 28,
				NMF1_CHUNK_BYTES + 28,
				17 + 28,
				32,
			]) {
				const next = await reader.read();
				expect(next.done).toBe(false);
				expect(next.value?.byteLength).toBe(expectedBytes);
				if (next.value !== undefined) ciphertextParts.push(new Uint8Array(next.value));
			}
			expect((await reader.read()).done).toBe(true);
		} finally {
			reader.releaseLock();
		}
		const ciphertext = concatFileBytes(...ciphertextParts);
		await encrypted.completion;
		expect(sourceNextCalls).toBe(2);
		expect(plaintext).toEqual(original);

		const decrypted = await engine.decrypt(merged(ciphertext), {
			...decryptInput(encrypted.detachedKey),
			expectedHeaderBytes: encrypted.headerBytes,
		});
		expect(await readAll(decrypted.plaintext)).toEqual(plaintext);
		await decrypted.verification;

		const tinyPlaintext = pattern(8_193);
		const tinyEncrypted = await engine.encrypt(byteFragments(tinyPlaintext), {
			aad: DEFAULT_AAD,
		});
		const tinyCiphertext = await readAll(tinyEncrypted.encrypted);
		await tinyEncrypted.completion;
		const tinyDecrypted = await engine.decrypt(byteFragments(tinyCiphertext), {
			...decryptInput(tinyEncrypted.detachedKey),
			expectedHeaderBytes: tinyEncrypted.headerBytes,
		});
		expect(await readAll(tinyDecrypted.plaintext)).toEqual(tinyPlaintext);
		await tinyDecrypted.verification;
		await engine.close();
	});

	it("propagates source failure, cancellation, and bounded output backpressure", async () => {
		const { engine } = harness();
		const failed = await engine.encrypt(failingSource(), { aad: DEFAULT_AAD });
		await expect(readAll(failed.encrypted)).rejects.toMatchObject({ code: "CIPHER_FAILURE" });
		await expect(failed.completion).rejects.toMatchObject({ code: "CIPHER_FAILURE" });

		const probe = webSource([
			pattern(NMF1_CHUNK_BYTES),
			pattern(NMF1_CHUNK_BYTES),
			pattern(NMF1_CHUNK_BYTES),
		]);
		const active = await engine.encrypt(probe.stream, { aad: DEFAULT_AAD });
		await Promise.resolve();
		expect(probe.pulls()).toBe(0);
		const reader = active.encrypted.getReader();
		expect((await reader.read()).value?.byteLength).toBe(NMF1_HEADER_BYTES);
		await Promise.resolve();
		await Promise.resolve();
		expect(probe.pulls()).toBe(1);
		expect((await reader.read()).value?.byteLength).toBe(NMF1_CHUNK_BYTES + 28);
		await Promise.resolve();
		await Promise.resolve();
		expect(probe.pulls()).toBe(2);
		await reader.cancel("test cancellation");
		await expect(active.completion).rejects.toMatchObject({ code: "ABORTED" });
		expect(probe.cancelled()).toBe(true);

		const directProbe = webSource([pattern(NMF1_CHUNK_BYTES)]);
		const directlyCancelled = await engine.encrypt(directProbe.stream, { aad: DEFAULT_AAD });
		await Promise.all([
			directlyCancelled.cancel("direct cancellation"),
			directlyCancelled.cancel("direct cancellation"),
		]);
		await expect(directlyCancelled.completion).rejects.toMatchObject({ code: "ABORTED" });
		expect(directProbe.cancelled()).toBe(true);
		await engine.close();
	});

	it("owns provider-bound encrypt and decrypt calls before close begins", async () => {
		const encryptProvider = new BlockingDataKeyProvider();
		const encryptEngine = new FileCipherEngine({
			providers: [{ name: "fixture", provider: encryptProvider }],
			defaultProvider: "fixture",
			maxPlaintextBytes: 1n,
			randomBytes: () => new Uint8Array(DEFAULT_NONCE_PREFIX),
		});
		const pendingEncrypt = encryptEngine.encrypt(fragmented(new Uint8Array()), {
			aad: DEFAULT_AAD,
		});
		await encryptProvider.generateEntered;
		const closingEncryptEngine = encryptEngine.close();
		expect(encryptEngine.close()).toBe(closingEncryptEngine);
		await expect(pendingEncrypt).rejects.toMatchObject({ code: "ABORTED" });
		await closingEncryptEngine;
		expect(encryptProvider.closed).toBe(true);
		encryptProvider.releaseGenerate();
		await Promise.resolve();

		const setup = harness();
		const encrypted = await setup.engine.encrypt(fragmented(Uint8Array.of(1)), {
			aad: DEFAULT_AAD,
		});
		const ciphertext = await readAll(encrypted.encrypted);
		await encrypted.completion;
		await setup.engine.close();

		const decryptProvider = new BlockingDataKeyProvider();
		const decryptEngine = new FileCipherEngine({
			providers: [{ name: "fixture", provider: decryptProvider }],
			defaultProvider: "fixture",
			maxPlaintextBytes: 1n,
		});
		const pendingDecrypt = decryptEngine.decrypt(
			fragmented(ciphertext),
			decryptInput(encrypted.detachedKey),
		);
		await decryptProvider.unwrapEntered;
		const closingDecryptEngine = decryptEngine.close();
		expect(decryptEngine.close()).toBe(closingDecryptEngine);
		await expect(pendingDecrypt).rejects.toMatchObject({ code: "ABORTED" });
		await closingDecryptEngine;
		expect(decryptProvider.closed).toBe(true);
		decryptProvider.releaseUnwrap();
		await Promise.resolve();
	});

	it("linearizes reentrant source cancellation and observes aborted source failures", async () => {
		const factorySetup = harness();
		let factoryClose: Promise<void> | undefined;
		let iteratorReturns = 0;
		const closingSource: AsyncIterable<Uint8Array> = {
			[Symbol.asyncIterator]() {
				factoryClose = factorySetup.engine.close();
				return {
					next: () => Promise.resolve({ done: false, value: Uint8Array.of(1) }),
					return: () => {
						iteratorReturns += 1;
						return Promise.resolve({ done: true, value: undefined });
					},
				};
			},
		};
		await expect(
			factorySetup.engine.encrypt(closingSource, { aad: DEFAULT_AAD }),
		).rejects.toMatchObject({ code: "ABORTED" });
		expect(factoryClose).toBeDefined();
		await factoryClose;
		expect(iteratorReturns).toBe(1);

		const cancelSetup = harness();
		let cancelAgain: ((reason?: unknown) => Promise<void>) | undefined;
		let sourceCancelCalls = 0;
		const reentrantSource = new ReadableStream<Uint8Array>(
			{
				cancel() {
					sourceCancelCalls += 1;
					void cancelAgain?.("reentrant source cancellation");
				},
			},
			{ highWaterMark: 0 },
		);
		const cancellable = await cancelSetup.engine.encrypt(reentrantSource, { aad: DEFAULT_AAD });
		cancelAgain = (reason) => cancellable.cancel(reason);
		const cancelling = cancellable.cancel("outer cancellation");
		expect(cancellable.cancel("duplicate cancellation")).toBe(cancelling);
		await cancelling;
		await expect(cancellable.completion).rejects.toMatchObject({ code: "ABORTED" });
		expect(sourceCancelCalls).toBe(1);
		await cancelSetup.engine.close();

		const abortSetup = harness();
		const controller = new AbortController();
		let abortIteratorReturns = 0;
		const abortingSource: AsyncIterable<Uint8Array> = {
			[Symbol.asyncIterator]() {
				return {
					next() {
						controller.abort("source aborted while returning its read promise");
						return Promise.reject(new Error("raw source rejection"));
					},
					return() {
						abortIteratorReturns += 1;
						return Promise.resolve({ done: true, value: undefined });
					},
				};
			},
		};
		const abortedResult = await abortSetup.engine.encrypt(abortingSource, {
			aad: DEFAULT_AAD,
			signal: controller.signal,
		});
		await expect(readAll(abortedResult.encrypted)).rejects.toMatchObject({ code: "ABORTED" });
		await expect(abortedResult.completion).rejects.toMatchObject({ code: "ABORTED" });
		expect(abortIteratorReturns).toBe(1);
		await abortSetup.engine.close();
	});

	it("enforces limits, provider allowlists, and closed-engine behavior", async () => {
		const { engine, provider } = harness({ maxPlaintextBytes: 1n });
		expect(engine.encryptedFileSize(1n)).toBe(113n);
		expect(() => engine.encryptedFileSize(2n)).toThrowError(CryptoError);
		const tooLarge = await engine.encrypt(fragmented(Uint8Array.of(1, 2)), { aad: DEFAULT_AAD });
		await expect(readAll(tooLarge.encrypted)).rejects.toMatchObject({ code: "LIMIT_EXCEEDED" });
		await expect(tooLarge.completion).rejects.toMatchObject({ code: "LIMIT_EXCEEDED" });

		const allowed = await engine.encrypt(fragmented(Uint8Array.of(1)), { aad: DEFAULT_AAD });
		const ciphertext = await readAll(allowed.encrypted);
		await allowed.completion;
		await expect(
			engine.decrypt(fragmented(ciphertext), {
				...decryptInput(allowed.detachedKey),
				allowedProviders: ["different-provider"],
			}),
		).rejects.toMatchObject({ code: "PROVIDER_NOT_FOUND" });
		await expect(
			engine.encrypt(fragmented(Uint8Array.of(1)), {
				aad: DEFAULT_AAD,
				provider: "missing-provider",
			}),
		).rejects.toMatchObject({ code: "PROVIDER_NOT_FOUND" });

		const abandoned = await engine.encrypt(fragmented(new Uint8Array()), { aad: DEFAULT_AAD });
		await engine.close();
		await expect(abandoned.completion).rejects.toMatchObject({ code: "ABORTED" });
		expect(provider.closed).toBe(true);
		expect(() => engine.encryptedFileSize(0n)).toThrowError(CryptoError);
		await expect(
			engine.encrypt(fragmented(new Uint8Array()), { aad: DEFAULT_AAD }),
		).rejects.toMatchObject({ code: "CIPHER_FAILURE" });
	});
});
