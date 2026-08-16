import { createHash, randomBytes as cryptoRandomBytes, KeyObject } from "node:crypto";
import { Aes256GcmCipher } from "../core/aes-256-gcm.js";
import {
	authenticationFailed,
	CryptoError,
	isCryptoError,
	providerCall,
	throwIfAborted,
} from "../core/errors.js";
import type {
	DataKeyProvider,
	GeneratedDataKey,
	KeyProviderRegistration,
	WrappedDataKey,
} from "../core/types.js";
import {
	NMF1_CHUNK_BYTES,
	NMF1_DATA_FRAME_HEADER_BYTES,
	NMF1_DATA_FRAME_TYPE,
	NMF1_FINAL_FRAME_HEADER_BYTES,
	NMF1_FINAL_FRAME_TYPE,
	NMF1_FORMAT_MAX_PLAINTEXT_BYTES,
	NMF1_HEADER_BYTES,
	NMF1_MAGIC,
	NMF1_TAG_BYTES,
	assertFileContext,
	assertNmf1PlaintextLimit,
	captureFileAad,
	concatFileBytes,
	copyFileBytes,
	encodeDataFrameHeader,
	encodeFileHeader,
	encodeFinalFrameHeader,
	equalFileBytes,
	frameAuthenticatedData,
	frameNonce,
	isLowercaseSha256,
	isStableFileBytes,
	nmf1EncryptedFileSize,
	parseDataFrameHeader,
	parseFileHeader,
	parseFinalFrameHeader,
	providerWrappingContext,
	wrappingContextDigest,
} from "./format.js";
import type {
	DetachedFileKey,
	FileByteSource,
	FileCipherEngineOptions,
	FileDecryptInput,
	FileDecryptResult,
	FileEncryptionSummary,
	FileEncryptInput,
	FileEncryptResult,
	FileHeaderInfo,
	FileSizeOptions,
} from "./types.js";

const MAX_WRAPPED_KEY_BYTES = 65_536;
const MAX_PROVIDER_NAME_BYTES = 128;
const MAX_KEY_REFERENCE_BYTES = 1_024;
const MAX_WRAPPING_ALGORITHM_BYTES = 128;
const cipher = new Aes256GcmCipher();

interface Deferred<Value> {
	readonly promise: Promise<Value>;
	readonly resolve: (value: Value) => void;
	readonly reject: (reason: unknown) => void;
	readonly settled: () => boolean;
}

interface SourceReader {
	next(signal: AbortSignal): Promise<IteratorResult<Uint8Array>>;
	cancel(reason?: unknown): Promise<void>;
	release(): void;
}

function deferred<Value>(): Deferred<Value> {
	let resolvePromise!: (value: Value) => void;
	let rejectPromise!: (reason: unknown) => void;
	let isSettled = false;
	const promise = new Promise<Value>((resolve, reject) => {
		resolvePromise = resolve;
		rejectPromise = reject;
	});
	// A caller receives the original rejecting promise. This observation only prevents
	// an abandoned stream from becoming a process-level unhandled rejection.
	void promise.catch(() => undefined);
	return {
		promise,
		resolve: (value) => {
			if (isSettled) return;
			isSettled = true;
			resolvePromise(value);
		},
		reject: (reason) => {
			if (isSettled) return;
			isSettled = true;
			rejectPromise(reason);
		},
		settled: () => isSettled,
	};
}

function aborted(reason?: unknown): CryptoError {
	return new CryptoError(
		"ABORTED",
		"The cryptographic operation was aborted.",
		reason === undefined ? {} : { cause: reason },
	);
}

async function abortable<Value>(pending: Promise<Value>, signal: AbortSignal): Promise<Value> {
	return new Promise<Value>((resolve, reject) => {
		let settled = false;
		const finish = (callback: () => void): void => {
			if (settled) return;
			settled = true;
			signal.removeEventListener("abort", onAbort);
			callback();
		};
		const onAbort = (): void => finish(() => reject(aborted(signal.reason)));
		signal.addEventListener("abort", onAbort, { once: true });
		if (signal.aborted) onAbort();
		void pending.then(
			(value) => finish(() => resolve(value)),
			(error: unknown) => finish(() => reject(error)),
		);
	});
}

function normalizeSourceError(error: unknown): CryptoError {
	if (isCryptoError(error)) return error;
	return new CryptoError("CIPHER_FAILURE", "The file byte source failed.", { cause: error });
}

function normalizeExternalSourceError(error: unknown, signal: AbortSignal): CryptoError {
	if (signal.aborted || isCryptoError(error, "ABORTED")) return aborted(signal.reason);
	return new CryptoError("CIPHER_FAILURE", "The file byte source failed.", { cause: error });
}

function sourceChunk(value: unknown): Uint8Array {
	if (!isStableFileBytes(value)) {
		throw new CryptoError("INVALID_ARGUMENT", "The file byte source emitted a non-byte chunk.");
	}
	return value;
}

function sourceReader(source: FileByteSource): SourceReader {
	try {
		if (source instanceof ReadableStream) {
			const reader = source.getReader();
			let released = false;
			return {
				async next(signal) {
					let result: ReadableStreamReadResult<Uint8Array>;
					try {
						result = await abortable(reader.read(), signal);
					} catch (error: unknown) {
						throw normalizeExternalSourceError(error, signal);
					}
					if (result.done) return { done: true, value: undefined };
					return { done: false, value: sourceChunk(result.value) };
				},
				async cancel(reason) {
					try {
						await reader.cancel(reason);
					} catch {
						// Cancellation is best effort; the primary operation still rejects as ABORTED.
					}
				},
				release() {
					if (released) return;
					released = true;
					try {
						reader.releaseLock();
					} catch {
						// A completed/cancelled reader may already have released its lock.
					}
				},
			};
		}

		if (typeof source !== "object" || source === null) throw new TypeError("Missing source.");
		const iteratorFactory = source[Symbol.asyncIterator];
		if (typeof iteratorFactory !== "function") throw new TypeError("Missing async iterator.");
		const iterator = iteratorFactory.call(source);
		if (typeof iterator !== "object" || iterator === null || typeof iterator.next !== "function") {
			throw new TypeError("Invalid async iterator.");
		}
		let released = false;
		return {
			async next(signal) {
				let result: IteratorResult<Uint8Array>;
				try {
					result = await abortable(Promise.resolve(iterator.next()), signal);
					if (typeof result !== "object" || result === null || typeof result.done !== "boolean") {
						throw new TypeError("Invalid iterator result.");
					}
				} catch (error: unknown) {
					throw normalizeExternalSourceError(error, signal);
				}
				if (result.done) return { done: true, value: undefined };
				return { done: false, value: sourceChunk(result.value) };
			},
			async cancel(reason) {
				try {
					await iterator.return?.(reason);
				} catch {
					// Cancellation is best effort; the primary operation still rejects as ABORTED.
				}
			},
			release() {
				if (released) return;
				released = true;
			},
		};
	} catch (error: unknown) {
		throw new CryptoError("INVALID_ARGUMENT", "A file byte source is required.", { cause: error });
	}
}

class SourceCursor {
	readonly #reader: SourceReader;
	#current: Uint8Array | undefined;
	#currentOffset = 0;
	#ended = false;
	#released = false;
	#cancelPromise: Promise<void> | undefined;

	constructor(reader: SourceReader) {
		this.#reader = reader;
	}

	async exact(length: number, signal: AbortSignal): Promise<Uint8Array> {
		this.#assertLength(length);
		if (length === 0) return new Uint8Array();
		const output = new Uint8Array(length);
		try {
			const written = await this.#copyInto(output, signal);
			if (written !== length) {
				throw new CryptoError("MALFORMED_ENVELOPE", "The NMF1 object is truncated.");
			}
			return output;
		} catch (error: unknown) {
			output.fill(0);
			throw error;
		}
	}

	async upTo(length: number, signal: AbortSignal): Promise<Uint8Array> {
		this.#assertLength(length);
		if (length === 0 || !(await this.#ensureCurrent(signal))) return new Uint8Array();
		const output = new Uint8Array(length);
		try {
			const written = await this.#copyInto(output, signal);
			return written === length ? output : output.subarray(0, written);
		} catch (error: unknown) {
			output.fill(0);
			throw error;
		}
	}

	async requirePhysicalEof(signal: AbortSignal): Promise<void> {
		if (await this.#ensureCurrent(signal)) {
			throw new CryptoError("MALFORMED_ENVELOPE", "The NMF1 object has trailing bytes.");
		}
	}

	cancel(reason?: unknown): Promise<void> {
		if (this.#cancelPromise !== undefined) return this.#cancelPromise;
		this.#current = undefined;
		this.#currentOffset = 0;
		this.#cancelPromise = Promise.resolve()
			.then(() => this.#reader.cancel(reason))
			.finally(() => this.#releaseReader());
		return this.#cancelPromise;
	}

	release(): void {
		this.#current = undefined;
		this.#currentOffset = 0;
		this.#releaseReader();
	}

	#assertLength(length: number): void {
		if (!Number.isSafeInteger(length) || length < 0) {
			throw new CryptoError("CIPHER_FAILURE", "An internal NMF1 read length is invalid.");
		}
	}

	async #copyInto(output: Uint8Array, signal: AbortSignal): Promise<number> {
		let written = 0;
		while (written < output.byteLength && (await this.#ensureCurrent(signal))) {
			const current = this.#current;
			if (current === undefined) break;
			const available = current.byteLength - this.#currentOffset;
			const count = Math.min(available, output.byteLength - written);
			output.set(current.subarray(this.#currentOffset, this.#currentOffset + count), written);
			written += count;
			this.#currentOffset += count;
			if (this.#currentOffset === current.byteLength) {
				this.#current = undefined;
				this.#currentOffset = 0;
			}
		}
		return written;
	}

	async #ensureCurrent(signal: AbortSignal): Promise<boolean> {
		while (this.#current === undefined && !this.#ended) {
			const result = await this.#reader.next(signal);
			if (result.done) {
				this.#ended = true;
				break;
			}
			if (result.value.byteLength === 0) continue;
			this.#current = result.value;
			this.#currentOffset = 0;
		}
		return this.#current !== undefined;
	}

	#releaseReader(): void {
		if (this.#released) return;
		this.#released = true;
		this.#reader.release();
	}
}

function validIdentifier(value: unknown, maximumBytes: number): value is string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.trim() !== value ||
		/\p{Cc}/u.test(value)
	) {
		return false;
	}
	return Buffer.byteLength(value, "utf8") <= maximumBytes;
}

function assertProvider(provider: unknown): asserts provider is DataKeyProvider {
	try {
		if (
			typeof provider !== "object" ||
			provider === null ||
			typeof (provider as Partial<DataKeyProvider>).generateDataKey !== "function" ||
			typeof (provider as Partial<DataKeyProvider>).unwrapDataKey !== "function" ||
			((provider as Partial<DataKeyProvider>).close !== undefined &&
				typeof (provider as Partial<DataKeyProvider>).close !== "function")
		) {
			throw new TypeError("Invalid provider.");
		}
	} catch (error: unknown) {
		throw new CryptoError("CONFIGURATION", "A file key-provider registration is invalid.", {
			cause: error,
		});
	}
}

function providerRegistry(
	registrations: readonly KeyProviderRegistration[],
): ReadonlyMap<string, DataKeyProvider> {
	if (!Array.isArray(registrations) || registrations.length === 0) {
		throw new CryptoError("CONFIGURATION", "At least one file key provider is required.");
	}
	const providers = new Map<string, DataKeyProvider>();
	for (const registration of registrations) {
		try {
			if (typeof registration !== "object" || registration === null) {
				throw new TypeError("Invalid registration.");
			}
			if (!validIdentifier(registration.name, MAX_PROVIDER_NAME_BYTES)) {
				throw new TypeError("Invalid provider name.");
			}
			assertProvider(registration.provider);
			if (providers.has(registration.name)) throw new TypeError("Duplicate provider name.");
			providers.set(registration.name, registration.provider);
		} catch (error: unknown) {
			if (isCryptoError(error)) throw error;
			throw new CryptoError("CONFIGURATION", "A file key-provider registration is invalid.", {
				cause: error,
			});
		}
	}
	return providers;
}

function captureGeneratedDataKey(value: unknown): GeneratedDataKey {
	try {
		if (typeof value !== "object" || value === null) throw new TypeError("Invalid data key.");
		const candidate = value as Partial<GeneratedDataKey>;
		if (
			!(candidate.plaintextKey instanceof KeyObject) ||
			candidate.plaintextKey.type !== "secret" ||
			candidate.plaintextKey.symmetricKeySize !== 32 ||
			!isStableFileBytes(candidate.wrappedKey) ||
			candidate.wrappedKey.byteLength === 0 ||
			candidate.wrappedKey.byteLength > MAX_WRAPPED_KEY_BYTES ||
			!validIdentifier(candidate.keyReference, MAX_KEY_REFERENCE_BYTES) ||
			!validIdentifier(candidate.wrappingAlgorithm, MAX_WRAPPING_ALGORITHM_BYTES)
		) {
			throw new TypeError("Invalid generated data key.");
		}
		return Object.freeze({
			plaintextKey: candidate.plaintextKey,
			wrappedKey: new Uint8Array(candidate.wrappedKey),
			keyReference: candidate.keyReference,
			wrappingAlgorithm: candidate.wrappingAlgorithm,
		});
	} catch (error: unknown) {
		throw new CryptoError("INVALID_KEY", "The generated file data key is invalid.", {
			cause: error,
		});
	}
}

function captureUnwrappedDataKey(value: unknown): KeyObject {
	try {
		if (!(value instanceof KeyObject) || value.type !== "secret" || value.symmetricKeySize !== 32) {
			throw new TypeError("Invalid unwrapped key.");
		}
		return value;
	} catch (error: unknown) {
		throw new CryptoError("INVALID_KEY", "The unwrapped file data key is invalid.", {
			cause: error,
		});
	}
}

function captureDetachedKey(value: unknown): DetachedFileKey {
	try {
		if (typeof value !== "object" || value === null) throw new TypeError("Missing key.");
		const candidate = value as Partial<DetachedFileKey>;
		if (
			candidate.version !== 1 ||
			!validIdentifier(candidate.provider, MAX_PROVIDER_NAME_BYTES) ||
			!validIdentifier(candidate.keyReference, MAX_KEY_REFERENCE_BYTES) ||
			!validIdentifier(candidate.wrappingAlgorithm, MAX_WRAPPING_ALGORITHM_BYTES) ||
			!isStableFileBytes(candidate.wrappedKey) ||
			candidate.wrappedKey.byteLength === 0 ||
			candidate.wrappedKey.byteLength > MAX_WRAPPED_KEY_BYTES
		) {
			throw new TypeError("Invalid detached key.");
		}
		return Object.freeze({
			version: 1,
			provider: candidate.provider,
			keyReference: candidate.keyReference,
			wrappingAlgorithm: candidate.wrappingAlgorithm,
			wrappedKey: new Uint8Array(candidate.wrappedKey),
		});
	} catch (error: unknown) {
		throw new CryptoError("INVALID_KEY", "The detached file key is invalid.", { cause: error });
	}
}

function validateExpectedSize(value: unknown, label: string): bigint | undefined {
	if (value === undefined) return undefined;
	if (typeof value !== "bigint" || value < 0n) {
		throw new CryptoError("INVALID_ARGUMENT", `${label} is invalid.`);
	}
	return value;
}

function fileSummary(
	dataFrameCount: number,
	plaintextBytes: bigint,
	ciphertextBytes: bigint,
	ciphertextSha256: string,
): FileEncryptionSummary {
	return Object.freeze({
		format: NMF1_MAGIC,
		dataFrameCount,
		plaintextBytes,
		ciphertextBytes,
		ciphertextSha256,
		authenticated: true,
	});
}

function streamFromIterator(
	iterator: AsyncGenerator<Uint8Array, void>,
	cancel: (reason?: unknown) => Promise<void>,
): ReadableStream<Uint8Array> {
	return new ReadableStream<Uint8Array>(
		{
			async pull(controller) {
				try {
					const result = await iterator.next();
					if (result.done) controller.close();
					else controller.enqueue(result.value);
				} catch (error: unknown) {
					controller.error(error);
				}
			},
			async cancel(reason) {
				await cancel(reason);
				try {
					await iterator.return(undefined);
				} catch {
					// The operation's completion/verification promise carries the sanitized failure.
				}
			},
		},
		{ highWaterMark: 1 },
	);
}

function operationController(external?: AbortSignal): {
	readonly controller: AbortController;
	readonly dispose: () => void;
} {
	const controller = new AbortController();
	const onAbort = (): void => controller.abort(external?.reason);
	if (external !== undefined) {
		if (external.aborted) onAbort();
		else external.addEventListener("abort", onAbort, { once: true });
	}
	return {
		controller,
		dispose: () => external?.removeEventListener("abort", onAbort),
	};
}

class ActiveFileOperation {
	readonly controller: AbortController;
	readonly #dispose: () => void;
	readonly #onAbort: () => void;
	readonly #onFinish: (operation: ActiveFileOperation) => void;
	#cursor: SourceCursor | undefined;
	#iterator: AsyncGenerator<Uint8Array, void> | undefined;
	#reject: ((reason: unknown) => void) | undefined;
	#cleanup: (() => void) | undefined;
	#cancelPromise: Promise<void> | undefined;
	#finished = false;

	constructor(
		external: AbortSignal | undefined,
		onFinish: (operation: ActiveFileOperation) => void,
	) {
		const operation = operationController(external);
		this.controller = operation.controller;
		this.#dispose = operation.dispose;
		this.#onFinish = onFinish;
		this.#onAbort = () => void this.cancel(this.controller.signal.reason);
		this.controller.signal.addEventListener("abort", this.#onAbort, { once: true });
	}

	start(): void {
		if (this.controller.signal.aborted) this.#onAbort();
	}

	bindCursor(cursor: SourceCursor): void {
		this.#cursor = cursor;
	}

	bindIterator(iterator: AsyncGenerator<Uint8Array, void>): void {
		this.#iterator = iterator;
	}

	bindRejection(reject: (reason: unknown) => void): void {
		this.#reject = reject;
	}

	bindCleanup(cleanup: () => void): void {
		this.#cleanup = cleanup;
	}

	cancel(reason?: unknown): Promise<void> {
		if (this.#finished) return Promise.resolve();
		if (this.#cancelPromise !== undefined) return this.#cancelPromise;
		this.#cancelPromise = Promise.resolve()
			.then(async () => {
				await this.#cursor?.cancel(reason);
				try {
					await this.#iterator?.return(undefined);
				} catch {
					// Completion/verification carries the sanitized ABORTED result.
				}
			})
			.finally(() => this.finish());
		this.controller.signal.removeEventListener("abort", this.#onAbort);
		if (!this.controller.signal.aborted) this.controller.abort(reason);
		this.#reject?.(aborted(reason));
		return this.#cancelPromise;
	}

	finish(): void {
		if (this.#finished) return;
		this.#finished = true;
		this.controller.signal.removeEventListener("abort", this.#onAbort);
		this.#dispose();
		try {
			this.#cleanup?.();
		} finally {
			this.#cursor = undefined;
			this.#iterator = undefined;
			this.#reject = undefined;
			this.#cleanup = undefined;
			this.#onFinish(this);
		}
	}
}

export class FileCipherEngine {
	readonly #providers: ReadonlyMap<string, DataKeyProvider>;
	readonly #defaultProvider: string;
	readonly #maxPlaintextBytes: bigint;
	readonly #randomBytes: (length: number) => Uint8Array;
	readonly #active = new Set<ActiveFileOperation>();
	#closed = false;
	#closePromise: Promise<void> | undefined;

	constructor(options: FileCipherEngineOptions) {
		if (typeof options !== "object" || options === null) {
			throw new CryptoError("CONFIGURATION", "File cipher engine options are required.");
		}
		this.#providers = providerRegistry(options.providers);
		if (!validIdentifier(options.defaultProvider, MAX_PROVIDER_NAME_BYTES)) {
			throw new CryptoError("CONFIGURATION", "The default file key provider is invalid.");
		}
		if (!this.#providers.has(options.defaultProvider)) {
			throw new CryptoError("CONFIGURATION", "The default file key provider is not registered.");
		}
		if (
			typeof options.maxPlaintextBytes !== "bigint" ||
			options.maxPlaintextBytes < 0n ||
			options.maxPlaintextBytes > NMF1_FORMAT_MAX_PLAINTEXT_BYTES
		) {
			throw new CryptoError("CONFIGURATION", "The file plaintext limit is invalid.");
		}
		if (options.randomBytes !== undefined && typeof options.randomBytes !== "function") {
			throw new CryptoError("CONFIGURATION", "The file random-byte source is invalid.");
		}
		this.#defaultProvider = options.defaultProvider;
		this.#maxPlaintextBytes = options.maxPlaintextBytes;
		this.#randomBytes = options.randomBytes ?? cryptoRandomBytes;
	}

	encryptedFileSize(plaintextBytes: bigint, options: FileSizeOptions = {}): bigint {
		this.#assertOpen();
		if (options.format !== undefined && options.format !== NMF1_MAGIC) {
			throw new CryptoError("INVALID_ARGUMENT", "The encrypted-file format is unsupported.");
		}
		assertNmf1PlaintextLimit(plaintextBytes, this.#maxPlaintextBytes);
		return nmf1EncryptedFileSize(plaintextBytes);
	}

	inspectFileHeader(prefix: Uint8Array): FileHeaderInfo {
		this.#assertOpen();
		return parseFileHeader(prefix);
	}

	async encrypt(source: FileByteSource, input: FileEncryptInput): Promise<FileEncryptResult> {
		this.#assertOpen();
		if (typeof input !== "object" || input === null) {
			throw new CryptoError("INVALID_ARGUMENT", "File encryption input is required.");
		}
		const aad = captureFileAad(input.aad);
		const expectedPlaintextBytes = validateExpectedSize(
			input.expectedPlaintextBytes,
			"The expected plaintext length",
		);
		if (expectedPlaintextBytes !== undefined) {
			assertNmf1PlaintextLimit(expectedPlaintextBytes, this.#maxPlaintextBytes);
		}
		const providerName = input.provider ?? this.#defaultProvider;
		if (!validIdentifier(providerName, MAX_PROVIDER_NAME_BYTES)) {
			aad.fill(0);
			throw new CryptoError("INVALID_ARGUMENT", "The file key provider is invalid.");
		}
		const provider = this.#providers.get(providerName);
		if (provider === undefined) {
			aad.fill(0);
			throw new CryptoError("PROVIDER_NOT_FOUND", "The file key provider was not found.");
		}
		let cursor: SourceCursor | undefined;
		let headerBytes: Uint8Array | undefined;
		const operation = this.#beginOperation(input.signal);
		try {
			throwIfAborted(operation.controller.signal);
			cursor = new SourceCursor(sourceReader(source));
			operation.bindCursor(cursor);
			operation.bindCleanup(() => {
				aad.fill(0);
				headerBytes?.fill(0);
				cursor?.release();
			});
			let randomPrefix: Uint8Array;
			try {
				randomPrefix = copyFileBytes(this.#randomBytes(8), "NMF1 nonce prefix");
				if (randomPrefix.byteLength !== 8) throw new TypeError("Wrong nonce length.");
			} catch (error: unknown) {
				throw new CryptoError(
					"CIPHER_FAILURE",
					"The NMF1 nonce source returned an invalid prefix.",
					{
						cause: error,
					},
				);
			}
			headerBytes = encodeFileHeader(randomPrefix, aad);
			randomPrefix.fill(0);
			const context = providerWrappingContext(aad, headerBytes);
			const contextDigest = wrappingContextDigest(context);
			let generated: GeneratedDataKey;
			try {
				generated = await providerCall(
					async () =>
						captureGeneratedDataKey(
							await provider.generateDataKey({
								wrappingContext: context,
								signal: operation.controller.signal,
							}),
						),
					operation.controller.signal,
				);
			} finally {
				context.fill(0);
			}
			const detachedInternal: DetachedFileKey = Object.freeze({
				version: 1,
				provider: providerName,
				keyReference: generated.keyReference,
				wrappingAlgorithm: generated.wrappingAlgorithm,
				wrappedKey: new Uint8Array(generated.wrappedKey),
			});
			const completion = deferred<FileEncryptionSummary>();
			operation.bindRejection(completion.reject);
			const encrypting = this.#encryptGenerator(
				cursor,
				aad,
				headerBytes,
				generated.plaintextKey,
				expectedPlaintextBytes,
				operation.controller.signal,
				(summary) => completion.resolve(summary),
				(error) => completion.reject(error),
				() => this.#finishOperation(operation),
			);
			operation.bindIterator(encrypting);
			const cancel = (reason?: unknown): Promise<void> => operation.cancel(reason);
			const encrypted = streamFromIterator(encrypting, cancel);
			const inspected = parseFileHeader(headerBytes);
			return Object.freeze({
				encrypted,
				detachedKey: Object.freeze({
					...detachedInternal,
					wrappedKey: new Uint8Array(detachedInternal.wrappedKey),
				}),
				header: inspected,
				headerBytes: new Uint8Array(headerBytes),
				wrappingContextDigest: contextDigest,
				completion: completion.promise,
				cancel,
			});
		} catch (error: unknown) {
			aad.fill(0);
			await operation.cancel(error);
			this.#finishOperation(operation);
			throw error;
		}
	}

	async decrypt(source: FileByteSource, input: FileDecryptInput): Promise<FileDecryptResult> {
		this.#assertOpen();
		if (typeof input !== "object" || input === null) {
			throw new CryptoError("INVALID_ARGUMENT", "File decryption input is required.");
		}
		const aad = captureFileAad(input.aad);
		const detachedKey = captureDetachedKey(input.detachedKey);
		const expectedPlaintextBytes = validateExpectedSize(
			input.expectedPlaintextBytes,
			"The expected plaintext length",
		);
		if (expectedPlaintextBytes !== undefined) {
			assertNmf1PlaintextLimit(expectedPlaintextBytes, this.#maxPlaintextBytes);
		}
		const expectedCiphertextBytes = validateExpectedSize(
			input.expectedCiphertextBytes,
			"The expected ciphertext length",
		);
		if (
			input.expectedCiphertextSha256 !== undefined &&
			!isLowercaseSha256(input.expectedCiphertextSha256)
		) {
			aad.fill(0);
			throw new CryptoError("INVALID_ARGUMENT", "The expected ciphertext digest is invalid.");
		}
		let expectedHeader: Uint8Array | undefined;
		if (input.expectedHeaderBytes !== undefined) {
			expectedHeader = copyFileBytes(input.expectedHeaderBytes, "Expected NMF1 header");
			if (expectedHeader.byteLength !== NMF1_HEADER_BYTES) {
				aad.fill(0);
				expectedHeader.fill(0);
				throw authenticationFailed();
			}
		}
		if (!Array.isArray(input.allowedProviders) || input.allowedProviders.length === 0) {
			aad.fill(0);
			expectedHeader?.fill(0);
			throw new CryptoError("INVALID_ARGUMENT", "At least one allowed file provider is required.");
		}
		const allowedProviders = new Set<string>();
		for (const allowed of input.allowedProviders) {
			if (!validIdentifier(allowed, MAX_PROVIDER_NAME_BYTES)) {
				aad.fill(0);
				expectedHeader?.fill(0);
				throw new CryptoError("INVALID_ARGUMENT", "An allowed file provider is invalid.");
			}
			allowedProviders.add(allowed);
		}
		const operation = this.#beginOperation(input.signal);
		let cursor: SourceCursor | undefined;
		let headerBytes: Uint8Array | undefined;
		try {
			throwIfAborted(operation.controller.signal);
			cursor = new SourceCursor(sourceReader(source));
			operation.bindCursor(cursor);
			operation.bindCleanup(() => {
				aad.fill(0);
				headerBytes?.fill(0);
				expectedHeader?.fill(0);
				detachedKey.wrappedKey.fill(0);
				cursor?.release();
			});
			headerBytes = await cursor.exact(NMF1_HEADER_BYTES, operation.controller.signal);
			if (expectedHeader !== undefined && !equalFileBytes(headerBytes, expectedHeader)) {
				throw authenticationFailed();
			}
			const inspectedHeader = parseFileHeader(headerBytes);
			assertFileContext(inspectedHeader, aad);
			if (!allowedProviders.has(detachedKey.provider)) {
				throw new CryptoError(
					"PROVIDER_NOT_FOUND",
					"The detached file-key provider is not allowed.",
				);
			}
			const provider = this.#providers.get(detachedKey.provider);
			if (provider === undefined) {
				throw new CryptoError(
					"PROVIDER_NOT_FOUND",
					"The detached file-key provider was not found.",
				);
			}
			const context = providerWrappingContext(aad, headerBytes);
			let plaintextKey: KeyObject;
			try {
				const wrapped: WrappedDataKey = {
					wrappedKey: new Uint8Array(detachedKey.wrappedKey),
					keyReference: detachedKey.keyReference,
					wrappingAlgorithm: detachedKey.wrappingAlgorithm,
				};
				plaintextKey = await providerCall(
					async () =>
						captureUnwrappedDataKey(
							await provider.unwrapDataKey(wrapped, {
								wrappingContext: context,
								signal: operation.controller.signal,
							}),
						),
					operation.controller.signal,
				);
			} finally {
				context.fill(0);
			}
			const verification = deferred<FileEncryptionSummary>();
			operation.bindRejection(verification.reject);
			const decrypting = this.#decryptGenerator(
				cursor,
				aad,
				headerBytes,
				inspectedHeader,
				plaintextKey,
				expectedPlaintextBytes,
				expectedCiphertextBytes,
				input.expectedCiphertextSha256,
				operation.controller.signal,
				(summary) => verification.resolve(summary),
				(error) => verification.reject(error),
				() => this.#finishOperation(operation),
			);
			operation.bindIterator(decrypting);
			const cancel = (reason?: unknown): Promise<void> => operation.cancel(reason);
			return Object.freeze({
				plaintext: streamFromIterator(decrypting, cancel),
				inspectedHeader,
				verification: verification.promise,
				cancel,
			});
		} catch (error: unknown) {
			aad.fill(0);
			expectedHeader?.fill(0);
			detachedKey.wrappedKey.fill(0);
			await operation.cancel(error);
			this.#finishOperation(operation);
			throw error;
		}
	}

	close(): Promise<void> {
		if (this.#closePromise !== undefined) return this.#closePromise;
		this.#closed = true;
		const closing = deferred<void>();
		this.#closePromise = closing.promise;
		const cancellations = [...this.#active].map((operation) =>
			operation.cancel("File cipher engine closed."),
		);
		void (async () => {
			try {
				await Promise.all(cancellations);
				const providers = new Set(this.#providers.values());
				await Promise.all(
					[...providers].map((provider) =>
						providerCall(async () => {
							await provider.close?.();
						}),
					),
				);
				closing.resolve(undefined);
			} catch (error: unknown) {
				closing.reject(error);
			}
		})();
		return this.#closePromise;
	}

	async *#encryptGenerator(
		cursor: SourceCursor,
		aad: Uint8Array,
		headerBytes: Uint8Array,
		plaintextKey: KeyObject,
		expectedPlaintextBytes: bigint | undefined,
		signal: AbortSignal,
		resolve: (summary: FileEncryptionSummary) => void,
		reject: (error: unknown) => void,
		finalize: () => void,
	): AsyncGenerator<Uint8Array, void> {
		const hash = createHash("sha256");
		let plaintextBytes = 0n;
		let ciphertextBytes = 0n;
		let frameCount = 0;
		try {
			throwIfAborted(signal);
			const emittedHeader = new Uint8Array(headerBytes);
			hash.update(emittedHeader);
			ciphertextBytes += BigInt(emittedHeader.byteLength);
			yield emittedHeader;

			for (;;) {
				throwIfAborted(signal);
				const plaintext = await cursor.upTo(NMF1_CHUNK_BYTES, signal);
				if (plaintext.byteLength === 0) break;
				try {
					const projected = plaintextBytes + BigInt(plaintext.byteLength);
					assertNmf1PlaintextLimit(projected, this.#maxPlaintextBytes);
					if (expectedPlaintextBytes !== undefined && projected > expectedPlaintextBytes) {
						throw new CryptoError("INVALID_ARGUMENT", "The plaintext exceeds its expected length.");
					}
					const frameHeader = encodeDataFrameHeader(frameCount, plaintext.byteLength);
					const nonce = frameNonce(headerBytes.subarray(12, 20), frameCount);
					const frameAad = frameAuthenticatedData(headerBytes, aad, frameHeader);
					const encrypted = cipher.encrypt({
						plaintext,
						key: plaintextKey,
						nonce,
						aad: frameAad,
					});
					const serialized = concatFileBytes(frameHeader, encrypted.ciphertext, encrypted.tag);
					encrypted.ciphertext.fill(0);
					encrypted.tag.fill(0);
					hash.update(serialized);
					ciphertextBytes += BigInt(serialized.byteLength);
					plaintextBytes = projected;
					frameCount += 1;
					yield serialized;
				} finally {
					plaintext.fill(0);
				}
			}

			if (expectedPlaintextBytes !== undefined && plaintextBytes !== expectedPlaintextBytes) {
				throw new CryptoError(
					"INVALID_ARGUMENT",
					"The plaintext length does not match expectation.",
				);
			}
			const finalHeader = encodeFinalFrameHeader(frameCount, plaintextBytes);
			const finalEncrypted = cipher.encrypt({
				plaintext: new Uint8Array(),
				key: plaintextKey,
				nonce: frameNonce(headerBytes.subarray(12, 20), frameCount),
				aad: frameAuthenticatedData(headerBytes, aad, finalHeader),
			});
			const finalFrame = concatFileBytes(finalHeader, finalEncrypted.tag);
			finalEncrypted.ciphertext.fill(0);
			finalEncrypted.tag.fill(0);
			hash.update(finalFrame);
			ciphertextBytes += BigInt(finalFrame.byteLength);
			yield finalFrame;
			throwIfAborted(signal);
			resolve(fileSummary(frameCount, plaintextBytes, ciphertextBytes, hash.digest("hex")));
		} catch (error: unknown) {
			const normalized = normalizeSourceError(error);
			reject(normalized);
			await cursor.cancel(normalized);
			throw normalized;
		} finally {
			finalize();
		}
	}

	async *#decryptGenerator(
		cursor: SourceCursor,
		aad: Uint8Array,
		headerBytes: Uint8Array,
		inspectedHeader: FileHeaderInfo,
		plaintextKey: KeyObject,
		expectedPlaintextBytes: bigint | undefined,
		expectedCiphertextBytes: bigint | undefined,
		expectedCiphertextSha256: string | undefined,
		signal: AbortSignal,
		resolve: (summary: FileEncryptionSummary) => void,
		reject: (error: unknown) => void,
		finalize: () => void,
	): AsyncGenerator<Uint8Array, void> {
		const hash = createHash("sha256");
		hash.update(headerBytes);
		let ciphertextBytes = BigInt(headerBytes.byteLength);
		let plaintextBytes = 0n;
		let expectedFrameIndex = 0;
		let pending: Uint8Array | undefined;
		const read = async (length: number): Promise<Uint8Array> => {
			const bytes = await cursor.exact(length, signal);
			hash.update(bytes);
			ciphertextBytes += BigInt(bytes.byteLength);
			return bytes;
		};
		try {
			for (;;) {
				throwIfAborted(signal);
				const common = await read(4);
				const type = common[0];
				if (type === NMF1_DATA_FRAME_TYPE) {
					const remainder = await read(NMF1_DATA_FRAME_HEADER_BYTES - 4);
					const frameHeader = concatFileBytes(common, remainder);
					const parsed = parseDataFrameHeader(frameHeader);
					if (parsed.frameIndex !== expectedFrameIndex) {
						throw new CryptoError("MALFORMED_ENVELOPE", "NMF1 frame indices are not contiguous.");
					}
					if (pending !== undefined) {
						if (pending.byteLength !== NMF1_CHUNK_BYTES) {
							throw new CryptoError("MALFORMED_ENVELOPE", "A short NMF1 frame is not final.");
						}
						const ready = pending;
						pending = undefined;
						yield ready;
						throwIfAborted(signal);
					}
					const projected = plaintextBytes + BigInt(parsed.plaintextLength);
					assertNmf1PlaintextLimit(projected, this.#maxPlaintextBytes);
					if (expectedPlaintextBytes !== undefined && projected > expectedPlaintextBytes) {
						throw new CryptoError(
							"LIMIT_EXCEEDED",
							"The file exceeds its expected plaintext length.",
						);
					}
					const body = await read(parsed.plaintextLength + NMF1_TAG_BYTES);
					const plaintext = cipher.decrypt({
						ciphertext: body.subarray(0, parsed.plaintextLength),
						key: plaintextKey,
						nonce: frameNonce(inspectedHeader.noncePrefix, expectedFrameIndex),
						tag: body.subarray(parsed.plaintextLength),
						aad: frameAuthenticatedData(headerBytes, aad, frameHeader),
					});
					body.fill(0);
					pending = plaintext;
					plaintextBytes = projected;
					expectedFrameIndex += 1;
					continue;
				}

				if (type !== NMF1_FINAL_FRAME_TYPE) {
					throw new CryptoError("MALFORMED_ENVELOPE", "The NMF1 frame type is invalid.");
				}
				const remainder = await read(NMF1_FINAL_FRAME_HEADER_BYTES - 4);
				const finalHeader = concatFileBytes(common, remainder);
				const final = parseFinalFrameHeader(finalHeader);
				if (
					final.dataFrameCount !== expectedFrameIndex ||
					final.totalPlaintextLength !== plaintextBytes ||
					(expectedFrameIndex === 0 && (plaintextBytes !== 0n || pending !== undefined)) ||
					(expectedFrameIndex > 0 && pending === undefined)
				) {
					throw new CryptoError("MALFORMED_ENVELOPE", "The NMF1 final totals are inconsistent.");
				}
				if (expectedFrameIndex > 0) {
					const lastLength = BigInt(pending?.byteLength ?? 0);
					const canonical = BigInt(expectedFrameIndex - 1) * BigInt(NMF1_CHUNK_BYTES) + lastLength;
					if (
						lastLength < 1n ||
						lastLength > BigInt(NMF1_CHUNK_BYTES) ||
						canonical !== plaintextBytes
					) {
						throw new CryptoError("MALFORMED_ENVELOPE", "The NMF1 frame shape is not canonical.");
					}
				}
				const finalTag = await read(NMF1_TAG_BYTES);
				const empty = cipher.decrypt({
					ciphertext: new Uint8Array(),
					key: plaintextKey,
					nonce: frameNonce(inspectedHeader.noncePrefix, expectedFrameIndex),
					tag: finalTag,
					aad: frameAuthenticatedData(headerBytes, aad, finalHeader),
				});
				empty.fill(0);
				finalTag.fill(0);
				await cursor.requirePhysicalEof(signal);
				if (expectedPlaintextBytes !== undefined && plaintextBytes !== expectedPlaintextBytes) {
					throw authenticationFailed();
				}
				if (expectedCiphertextBytes !== undefined && ciphertextBytes !== expectedCiphertextBytes) {
					throw authenticationFailed();
				}
				const digest = hash.digest("hex");
				if (expectedCiphertextSha256 !== undefined && digest !== expectedCiphertextSha256) {
					throw authenticationFailed();
				}
				if (pending !== undefined) {
					const ready = pending;
					pending = undefined;
					yield ready;
					throwIfAborted(signal);
				}
				resolve(fileSummary(expectedFrameIndex, plaintextBytes, ciphertextBytes, digest));
				return;
			}
		} catch (error: unknown) {
			pending?.fill(0);
			const normalized = normalizeSourceError(error);
			reject(normalized);
			await cursor.cancel(normalized);
			throw normalized;
		} finally {
			finalize();
		}
	}

	#beginOperation(signal?: AbortSignal): ActiveFileOperation {
		this.#assertOpen();
		const operation = new ActiveFileOperation(signal, (finished) => this.#active.delete(finished));
		this.#active.add(operation);
		operation.start();
		return operation;
	}

	#finishOperation(operation: ActiveFileOperation): void {
		operation.finish();
	}

	#assertOpen(): void {
		if (this.#closed) {
			throw new CryptoError("CIPHER_FAILURE", "The file cipher engine is closed.");
		}
	}
}
