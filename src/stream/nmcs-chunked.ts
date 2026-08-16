import { KeyObject } from "node:crypto";
import { Aes256GcmCipher } from "../core/aes-256-gcm.js";
import { isStableBytes } from "../core/encoding.js";
import { authenticationFailed, CryptoError, throwIfAborted } from "../core/errors.js";
import type { CipherAad } from "../core/types.js";
import type { KeyWrapRecord } from "../keys/key-wrap-record.js";
import {
	assertByteLimit,
	assertChunkSizeCeiling,
	assertChunkSizeLog2,
	CHUNK_LENGTH_PREFIX_BYTES,
	CHUNK_OVERHEAD_BYTES,
	chunkAad,
	chunkNonce,
	contextAadBytes,
	decodeHeaderContent,
	deriveChunkSchedule,
	deriveHeaderSchedule,
	encodeHeaderContent,
	generateFileId,
	HEADER_CONTENT_BYTES,
	headerInfo,
	MAX_CHUNK_INDEX,
	NMCS_DEFAULT_CHUNK_SIZE_LOG2,
	NMCS_HEADER_BYTES,
	normalizeStreamKey,
	readFileIdOverride,
	TAG_BYTES,
	type ChunkedHeaderInfo,
	type HeaderFields,
} from "./nmcs-format.js";

export interface ChunkedSealOptions {
	/** Opaque key selector recorded in the authenticated header. */
	readonly keyReference: string;
	/** Application context bound into the header (never encrypted — it is associated data). */
	readonly aad?: CipherAad;
	readonly chunkSizeLog2?: number;
	/**
	 * Raises the chunk-size ceiling above the default of 24. Readers must opt in to the same
	 * ceiling, so anything written above the default is unreadable by a default reader.
	 */
	readonly maxChunkSizeLog2?: number;
	/** Declares the plaintext length in the header. Must match the payload exactly. */
	readonly plaintextLength?: number;
	/** Wrapped data keys carried inline so the object is self-contained. */
	readonly wrapRecords?: readonly KeyWrapRecord[];
	readonly maxPlaintextBytes?: number;
	readonly signal?: AbortSignal;
}

export interface ChunkedOpenOptions {
	readonly aad?: CipherAad;
	/** Enforced against the authenticated header when present. */
	readonly expectedKeyReference?: string;
	readonly maxPlaintextBytes?: number;
	readonly maxChunkSizeLog2?: number;
	readonly signal?: AbortSignal;
}

export interface InspectChunkedOptions {
	readonly maxChunkSizeLog2?: number;
}

/**
 * Byte accumulator for the streaming paths.
 *
 * Source writes are retained by reference and only copied when a frame is actually
 * consumed, so a chunk assembled from many small writes costs one copy of its own bytes
 * rather than one copy of the whole backlog per write.
 */
class ByteQueue {
	#parts: Uint8Array[] = [];
	#offset = 0;
	#byteLength = 0;

	get byteLength(): number {
		return this.#byteLength;
	}

	push(chunk: Uint8Array): void {
		if (chunk.byteLength === 0) return;
		this.#parts.push(chunk);
		this.#byteLength += chunk.byteLength;
	}

	/** Big-endian u32 at `position`, without consuming. Callers must check `byteLength`. */
	readUint32(position: number): number {
		let value = 0;
		for (let index = 0; index < 4; index += 1) {
			value = value * 0x100 + this.#byteAt(position + index);
		}
		return value;
	}

	/** Copy out and consume exactly `length` bytes. */
	take(length: number): Uint8Array {
		if (length > this.#byteLength) {
			throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream is truncated.");
		}
		const output = new Uint8Array(length);
		let written = 0;
		while (written < length) {
			const part = this.#parts[0] as Uint8Array;
			const available = part.byteLength - this.#offset;
			const wanted = Math.min(available, length - written);
			output.set(part.subarray(this.#offset, this.#offset + wanted), written);
			written += wanted;
			this.#offset += wanted;
			if (this.#offset === part.byteLength) {
				this.#parts.shift();
				this.#offset = 0;
			}
		}
		this.#byteLength -= length;
		return output;
	}

	#byteAt(position: number): number {
		let remaining = position + this.#offset;
		for (const part of this.#parts) {
			if (remaining < part.byteLength) return part[remaining] as number;
			remaining -= part.byteLength;
		}
		throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream is truncated.");
	}
}

/** Sealed byte length for a plaintext of `plaintextLength` bytes. */
export function chunkedCiphertextLength(
	plaintextLength: number,
	chunkSizeLog2: number = NMCS_DEFAULT_CHUNK_SIZE_LOG2,
): number {
	assertChunkSizeLog2(chunkSizeLog2);
	if (!Number.isInteger(plaintextLength) || plaintextLength < 0) {
		throw new CryptoError(
			"INVALID_ARGUMENT",
			"The plaintext length must be a non-negative integer.",
		);
	}
	const chunkSize = 2 ** chunkSizeLog2;
	const chunks = plaintextLength === 0 ? 1 : Math.ceil(plaintextLength / chunkSize);
	return NMCS_HEADER_BYTES + plaintextLength + chunks * CHUNK_OVERHEAD_BYTES;
}

/**
 * Exact inverse of {@link chunkedCiphertextLength}. Returns `undefined` when
 * `ciphertextLength` is not a value the format can produce, which lets callers
 * translate stored sizes back to plaintext sizes without reading the object.
 */
export function chunkedPlaintextLength(
	ciphertextLength: number,
	chunkSizeLog2: number = NMCS_DEFAULT_CHUNK_SIZE_LOG2,
): number | undefined {
	assertChunkSizeLog2(chunkSizeLog2);
	if (!Number.isInteger(ciphertextLength) || ciphertextLength < 0) return undefined;
	const body = ciphertextLength - NMCS_HEADER_BYTES;
	if (body < CHUNK_OVERHEAD_BYTES) return undefined;
	const chunkSize = 2 ** chunkSizeLog2;
	const perChunk = chunkSize + CHUNK_OVERHEAD_BYTES;
	// Full chunks first, then whatever remains must form exactly one final chunk.
	const fullChunks = Math.floor(body / perChunk);
	for (const chunks of [fullChunks, fullChunks + 1]) {
		if (chunks < 1) continue;
		const plaintext = body - chunks * CHUNK_OVERHEAD_BYTES;
		if (plaintext < 0) continue;
		if (chunkedCiphertextLength(plaintext, chunkSizeLog2) === ciphertextLength) return plaintext;
	}
	return undefined;
}

/** Ciphertext byte range of chunk `chunkIndex`, for range-read planning. */
export function chunkedChunkRange(
	chunkIndex: number,
	chunkSizeLog2: number = NMCS_DEFAULT_CHUNK_SIZE_LOG2,
): { start: number; end: number } {
	assertChunkSizeLog2(chunkSizeLog2);
	if (!Number.isInteger(chunkIndex) || chunkIndex < 0 || chunkIndex >= MAX_CHUNK_INDEX) {
		throw new CryptoError("INVALID_ARGUMENT", "The chunk index is out of range.");
	}
	const stride = 2 ** chunkSizeLog2 + CHUNK_OVERHEAD_BYTES;
	const start = NMCS_HEADER_BYTES + chunkIndex * stride;
	return { start, end: start + stride };
}

/** Untrusted framing metadata. Nothing is authenticated until an open succeeds. */
export function inspectChunked(
	headerPrefix: Uint8Array,
	options?: InspectChunkedOptions,
): ChunkedHeaderInfo {
	// A complete header includes its tag: accepting 496 bytes would report on a prefix that
	// no reader could ever authenticate.
	if (!isStableBytes(headerPrefix) || headerPrefix.byteLength < NMCS_HEADER_BYTES) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream header is truncated.");
	}
	const ceiling = assertChunkSizeCeiling(options?.maxChunkSizeLog2);
	return headerInfo(decodeHeaderContent(headerPrefix.subarray(0, HEADER_CONTENT_BYTES), ceiling));
}

interface SealContext {
	readonly header: Uint8Array;
	readonly chunkKey: KeyObject;
	readonly noncePrefix: Uint8Array;
	readonly chunkSize: number;
}

/** Build the full 512-byte header and the chunk key schedule it commits to. */
function beginSeal(key: KeyObject, options: ChunkedSealOptions): SealContext {
	const chunkSizeLog2 = assertChunkSizeLog2(
		options.chunkSizeLog2 ?? NMCS_DEFAULT_CHUNK_SIZE_LOG2,
		assertChunkSizeCeiling(options.maxChunkSizeLog2),
	);
	assertByteLimit(options.maxPlaintextBytes);
	if (options.plaintextLength !== undefined) {
		if (!Number.isSafeInteger(options.plaintextLength) || options.plaintextLength < 0) {
			throw new CryptoError("INVALID_ARGUMENT", "The declared plaintext length is invalid.");
		}
	}
	const override = readFileIdOverride(options);
	const fields: HeaderFields = {
		chunkSizeLog2,
		fileId: override ?? generateFileId(),
		keyReference: options.keyReference,
		contextAad: contextAadBytes(options.aad),
		wrapRecords: options.wrapRecords ?? [],
		...(options.plaintextLength === undefined ? {} : { plaintextLength: options.plaintextLength }),
	};
	const content = encodeHeaderContent(fields);
	const { headerKey, headerNonce } = deriveHeaderSchedule(key, fields.fileId);
	const { tag } = new Aes256GcmCipher().encrypt({
		plaintext: new Uint8Array(),
		key: headerKey,
		nonce: headerNonce,
		aad: content,
	});
	const header = new Uint8Array(NMCS_HEADER_BYTES);
	header.set(content, 0);
	header.set(tag, HEADER_CONTENT_BYTES);
	const { chunkKey, noncePrefix } = deriveChunkSchedule(key, content);
	return { header, chunkKey, noncePrefix, chunkSize: 2 ** chunkSizeLog2 };
}

/** Encode one chunk: `u32BE length ‖ ciphertext ‖ tag`. */
function sealChunk(
	context: SealContext,
	index: number,
	plaintext: Uint8Array,
	final: boolean,
): Uint8Array {
	if (index >= MAX_CHUNK_INDEX) {
		throw new CryptoError("LIMIT_EXCEEDED", "The chunked stream has too many chunks.");
	}
	const { ciphertext, tag } = new Aes256GcmCipher().encrypt({
		plaintext,
		key: context.chunkKey,
		nonce: chunkNonce(context.noncePrefix, index, final),
		aad: chunkAad(index, final, plaintext.byteLength),
	});
	const framed = new Uint8Array(CHUNK_LENGTH_PREFIX_BYTES + ciphertext.byteLength + TAG_BYTES);
	new DataView(framed.buffer).setUint32(0, ciphertext.byteLength, false);
	framed.set(ciphertext, CHUNK_LENGTH_PREFIX_BYTES);
	framed.set(tag, CHUNK_LENGTH_PREFIX_BYTES + ciphertext.byteLength);
	return framed;
}

export function sealChunked(
	key: KeyObject | Uint8Array,
	plaintext: Uint8Array,
	options: ChunkedSealOptions,
): Uint8Array {
	if (!isStableBytes(plaintext)) {
		throw new CryptoError("INVALID_ARGUMENT", "The chunked stream plaintext must be bytes.");
	}
	throwIfAborted(options.signal);
	const maxPlaintextBytes = assertByteLimit(options.maxPlaintextBytes);
	if (maxPlaintextBytes !== undefined && plaintext.byteLength > maxPlaintextBytes) {
		throw new CryptoError("LIMIT_EXCEEDED", "The plaintext exceeds the configured limit.");
	}
	// A declared length that contradicts the payload would produce an object whose own
	// header makes it permanently unopenable, so refuse it rather than emit it.
	if (options.plaintextLength !== undefined && options.plaintextLength !== plaintext.byteLength) {
		throw new CryptoError(
			"INVALID_ARGUMENT",
			"The declared plaintext length does not match the payload.",
		);
	}
	const streamKey = normalizeStreamKey(key);
	const context = beginSeal(streamKey, { ...options, plaintextLength: plaintext.byteLength });
	const parts: Uint8Array[] = [context.header];
	let index = 0;
	let offset = 0;
	do {
		throwIfAborted(options.signal);
		const end = Math.min(offset + context.chunkSize, plaintext.byteLength);
		const final = end >= plaintext.byteLength;
		parts.push(sealChunk(context, index, plaintext.subarray(offset, end), final));
		offset = end;
		index += 1;
	} while (offset < plaintext.byteLength);

	let total = 0;
	for (const part of parts) total += part.byteLength;
	const sealed = new Uint8Array(total);
	let cursor = 0;
	for (const part of parts) {
		sealed.set(part, cursor);
		cursor += part.byteLength;
	}
	return sealed;
}

interface OpenContext {
	readonly fields: HeaderFields;
	readonly chunkKey: KeyObject;
	readonly noncePrefix: Uint8Array;
	readonly chunkSize: number;
}

/** Verify the header tag and derive the chunk schedule it commits to. */
function beginOpen(
	key: KeyObject,
	header: Uint8Array,
	options: ChunkedOpenOptions | undefined,
): OpenContext {
	const content = header.subarray(0, HEADER_CONTENT_BYTES);
	// The chunk-size ceiling is enforced here, before a single chunk is buffered, so a
	// hostile header cannot make the reader hold an oversized frame in memory.
	const fields = decodeHeaderContent(content, assertChunkSizeCeiling(options?.maxChunkSizeLog2));
	const { headerKey, headerNonce } = deriveHeaderSchedule(key, fields.fileId);
	new Aes256GcmCipher().decrypt({
		ciphertext: new Uint8Array(),
		key: headerKey,
		nonce: headerNonce,
		tag: header.subarray(HEADER_CONTENT_BYTES, NMCS_HEADER_BYTES),
		aad: content,
	});

	// Only compare caller expectations after the header is authenticated.
	const expectedAad = contextAadBytes(options?.aad);
	if (
		expectedAad.byteLength !== fields.contextAad.byteLength ||
		!expectedAad.every((byte, index) => byte === fields.contextAad[index])
	) {
		throw authenticationFailed();
	}
	if (
		options?.expectedKeyReference !== undefined &&
		options.expectedKeyReference !== fields.keyReference
	) {
		throw authenticationFailed();
	}
	const maxPlaintextBytes = assertByteLimit(options?.maxPlaintextBytes);
	if (
		maxPlaintextBytes !== undefined &&
		fields.plaintextLength !== undefined &&
		fields.plaintextLength > maxPlaintextBytes
	) {
		throw new CryptoError("LIMIT_EXCEEDED", "The plaintext exceeds the configured limit.");
	}
	const { chunkKey, noncePrefix } = deriveChunkSchedule(key, content);
	return { fields, chunkKey, noncePrefix, chunkSize: 2 ** fields.chunkSizeLog2 };
}

function openChunk(
	context: OpenContext,
	index: number,
	ciphertext: Uint8Array,
	tag: Uint8Array,
	final: boolean,
): Uint8Array {
	if (index >= MAX_CHUNK_INDEX) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream has too many chunks.");
	}
	return new Aes256GcmCipher().decrypt({
		ciphertext,
		key: context.chunkKey,
		nonce: chunkNonce(context.noncePrefix, index, final),
		tag,
		aad: chunkAad(index, final, ciphertext.byteLength),
	});
}

export function openChunked(
	key: KeyObject | Uint8Array,
	sealed: Uint8Array,
	options?: ChunkedOpenOptions,
): Uint8Array {
	if (!isStableBytes(sealed)) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream must be bytes.");
	}
	if (sealed.byteLength < NMCS_HEADER_BYTES + CHUNK_OVERHEAD_BYTES) {
		throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream is truncated.");
	}
	throwIfAborted(options?.signal);
	const streamKey = normalizeStreamKey(key);
	const context = beginOpen(streamKey, sealed.subarray(0, NMCS_HEADER_BYTES), options);

	const parts: Uint8Array[] = [];
	let offset = NMCS_HEADER_BYTES;
	let index = 0;
	let total = 0;
	let terminated = false;
	const view = new DataView(sealed.buffer, sealed.byteOffset, sealed.byteLength);

	while (offset < sealed.byteLength) {
		throwIfAborted(options?.signal);
		if (terminated) {
			throw new CryptoError(
				"MALFORMED_ENVELOPE",
				"The chunked stream continues past its final chunk.",
			);
		}
		if (sealed.byteLength - offset < CHUNK_OVERHEAD_BYTES) {
			throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream is truncated.");
		}
		const length = view.getUint32(offset, false);
		if (length > context.chunkSize) {
			throw new CryptoError("MALFORMED_ENVELOPE", "A chunk exceeds the declared chunk size.");
		}
		const bodyStart = offset + CHUNK_LENGTH_PREFIX_BYTES;
		const tagStart = bodyStart + length;
		if (tagStart + TAG_BYTES > sealed.byteLength) {
			throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream is truncated.");
		}
		// The final flag is authenticated, so it is resolved by trial: a chunk that is not the
		// last one in the buffer must be a full non-final chunk.
		const isLast = tagStart + TAG_BYTES === sealed.byteLength;
		if (!isLast && length !== context.chunkSize) {
			throw new CryptoError("MALFORMED_ENVELOPE", "A non-final chunk is not full.");
		}
		const plaintext = openChunk(
			context,
			index,
			sealed.subarray(bodyStart, tagStart),
			sealed.subarray(tagStart, tagStart + TAG_BYTES),
			isLast,
		);
		parts.push(plaintext);
		total += plaintext.byteLength;
		if (options?.maxPlaintextBytes !== undefined && total > options.maxPlaintextBytes) {
			throw new CryptoError("LIMIT_EXCEEDED", "The plaintext exceeds the configured limit.");
		}
		terminated = isLast;
		offset = tagStart + TAG_BYTES;
		index += 1;
	}

	if (!terminated) {
		// Unreachable for well-formed input; a truncated stream fails the final-flag check above.
		throw authenticationFailed();
	}
	if (context.fields.plaintextLength !== undefined && context.fields.plaintextLength !== total) {
		throw authenticationFailed();
	}

	const output = new Uint8Array(total);
	let cursor = 0;
	for (const part of parts) {
		output.set(part, cursor);
		cursor += part.byteLength;
	}
	return output;
}

/**
 * Streaming seal.
 *
 * Byte-identical to {@link sealChunked} for the same inputs **only when
 * `plaintextLength` is declared**: `sealChunked` always knows the size and records it,
 * whereas a stream does not, so an undeclared stream sets the header's declared-length
 * flag to zero and produces a different (equally valid, same-length) header. Pass
 * `plaintextLength` when the size is known so readers can validate it and so the two
 * paths agree byte for byte.
 */
export function createChunkedSealStream(
	key: KeyObject | Uint8Array,
	options: ChunkedSealOptions,
): TransformStream<Uint8Array, Uint8Array> {
	const streamKey = normalizeStreamKey(key);
	const maxPlaintextBytes = assertByteLimit(options.maxPlaintextBytes);
	let context: SealContext | undefined;
	const pending = new ByteQueue();
	let index = 0;
	let total = 0;

	return new TransformStream<Uint8Array, Uint8Array>({
		start(controller) {
			context = beginSeal(streamKey, options);
			controller.enqueue(context.header);
		},
		transform(chunk, controller) {
			throwIfAborted(options.signal);
			if (!isStableBytes(chunk)) {
				throw new CryptoError("INVALID_ARGUMENT", "The chunked stream plaintext must be bytes.");
			}
			const active = context!;
			total += chunk.byteLength;
			if (maxPlaintextBytes !== undefined && total > maxPlaintextBytes) {
				throw new CryptoError("LIMIT_EXCEEDED", "The plaintext exceeds the configured limit.");
			}
			pending.push(chunk);
			// Hold back one full chunk: the final chunk is flagged, so it can only be emitted
			// once the stream is known to be finished.
			while (pending.byteLength > active.chunkSize) {
				controller.enqueue(sealChunk(active, index, pending.take(active.chunkSize), false));
				index += 1;
			}
		},
		flush(controller) {
			throwIfAborted(options.signal);
			const active = context!;
			if (options.plaintextLength !== undefined && options.plaintextLength !== total) {
				throw new CryptoError(
					"INVALID_ARGUMENT",
					"The declared plaintext length does not match the stream.",
				);
			}
			controller.enqueue(sealChunk(active, index, pending.take(pending.byteLength), true));
		},
	});
}

/**
 * Streaming open.
 *
 * IMPORTANT: this emits an *authenticated prefix*. Every chunk is tag-verified before it
 * is enqueued, but truncation of the stream is only detected at the end — a consumer that
 * acts on partial output before the stream completes successfully may act on a prefix of
 * the plaintext. Callers needing all-or-nothing semantics must use {@link openChunked}.
 */
export function createChunkedOpenStream(
	key: KeyObject | Uint8Array,
	options?: ChunkedOpenOptions,
): TransformStream<Uint8Array, Uint8Array> {
	const streamKey = normalizeStreamKey(key);
	const maxPlaintextBytes = assertByteLimit(options?.maxPlaintextBytes);
	assertChunkSizeCeiling(options?.maxChunkSizeLog2);
	let context: OpenContext | undefined;
	const pending = new ByteQueue();
	let index = 0;
	let total = 0;
	let received = 0;
	/** Largest ciphertext a compliant object could have under `maxPlaintextBytes`. */
	let maxCiphertextBytes = Number.POSITIVE_INFINITY;

	/** Emit every chunk that is provably complete and provably not the final one. */
	const drain = (controller: TransformStreamDefaultController<Uint8Array>): void => {
		const active = context!;
		const stride = active.chunkSize + CHUNK_OVERHEAD_BYTES;
		// A chunk is only known to be non-final once bytes beyond it have arrived.
		while (pending.byteLength > stride) {
			const length = pending.readUint32(0);
			if (length !== active.chunkSize) {
				throw new CryptoError("MALFORMED_ENVELOPE", "A non-final chunk is not full.");
			}
			const frame = pending.take(stride);
			const bodyStart = CHUNK_LENGTH_PREFIX_BYTES;
			const tagStart = bodyStart + length;
			const plaintext = openChunk(
				active,
				index,
				frame.subarray(bodyStart, tagStart),
				frame.subarray(tagStart, tagStart + TAG_BYTES),
				false,
			);
			total += plaintext.byteLength;
			if (maxPlaintextBytes !== undefined && total > maxPlaintextBytes) {
				throw new CryptoError("LIMIT_EXCEEDED", "The plaintext exceeds the configured limit.");
			}
			controller.enqueue(plaintext);
			index += 1;
		}
	};

	return new TransformStream<Uint8Array, Uint8Array>({
		transform(chunk, controller) {
			throwIfAborted(options?.signal);
			if (!isStableBytes(chunk)) {
				throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream must be bytes.");
			}
			received += chunk.byteLength;
			// Trip the plaintext budget on arrival rather than after a full chunk decrypts, so a
			// hostile object cannot force the reader to buffer one whole chunk per limit check.
			if (received > maxCiphertextBytes) {
				throw new CryptoError("LIMIT_EXCEEDED", "The plaintext exceeds the configured limit.");
			}
			pending.push(chunk);
			if (context === undefined) {
				if (pending.byteLength < NMCS_HEADER_BYTES) return;
				context = beginOpen(streamKey, pending.take(NMCS_HEADER_BYTES), options);
				if (maxPlaintextBytes !== undefined) {
					maxCiphertextBytes = chunkedCiphertextLength(
						maxPlaintextBytes,
						context.fields.chunkSizeLog2,
					);
					if (received > maxCiphertextBytes) {
						throw new CryptoError("LIMIT_EXCEEDED", "The plaintext exceeds the configured limit.");
					}
				}
			}
			drain(controller);
		},
		flush(controller) {
			throwIfAborted(options?.signal);
			if (context === undefined) {
				throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream is truncated.");
			}
			const active = context;
			drain(controller);
			if (pending.byteLength < CHUNK_OVERHEAD_BYTES) {
				throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream is truncated.");
			}
			const length = pending.readUint32(0);
			if (length > active.chunkSize) {
				throw new CryptoError("MALFORMED_ENVELOPE", "A chunk exceeds the declared chunk size.");
			}
			const bodyStart = CHUNK_LENGTH_PREFIX_BYTES;
			const tagStart = bodyStart + length;
			if (tagStart + TAG_BYTES !== pending.byteLength) {
				throw new CryptoError("MALFORMED_ENVELOPE", "The chunked stream is truncated.");
			}
			const frame = pending.take(pending.byteLength);
			const plaintext = openChunk(
				active,
				index,
				frame.subarray(bodyStart, tagStart),
				frame.subarray(tagStart, tagStart + TAG_BYTES),
				true,
			);
			total += plaintext.byteLength;
			if (maxPlaintextBytes !== undefined && total > maxPlaintextBytes) {
				throw new CryptoError("LIMIT_EXCEEDED", "The plaintext exceeds the configured limit.");
			}
			if (active.fields.plaintextLength !== undefined && active.fields.plaintextLength !== total) {
				throw authenticationFailed();
			}
			controller.enqueue(plaintext);
		},
	});
}
