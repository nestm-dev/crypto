import { FILE_ID_OVERRIDE } from "../stream/nmcs-format.js";

export function fixedNonceSource(noncePrefix: Uint8Array): (length: number) => Uint8Array {
	const copy = new Uint8Array(noncePrefix);
	return (length: number): Uint8Array => {
		if (copy.byteLength !== length) {
			throw new Error(`Expected a ${copy.byteLength}-byte nonce request but received ${length}.`);
		}
		return new Uint8Array(copy);
	};
}

/**
 * Pin the per-object file identifier of a chunked seal.
 *
 * **Never use this outside tests.** The file identifier is the only per-object randomness
 * in the `nmcs1` key schedule: sealing twice with the same identifier under the same data
 * key repeats the chunk key and nonce prefix, which exposes the XOR of the two plaintexts
 * and leaks the header GMAC subkey. It exists so format vectors can be frozen, and it is
 * reachable only from this entry point — `ChunkedSealOptions` has no such field.
 *
 * @example
 * sealChunked(key, plaintext, withFixedFileId({ keyReference: "ws:1" }, fileId));
 */
export function withFixedFileId<Options extends object>(
	options: Options,
	fileId: Uint8Array,
): Options {
	if (!(fileId instanceof Uint8Array) || fileId.byteLength !== 16) {
		throw new TypeError("A fixed file identifier must contain 16 bytes.");
	}
	return { ...options, [FILE_ID_OVERRIDE]: new Uint8Array(fileId) };
}
