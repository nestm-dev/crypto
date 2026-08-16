import { createSecretKey, randomBytes, scrypt, type KeyObject } from "node:crypto";
import { aadBytes, frame, utf8 } from "../core/encoding.js";
import { CryptoError, throwIfAborted } from "../core/errors.js";
import type { CipherAad } from "../core/types.js";
import { hkdfSha256 } from "../keys/hkdf.js";

export type PasswordKdfId = "scrypt-1";

export interface ScryptParams {
	readonly N: number;
	readonly r: number;
	readonly p: number;
}

export interface PasswordKdfParams {
	readonly id: PasswordKdfId | (string & {});
	readonly params: unknown;
}

/** Interactive-login defaults: 64 MiB, roughly 100-150 ms on current server hardware. */
export const PASSWORD_KDF_SCRYPT_DEFAULT: PasswordKdfParams = Object.freeze({
	id: "scrypt-1",
	params: Object.freeze({ N: 65_536, r: 8, p: 1 }),
});

const DERIVED_KEY_BYTES = 32;
const MIN_SALT_BYTES = 16;
const DEFAULT_SALT_BYTES = 32;
const MAX_SALT_BYTES = 1024;
const DEFAULT_MAX_CONCURRENCY = 4;
const INFO_LABEL = "nmc/password/v1";
const EMPTY_SALT = new Uint8Array();

/**
 * Absolute parameter ceilings, independent of anything a caller passes. Without them a
 * single derivation could reserve tens of gigabytes and run for minutes, which is a
 * denial of service wearing a password-hardening costume.
 */
const MAX_SCRYPT_COST = 2 ** 20;
const MAX_SCRYPT_BLOCK_SIZE = 32;
const MAX_SCRYPT_PARALLELISM = 16;
/** Hard per-derivation footprint ceiling: 1 GiB. */
const MAX_SCRYPT_MEMORY_BYTES = 1024 * 1024 * 1024;
/** Ceiling on what is ever handed to Node as `maxmem`, headroom included. */
const MAX_SCRYPT_MAXMEM_BYTES = Math.ceil(MAX_SCRYPT_MEMORY_BYTES * 1.25);

/** RFC 7914 working-memory footprint of a single derivation. */
function scryptMemoryBytes(N: number, r: number): number {
	return 128 * N * r;
}

export interface DerivePasswordKeyInput {
	readonly password: string | Uint8Array;
	readonly salt: Uint8Array;
	readonly kdf: PasswordKdfParams;
	/** Domain separation applied to the KDF output. Must match to reproduce the key. */
	readonly info?: CipherAad;
	readonly signal?: AbortSignal;
}

export interface PasswordKdfDeriveInput {
	readonly password: Uint8Array;
	readonly salt: Uint8Array;
	readonly params: unknown;
	readonly keyLength: number;
	readonly signal?: AbortSignal;
}

export interface PasswordKdfAlgorithm {
	readonly id: string;
	validateParams(params: unknown): void;
	derive(input: PasswordKdfDeriveInput): Promise<Uint8Array>;
}

export interface PasswordKdf {
	readonly defaultParams: PasswordKdfParams;
	derive(input: DerivePasswordKeyInput): Promise<KeyObject>;
	supports(id: string): boolean;
}

export interface CreatePasswordKdfOptions {
	readonly algorithms?: readonly PasswordKdfAlgorithm[];
	readonly defaultParams?: PasswordKdfParams;
	/** Bounds concurrent derivations. Each scrypt call holds `128 * N * r` bytes. */
	readonly maxConcurrency?: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPowerOfTwo(value: number): boolean {
	return Number.isInteger(value) && value > 1 && (value & (value - 1)) === 0;
}

function assertScryptParams(params: unknown): asserts params is ScryptParams {
	if (!isRecord(params)) {
		throw new CryptoError("INVALID_ARGUMENT", "The scrypt parameters are invalid.");
	}
	if (Object.keys(params).toSorted().join(",") !== "N,p,r") {
		throw new CryptoError("INVALID_ARGUMENT", "The scrypt parameters have an invalid shape.");
	}
	const { N, r, p } = params as Record<"N" | "r" | "p", unknown>;
	if (typeof N !== "number" || !isPowerOfTwo(N) || N < 1024 || N > MAX_SCRYPT_COST) {
		throw new CryptoError("INVALID_ARGUMENT", "The scrypt cost parameter is out of range.");
	}
	if (typeof r !== "number" || !Number.isInteger(r) || r < 1 || r > MAX_SCRYPT_BLOCK_SIZE) {
		throw new CryptoError("INVALID_ARGUMENT", "The scrypt block size is out of range.");
	}
	if (typeof p !== "number" || !Number.isInteger(p) || p < 1 || p > MAX_SCRYPT_PARALLELISM) {
		throw new CryptoError("INVALID_ARGUMENT", "The scrypt parallelism is out of range.");
	}
	// The individual ranges still admit combinations that would reserve many gigabytes per
	// derivation, so the footprint itself is what has to be bounded. Rejecting outright
	// rather than clamping keeps `maxmem` a true ceiling instead of a value the caller
	// dictates.
	if (scryptMemoryBytes(N, r) > MAX_SCRYPT_MEMORY_BYTES) {
		throw new CryptoError("INVALID_ARGUMENT", "The scrypt parameters require too much memory.");
	}
}

/** RFC 7914 scrypt over `node:crypto`. No native dependency; core stays dependency-free. */
export function scryptPasswordKdf(): PasswordKdfAlgorithm {
	return Object.freeze({
		id: "scrypt-1",
		validateParams(params: unknown): void {
			assertScryptParams(params);
		},
		async derive(input: PasswordKdfDeriveInput): Promise<Uint8Array> {
			assertScryptParams(input.params);
			const { N, r, p } = input.params;
			// Node rejects the derivation outright unless maxmem covers 128 * N * r. The
			// parameters are already bounded above, so this stays a ceiling rather than
			// something the caller can inflate.
			const maxmem = Math.min(Math.ceil(scryptMemoryBytes(N, r) * 1.25), MAX_SCRYPT_MAXMEM_BYTES);
			return await new Promise<Uint8Array>((resolve, reject) => {
				scrypt(
					input.password,
					input.salt,
					input.keyLength,
					{ N, r, p, maxmem },
					(error, derived) => {
						if (error) {
							reject(
								new CryptoError("CIPHER_FAILURE", "Password derivation failed.", { cause: error }),
							);
							return;
						}
						resolve(new Uint8Array(derived));
					},
				);
			});
		},
	}) satisfies PasswordKdfAlgorithm;
}

/** Random salt for a new password record. */
export function generatePasswordSalt(byteLength: number = DEFAULT_SALT_BYTES): Uint8Array {
	if (!Number.isInteger(byteLength) || byteLength < MIN_SALT_BYTES || byteLength > MAX_SALT_BYTES) {
		throw new CryptoError("INVALID_ARGUMENT", "The password salt length is out of range.");
	}
	return new Uint8Array(randomBytes(byteLength));
}

function canonicalize(value: unknown): unknown {
	if (Array.isArray(value)) return value.map((entry) => canonicalize(entry));
	if (isRecord(value)) {
		const result: Record<string, unknown> = {};
		for (const key of Object.keys(value).toSorted()) {
			result[key] = canonicalize(value[key]);
		}
		return result;
	}
	return value;
}

function assertParamsShape(value: unknown): asserts value is PasswordKdfParams {
	if (!isRecord(value)) {
		throw new CryptoError("INVALID_ARGUMENT", "The password KDF parameters are invalid.");
	}
	if (Object.keys(value).toSorted().join(",") !== "id,params") {
		throw new CryptoError("INVALID_ARGUMENT", "The password KDF parameters have an invalid shape.");
	}
	if (
		typeof value.id !== "string" ||
		value.id.length === 0 ||
		value.id.length > 64 ||
		value.id.trim() !== value.id ||
		/\p{Cc}/u.test(value.id)
	) {
		throw new CryptoError("INVALID_ARGUMENT", "The password KDF identifier is invalid.");
	}
	if (!isRecord(value.params)) {
		throw new CryptoError("INVALID_ARGUMENT", "The password KDF parameters are invalid.");
	}
}

/** Canonical JSON encoding, stable across releases and safe for a database column. */
export function encodePasswordKdfParams(params: PasswordKdfParams): string {
	assertParamsShape(params);
	return JSON.stringify({ id: params.id, params: canonicalize(params.params) });
}

export function decodePasswordKdfParams(value: string): PasswordKdfParams {
	if (typeof value !== "string" || value.length === 0 || value.length > 4096) {
		throw new CryptoError("INVALID_ARGUMENT", "The encoded password KDF parameters are invalid.");
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(value) as unknown;
	} catch (error: unknown) {
		throw new CryptoError(
			"INVALID_ARGUMENT",
			"The encoded password KDF parameters are malformed.",
			{
				cause: error,
			},
		);
	}
	assertParamsShape(parsed);
	const normalized: PasswordKdfParams = Object.freeze({
		id: parsed.id,
		params: Object.freeze(canonicalize(parsed.params)),
	});
	if (encodePasswordKdfParams(normalized) !== value) {
		throw new CryptoError(
			"INVALID_ARGUMENT",
			"The encoded password KDF parameters are not canonical.",
		);
	}
	return normalized;
}

/** FIFO semaphore. Memory-hard derivations must never run unbounded in parallel. */
function createSemaphore(limit: number): (signal?: AbortSignal) => Promise<() => void> {
	let active = 0;
	const waiting: (() => void)[] = [];
	const release = (): void => {
		active -= 1;
		const next = waiting.shift();
		if (next) next();
	};
	return async (signal?: AbortSignal): Promise<() => void> => {
		throwIfAborted(signal);
		if (active < limit) {
			active += 1;
			return release;
		}
		await new Promise<void>((resolve, reject) => {
			const onAbort = (): void => {
				const index = waiting.indexOf(admit);
				if (index !== -1) waiting.splice(index, 1);
				reject(new CryptoError("ABORTED", "The cryptographic operation was aborted."));
			};
			const admit = (): void => {
				signal?.removeEventListener("abort", onAbort);
				active += 1;
				resolve();
			};
			waiting.push(admit);
			signal?.addEventListener("abort", onAbort, { once: true });
		});
		return release;
	};
}

function passwordBytes(password: string | Uint8Array): { bytes: Uint8Array; owned: boolean } {
	if (typeof password === "string") {
		if (password.length === 0) {
			throw new CryptoError("INVALID_ARGUMENT", "The password must be non-empty.");
		}
		return { bytes: utf8(password), owned: true };
	}
	if (password instanceof Uint8Array) {
		if (password.byteLength === 0) {
			throw new CryptoError("INVALID_ARGUMENT", "The password must be non-empty.");
		}
		return { bytes: password, owned: false };
	}
	throw new CryptoError("INVALID_ARGUMENT", "The password must be text or bytes.");
}

export function createPasswordKdf(options?: CreatePasswordKdfOptions): PasswordKdf {
	const algorithms = options?.algorithms ?? [scryptPasswordKdf()];
	if (!Array.isArray(algorithms) || algorithms.length === 0) {
		throw new CryptoError("CONFIGURATION", "A password KDF registry is required.");
	}
	const registry = new Map<string, PasswordKdfAlgorithm>();
	for (const algorithm of algorithms) {
		try {
			if (
				typeof algorithm !== "object" ||
				algorithm === null ||
				typeof algorithm.id !== "string" ||
				algorithm.id.length === 0 ||
				algorithm.id.length > 64 ||
				algorithm.id.trim() !== algorithm.id ||
				typeof algorithm.derive !== "function" ||
				typeof algorithm.validateParams !== "function"
			) {
				throw new TypeError("Invalid password KDF registration.");
			}
			if (registry.has(algorithm.id)) throw new TypeError("Duplicate password KDF identifier.");
			registry.set(algorithm.id, algorithm);
		} catch (error: unknown) {
			throw new CryptoError("CONFIGURATION", "A password KDF registration is invalid.", {
				cause: error,
			});
		}
	}

	const defaultParams = options?.defaultParams ?? PASSWORD_KDF_SCRYPT_DEFAULT;
	assertParamsShape(defaultParams);
	const defaultAlgorithm = registry.get(defaultParams.id);
	if (defaultAlgorithm === undefined) {
		throw new CryptoError("CONFIGURATION", "The default password KDF is not registered.");
	}
	try {
		defaultAlgorithm.validateParams(defaultParams.params);
	} catch (error: unknown) {
		throw new CryptoError("CONFIGURATION", "The default password KDF parameters are invalid.", {
			cause: error,
		});
	}

	const maxConcurrency = options?.maxConcurrency ?? DEFAULT_MAX_CONCURRENCY;
	if (!Number.isInteger(maxConcurrency) || maxConcurrency < 1 || maxConcurrency > 1024) {
		throw new CryptoError("CONFIGURATION", "The password KDF concurrency limit is invalid.");
	}
	const acquire = createSemaphore(maxConcurrency);

	return Object.freeze({
		defaultParams: Object.freeze({
			id: defaultParams.id,
			params: Object.freeze(canonicalize(defaultParams.params)),
		}),
		supports(id: string): boolean {
			return registry.has(id);
		},
		async derive(input: DerivePasswordKeyInput): Promise<KeyObject> {
			assertParamsShape(input.kdf);
			const algorithm = registry.get(input.kdf.id);
			if (algorithm === undefined) {
				throw new CryptoError("CONFIGURATION", "The password KDF is not registered.");
			}
			algorithm.validateParams(input.kdf.params);
			if (
				!(input.salt instanceof Uint8Array) ||
				input.salt.byteLength < MIN_SALT_BYTES ||
				input.salt.byteLength > MAX_SALT_BYTES
			) {
				throw new CryptoError("INVALID_ARGUMENT", "The password salt length is out of range.");
			}
			const { bytes: password, owned } = passwordBytes(input.password);
			// Acquisition can reject (abort, or an aborted wait in the queue). Keeping it inside
			// the same try is what guarantees the plaintext copy is wiped on that path too.
			let release: (() => void) | undefined;
			let raw: Uint8Array | undefined;
			let okm: Uint8Array | undefined;
			try {
				release = await acquire(input.signal);
				throwIfAborted(input.signal);
				raw = await algorithm.derive({
					password,
					salt: input.salt,
					params: input.kdf.params,
					keyLength: DERIVED_KEY_BYTES,
					...(input.signal === undefined ? {} : { signal: input.signal }),
				});
				throwIfAborted(input.signal);
				if (!(raw instanceof Uint8Array) || raw.byteLength !== DERIVED_KEY_BYTES) {
					throw new CryptoError("INVALID_KEY", "The password KDF returned invalid key material.");
				}
				okm = hkdfSha256(
					raw,
					EMPTY_SALT,
					frame(utf8(INFO_LABEL), aadBytes(input.info)),
					DERIVED_KEY_BYTES,
				);
				return createSecretKey(okm);
			} finally {
				release?.();
				if (owned) password.fill(0);
				raw?.fill(0);
				okm?.fill(0);
			}
		},
	}) satisfies PasswordKdf;
}
