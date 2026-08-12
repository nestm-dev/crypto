import { types as nodeTypes } from "node:util";
import { aadBytes, CryptoError, type CipherAad } from "../core/index.js";
import type { TenantFieldCipherOptions, TenantFieldDecryptOptions } from "../tenant/index.js";

interface CapturedFieldOptions {
	readonly aad?: Uint8Array;
	readonly signal?: AbortSignal;
	readonly maxDepth?: number;
}

function ownDataValue(source: object, key: PropertyKey): unknown {
	const descriptor = Object.getOwnPropertyDescriptor(source, key);
	if (descriptor === undefined) return undefined;
	if (!("value" in descriptor)) {
		throw new TypeError("Tenant HTTP field options cannot contain accessors.");
	}
	const value: unknown = Reflect.get(source, key);
	return value;
}

function isCipherAad(value: unknown): value is CipherAad {
	return typeof value === "string" || value instanceof Uint8Array;
}

function captureFieldOptions(
	options: TenantFieldCipherOptions | undefined,
	allowLegacyPlaintext: boolean,
): CapturedFieldOptions {
	try {
		const candidate: unknown = options === undefined ? {} : options;
		if (
			typeof candidate !== "object" ||
			candidate === null ||
			Array.isArray(candidate) ||
			nodeTypes.isProxy(candidate)
		) {
			throw new TypeError("Tenant HTTP field options must be a plain object.");
		}
		const prototype: unknown = Object.getPrototypeOf(candidate);
		if (prototype !== Object.prototype && prototype !== null) {
			throw new TypeError("Tenant HTTP field options must be a plain object.");
		}
		for (const key of Reflect.ownKeys(candidate)) {
			if (
				typeof key !== "string" ||
				(key !== "aad" &&
					key !== "signal" &&
					key !== "maxDepth" &&
					(!allowLegacyPlaintext || key !== "legacyPlaintext"))
			) {
				throw new TypeError("Tenant HTTP field options contain an unknown property.");
			}
			ownDataValue(candidate, key);
		}

		const unresolvedAad = ownDataValue(candidate, "aad");
		const signal = ownDataValue(candidate, "signal");
		const maxDepth = ownDataValue(candidate, "maxDepth");
		if (unresolvedAad !== undefined && !isCipherAad(unresolvedAad)) {
			throw new TypeError("The tenant HTTP field authenticated data is invalid.");
		}
		if (signal !== undefined && !(signal instanceof AbortSignal)) {
			throw new TypeError("The tenant HTTP field abort signal is invalid.");
		}
		if (maxDepth !== undefined && typeof maxDepth !== "number") {
			throw new TypeError("The tenant HTTP field traversal depth is invalid.");
		}
		return Object.freeze({
			...(unresolvedAad === undefined ? {} : { aad: aadBytes(unresolvedAad) }),
			...(signal === undefined ? {} : { signal }),
			...(maxDepth === undefined ? {} : { maxDepth }),
		});
	} catch (error: unknown) {
		throw new CryptoError("INVALID_ARGUMENT", "Tenant HTTP field options are invalid.", {
			cause: error,
		});
	}
}

function materializeOptions(
	captured: CapturedFieldOptions,
	legacyPlaintext?: TenantFieldDecryptOptions["legacyPlaintext"],
): Readonly<TenantFieldDecryptOptions> {
	const aad = captured.aad;
	const options: TenantFieldDecryptOptions = {
		...(captured.signal === undefined ? {} : { signal: captured.signal }),
		...(captured.maxDepth === undefined ? {} : { maxDepth: captured.maxDepth }),
		...(legacyPlaintext === undefined ? {} : { legacyPlaintext }),
	};
	if (aad !== undefined) {
		Object.defineProperty(options, "aad", {
			configurable: false,
			enumerable: true,
			get: () => new Uint8Array(aad),
		});
	}
	return Object.freeze(options);
}

export function captureTenantFieldCipherOptions(
	options: TenantFieldCipherOptions | undefined,
): Readonly<TenantFieldCipherOptions> {
	const captured = captureFieldOptions(options, false);
	return materializeOptions(captured);
}

export function captureTenantFieldDecryptOptions(
	options: TenantFieldDecryptOptions | undefined,
): Readonly<TenantFieldDecryptOptions> {
	const captured = captureFieldOptions(options, true);
	let legacyPlaintext: unknown;
	try {
		legacyPlaintext = ownDataValue(options === undefined ? {} : options, "legacyPlaintext");
		if (
			legacyPlaintext !== undefined &&
			legacyPlaintext !== "allow" &&
			legacyPlaintext !== "reject"
		) {
			throw new TypeError("The legacy plaintext policy is invalid.");
		}
	} catch (error: unknown) {
		captured.aad?.fill(0);
		throw new CryptoError("INVALID_ARGUMENT", "Tenant HTTP field options are invalid.", {
			cause: error,
		});
	}
	return materializeOptions(captured, legacyPlaintext);
}
