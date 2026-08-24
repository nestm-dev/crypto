import type { CipherEngine } from "../core/cipher-engine.js";

import type {
	AuthenticatedWorkspaceCipher,
	AuthenticatedWorkspaceCipherContext,
	CipherEngineWorkspaceCipherOptions,
} from "./types.js";

/** Adapt a CipherEngine without transferring ownership of its lifecycle. */
export function createCipherEngineWorkspaceCipher(
	engine: CipherEngine,
	options: CipherEngineWorkspaceCipherOptions = {},
): AuthenticatedWorkspaceCipher {
	if (
		typeof engine !== "object" ||
		engine === null ||
		typeof engine.encryptBytes !== "function" ||
		typeof engine.decryptBytes !== "function" ||
		typeof engine.defaultProvider !== "string"
	) {
		throw new TypeError("A CipherEngine is required.");
	}
	if (typeof options !== "object" || options === null) {
		throw new TypeError("CipherEngine workspace-cipher options are invalid.");
	}
	const provider = captureOptionalIdentifier(options.provider, "provider");
	const cipher = captureOptionalIdentifier(options.cipher, "cipher");
	const allowedProviders = captureAllowedProviders(
		options.allowedProviders,
		provider ?? engine.defaultProvider,
	);
	const writeProvider = provider ?? engine.defaultProvider;
	if (!allowedProviders.includes(writeProvider)) {
		throw new TypeError("The CipherEngine write provider must be admitted for reads.");
	}
	for (const allowedProvider of allowedProviders) {
		if (!engine.hasProvider(allowedProvider)) {
			throw new TypeError("A CipherEngine allowed provider is not registered.");
		}
	}

	return Object.freeze({
		async decryptBytes(
			envelope: string,
			context: AuthenticatedWorkspaceCipherContext,
		): Promise<Uint8Array> {
			return await engine.decryptBytes(envelope, {
				aad: context.authenticatedData,
				allowedProviders,
				keyContext: context.keyContext,
				...(context.signal === undefined ? {} : { signal: context.signal }),
			});
		},
		async encryptBytes(
			plaintext: Uint8Array,
			context: AuthenticatedWorkspaceCipherContext,
		): Promise<string> {
			return await engine.encryptBytes(plaintext, {
				aad: context.authenticatedData,
				keyContext: context.keyContext,
				...(cipher === undefined ? {} : { cipher }),
				...(provider === undefined ? {} : { provider }),
				...(context.signal === undefined ? {} : { signal: context.signal }),
			});
		},
	} satisfies AuthenticatedWorkspaceCipher);
}

function captureOptionalIdentifier(value: string | undefined, label: string): string | undefined {
	if (value === undefined) return undefined;
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > 128 ||
		value.trim() !== value ||
		/\p{C}/u.test(value)
	) {
		throw new TypeError(`The CipherEngine ${label} selection is invalid.`);
	}
	return value;
}

function captureAllowedProviders(
	values: readonly string[] | undefined,
	fallback: string,
): readonly string[] {
	const candidates = values === undefined ? [fallback] : [...values];
	if (candidates.length === 0) {
		throw new TypeError("At least one allowed CipherEngine provider is required.");
	}
	const unique = new Set<string>();
	for (const candidate of candidates) {
		const captured = captureOptionalIdentifier(candidate, "allowed provider");
		if (captured === undefined || unique.has(captured)) {
			throw new TypeError("CipherEngine allowed providers are invalid.");
		}
		unique.add(captured);
	}
	return Object.freeze([...unique]);
}
