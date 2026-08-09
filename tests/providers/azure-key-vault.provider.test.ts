// oxlint-disable typescript/no-unsafe-type-assertion -- SDK clients are intentionally replaced with structural contract fakes.
import { type KeyObject } from "node:crypto";
import type { CryptographyClient } from "@azure/keyvault-keys";
import {
	AZURE_A256KW,
	AZURE_RSA_OAEP_256,
	AzureKeyVaultProvider,
} from "../../src/kms/azure/index.js";

const KEY_ID = "https://example.vault.azure.net/keys/envelope/0123456789abcdef";

function exportSecret(key: KeyObject): Buffer {
	return Buffer.from(key.export());
}

describe("AzureKeyVaultProvider", () => {
	it("wraps and unwraps with RSA-OAEP-256 and validates the exact returned key ID", async () => {
		let wrappedPlaintext: Uint8Array | undefined;
		let wrapOptions: unknown;
		let unwrapOptions: unknown;
		const wrapped = new Uint8Array([44, 55, 66]);
		const wrapKey = vi.fn(async (algorithm: string, plaintext: Uint8Array, options: unknown) => {
			wrappedPlaintext = new Uint8Array(plaintext);
			wrapOptions = options;
			return { result: wrapped, algorithm, keyID: KEY_ID };
		});
		const unwrapKey = vi.fn(async (algorithm: string, ciphertext: Uint8Array, options: unknown) => {
			expect(ciphertext).toEqual(wrapped);
			unwrapOptions = options;
			return { result: new Uint8Array(wrappedPlaintext!), algorithm, keyID: KEY_ID };
		});
		const close = vi.fn();
		const client = {
			keyID: KEY_ID,
			wrapKey,
			unwrapKey,
			close,
		} as unknown as CryptographyClient;
		const provider = new AzureKeyVaultProvider({ keyId: KEY_ID, client });
		const controller = new AbortController();
		const context = {
			wrappingContext: new TextEncoder().encode("tenant-scope"),
			signal: controller.signal,
		};

		const generated = await provider.generateDataKey(context);
		const unwrapped = await provider.unwrapDataKey(generated, context);
		const generatedRaw = exportSecret(generated.plaintextKey);
		const unwrappedRaw = exportSecret(unwrapped);
		try {
			expect(generated.keyReference).toBe(KEY_ID);
			expect(generated.wrappingAlgorithm).toBe(AZURE_RSA_OAEP_256);
			expect(generated.wrappedKey).toEqual(wrapped);
			expect(generatedRaw).toEqual(Buffer.from(wrappedPlaintext!));
			expect(unwrappedRaw).toEqual(Buffer.from(wrappedPlaintext!));
		} finally {
			generatedRaw.fill(0);
			unwrappedRaw.fill(0);
		}
		expect(wrapKey).toHaveBeenCalledWith(
			AZURE_RSA_OAEP_256,
			expect.any(Uint8Array),
			expect.any(Object),
		);
		expect(wrapOptions).toEqual({ abortSignal: controller.signal });
		expect(unwrapOptions).toEqual({ abortSignal: controller.signal });

		await provider.close();
		expect(close).not.toHaveBeenCalled();
	});

	it("supports A256KW for a version-pinned Managed HSM key", async () => {
		const keyId = "https://example.managedhsm.azure.net/keys/envelope/version-2";
		const raw = new Uint8Array(32).fill(5);
		const client = {
			keyID: keyId,
			wrapKey: vi.fn(async (algorithm: string) => ({
				result: new Uint8Array([1, 2]),
				algorithm,
				keyID: keyId,
			})),
			unwrapKey: vi.fn(async (algorithm: string) => ({ result: raw, algorithm, keyID: keyId })),
		} as unknown as CryptographyClient;
		const provider = new AzureKeyVaultProvider({
			keyId,
			algorithm: AZURE_A256KW,
			client,
		});

		const generated = await provider.generateDataKey({ wrappingContext: new Uint8Array() });
		const unwrapped = await provider.unwrapDataKey(
			{
				wrappedKey: generated.wrappedKey,
				keyReference: keyId,
				wrappingAlgorithm: AZURE_A256KW,
			},
			{ wrappingContext: new Uint8Array() },
		);
		const unwrappedRaw = exportSecret(unwrapped);
		try {
			expect(generated.wrappingAlgorithm).toBe(AZURE_A256KW);
			expect(unwrappedRaw).toEqual(Buffer.alloc(32, 5));
		} finally {
			unwrappedRaw.fill(0);
		}
	});

	it("rejects versionless URLs and clients bound to a different key", () => {
		expect(
			() =>
				new AzureKeyVaultProvider({
					keyId: "https://example.vault.azure.net/keys/envelope",
					credential: { getToken: vi.fn() },
				}),
		).toThrowError(/version-specific/u);
		expect(
			() =>
				new AzureKeyVaultProvider({
					keyId: KEY_ID,
					client: { keyID: `${KEY_ID}-other` } as CryptographyClient,
				}),
		).toThrowError(/different key/u);
	});

	it("rejects untrusted credential hosts unless they are explicitly pinned", () => {
		const keyId = "https://keys.internal.example/keys/envelope/version-1";
		const credential = { getToken: vi.fn() };
		expect(() => new AzureKeyVaultProvider({ keyId, credential })).toThrowError(/not trusted/u);
		expect(
			() =>
				new AzureKeyVaultProvider({
					keyId,
					credential,
					trustedHosts: ["keys.internal.example"],
				}),
		).not.toThrow();
	});

	it("rejects a response key mismatch and zeroes returned plaintext", async () => {
		const plaintext = new Uint8Array(32).fill(9);
		const client = {
			keyID: KEY_ID,
			wrapKey: vi.fn(),
			unwrapKey: vi.fn(async (algorithm: string) => ({
				result: plaintext,
				algorithm,
				keyID: `${KEY_ID}-foreign`,
			})),
		} as unknown as CryptographyClient;
		const provider = new AzureKeyVaultProvider({ keyId: KEY_ID, client });

		await expect(
			provider.unwrapDataKey(
				{
					wrappedKey: new Uint8Array([1]),
					keyReference: KEY_ID,
					wrappingAlgorithm: AZURE_RSA_OAEP_256,
				},
				{ wrappingContext: new Uint8Array() },
			),
		).rejects.toMatchObject({
			code: "KEY_PROVIDER",
			message: "The key provider operation failed.",
		});
		expect(plaintext).toEqual(new Uint8Array(32));
	});

	it("normalizes bad ciphertext from Key Vault as an authentication failure", async () => {
		const client = {
			keyID: KEY_ID,
			wrapKey: vi.fn(),
			unwrapKey: vi.fn(async () => {
				throw Object.assign(new Error("provider detail"), { statusCode: 400 });
			}),
		} as unknown as CryptographyClient;
		const provider = new AzureKeyVaultProvider({ keyId: KEY_ID, client });

		await expect(
			provider.unwrapDataKey(
				{
					wrappedKey: new Uint8Array([1]),
					keyReference: KEY_ID,
					wrappingAlgorithm: AZURE_RSA_OAEP_256,
				},
				{ wrappingContext: new Uint8Array() },
			),
		).rejects.toMatchObject({
			code: "AUTHENTICATION_FAILED",
			message: "Ciphertext authentication failed.",
		});
	});
});
