// oxlint-disable typescript/no-unsafe-type-assertion -- SDK clients are intentionally replaced with structural contract fakes.
import { type KeyObject } from "node:crypto";
import type { KeyManagementServiceClient } from "@google-cloud/kms";
import { GCP_KMS, GcpKmsProvider, calculateCrc32c } from "../../src/kms/gcp/index.js";

const KEY_NAME = "projects/example/locations/us-central1/keyRings/application/cryptoKeys/envelope";

interface GcpRequest {
	readonly name?: string;
	readonly plaintext?: Uint8Array;
	readonly ciphertext?: Uint8Array;
	readonly additionalAuthenticatedData?: Uint8Array;
	readonly plaintextCrc32c?: { readonly value?: number };
	readonly ciphertextCrc32c?: { readonly value?: number };
	readonly additionalAuthenticatedDataCrc32c?: { readonly value?: number };
}

function asRequest(value: unknown): GcpRequest {
	if (typeof value !== "object" || value === null) throw new TypeError("Expected a GCP request.");
	return value;
}

function exportSecret(key: KeyObject): Buffer {
	return Buffer.from(key.export());
}

describe("GcpKmsProvider", () => {
	it("implements the standard CRC32C test vector", () => {
		expect(calculateCrc32c(new TextEncoder().encode("123456789"))).toBe(0xe306_9283);
	});

	it("wraps a local data key with AAD and verifies every returned checksum", async () => {
		const secret = Uint8Array.from({ length: 32 }, (_, index) => 255 - index);
		const wrapped = new Uint8Array([10, 20, 30, 40]);
		let encryptRequest: GcpRequest | undefined;
		let decryptRequest: GcpRequest | undefined;
		let encryptedPlaintext: Uint8Array | undefined;
		const encrypt = vi.fn(async (request: unknown) => {
			encryptRequest = asRequest(request);
			encryptedPlaintext = new Uint8Array(encryptRequest.plaintext!);
			return [
				{
					name: `${KEY_NAME}/cryptoKeyVersions/9`,
					ciphertext: wrapped,
					ciphertextCrc32c: { value: calculateCrc32c(wrapped) },
					verifiedPlaintextCrc32c: true,
					verifiedAdditionalAuthenticatedDataCrc32c: true,
				},
			] as const;
		});
		const decrypt = vi.fn(async (request: unknown) => {
			decryptRequest = asRequest(request);
			const plaintext = new Uint8Array(secret);
			return [
				{
					plaintext,
					plaintextCrc32c: { value: calculateCrc32c(plaintext) },
				},
			] as const;
		});
		const close = vi.fn(async () => undefined);
		const provider = new GcpKmsProvider({
			keyName: KEY_NAME,
			client: { encrypt, decrypt, close } as unknown as KeyManagementServiceClient,
		});
		const wrappingContext = new TextEncoder().encode("tenant-scope-digest");

		const generated = await provider.generateDataKey({ wrappingContext });
		const unwrapped = await provider.unwrapDataKey(generated, { wrappingContext });
		const generatedRaw = exportSecret(generated.plaintextKey);
		const unwrappedRaw = exportSecret(unwrapped);
		try {
			expect(generated.wrappingAlgorithm).toBe(GCP_KMS);
			expect(generated.keyReference).toBe(KEY_NAME);
			expect(generated.wrappedKey).toEqual(wrapped);
			expect(generatedRaw).toEqual(Buffer.from(encryptedPlaintext!));
			expect(unwrappedRaw).toEqual(Buffer.from(secret));
		} finally {
			generatedRaw.fill(0);
			unwrappedRaw.fill(0);
		}

		expect(encryptRequest).toMatchObject({
			name: KEY_NAME,
			additionalAuthenticatedData: wrappingContext,
			additionalAuthenticatedDataCrc32c: { value: calculateCrc32c(wrappingContext) },
		});
		expect(encryptRequest?.plaintextCrc32c?.value).toBe(calculateCrc32c(encryptedPlaintext!));
		expect(decryptRequest).toMatchObject({
			name: KEY_NAME,
			ciphertext: wrapped,
			ciphertextCrc32c: { value: calculateCrc32c(wrapped) },
			additionalAuthenticatedData: wrappingContext,
		});

		await provider.close();
		expect(close).not.toHaveBeenCalled();
	});

	it("rejects a mismatched ciphertext checksum", async () => {
		const encrypt = vi.fn(async () => [
			{
				name: `${KEY_NAME}/cryptoKeyVersions/1`,
				ciphertext: new Uint8Array([1, 2, 3]),
				ciphertextCrc32c: { value: 0 },
				verifiedPlaintextCrc32c: true,
				verifiedAdditionalAuthenticatedDataCrc32c: true,
			},
		]);
		const provider = new GcpKmsProvider({
			keyName: KEY_NAME,
			client: {
				encrypt,
				decrypt: vi.fn(),
				close: vi.fn(),
			} as unknown as KeyManagementServiceClient,
		});

		await expect(
			provider.generateDataKey({ wrappingContext: new Uint8Array() }),
		).rejects.toMatchObject({
			code: "KEY_PROVIDER",
			message: "The key provider operation failed.",
		});
	});

	it("rejects foreign key references before calling Cloud KMS", async () => {
		const decrypt = vi.fn();
		const provider = new GcpKmsProvider({
			keyName: KEY_NAME,
			client: {
				encrypt: vi.fn(),
				decrypt,
				close: vi.fn(),
			} as unknown as KeyManagementServiceClient,
		});

		await expect(
			provider.unwrapDataKey(
				{
					wrappedKey: new Uint8Array([1]),
					keyReference:
						"projects/example/locations/us-central1/keyRings/application/cryptoKeys/foreign",
					wrappingAlgorithm: GCP_KMS,
				},
				{ wrappingContext: new Uint8Array() },
			),
		).rejects.toMatchObject({ code: "KEY_NOT_FOUND" });
		expect(decrypt).not.toHaveBeenCalled();
	});

	it("normalizes INVALID_ARGUMENT from decrypt as an authentication failure", async () => {
		const decrypt = vi.fn(async () => {
			throw Object.assign(new Error("provider detail"), { code: 3 });
		});
		const provider = new GcpKmsProvider({
			keyName: KEY_NAME,
			client: {
				encrypt: vi.fn(),
				decrypt,
				close: vi.fn(),
			} as unknown as KeyManagementServiceClient,
		});

		await expect(
			provider.unwrapDataKey(
				{
					wrappedKey: new Uint8Array([1]),
					keyReference: KEY_NAME,
					wrappingAlgorithm: GCP_KMS,
				},
				{ wrappingContext: new Uint8Array([2]) },
			),
		).rejects.toMatchObject({
			code: "AUTHENTICATION_FAILED",
			message: "Ciphertext authentication failed.",
		});
	});
});
