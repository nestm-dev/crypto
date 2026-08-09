// oxlint-disable typescript/no-unsafe-type-assertion -- SDK clients are intentionally replaced with structural contract fakes.
import { createHash, type KeyObject } from "node:crypto";
import type { KMSClient } from "@aws-sdk/client-kms";
import { AWS_KMS, AWS_WRAPPING_CONTEXT_KEY, AwsKmsProvider } from "../../src/kms/aws/index.js";

const KEY_ID = "1234abcd-12ab-34cd-56ef-1234567890ab";
const KEY_ARN = `arn:aws:kms:us-east-1:111122223333:key/${KEY_ID}`;

function commandInput(command: unknown): Readonly<Record<string, unknown>> {
	if (typeof command !== "object" || command === null || !("input" in command)) {
		throw new TypeError("Expected an AWS SDK command.");
	}
	const input = command.input;
	if (typeof input !== "object" || input === null) {
		throw new TypeError("Expected AWS SDK command input.");
	}
	return input as Readonly<Record<string, unknown>>;
}

function commandName(command: unknown): string {
	if (typeof command !== "object" || command === null) {
		throw new TypeError("Expected an AWS SDK command.");
	}
	return command.constructor.name;
}

function exportSecret(key: KeyObject): Buffer {
	return Buffer.from(key.export());
}

describe("AwsKmsProvider", () => {
	it("uses GenerateDataKey(AES_256), static context, and a wrapping-context digest", async () => {
		const secret = Uint8Array.from({ length: 32 }, (_, index) => index);
		const inputs: Readonly<Record<string, unknown>>[] = [];
		const send = vi.fn(async (command: unknown) => {
			const input = commandInput(command);
			inputs.push(input);
			if (commandName(command) === "GenerateDataKeyCommand") {
				return {
					Plaintext: new Uint8Array(secret),
					CiphertextBlob: new Uint8Array([90, 91, 92]),
					KeyId: KEY_ARN,
				};
			}
			return {
				Plaintext: new Uint8Array(secret),
				KeyId: KEY_ARN,
				EncryptionAlgorithm: "SYMMETRIC_DEFAULT",
			};
		});
		const destroy = vi.fn();
		const provider = new AwsKmsProvider({
			keyId: KEY_ID,
			client: { send, destroy } as unknown as KMSClient,
			encryptionContext: { application: "billing" },
		});
		const wrappingContext = new TextEncoder().encode("tenant/acme");

		const generated = await provider.generateDataKey({ wrappingContext });
		const unwrapped = await provider.unwrapDataKey(generated, { wrappingContext });
		const generatedRaw = exportSecret(generated.plaintextKey);
		const unwrappedRaw = exportSecret(unwrapped);
		try {
			expect(generated.keyReference).toBe(KEY_ID);
			expect(generated.wrappingAlgorithm).toBe(AWS_KMS);
			expect(generated.wrappedKey).toEqual(new Uint8Array([90, 91, 92]));
			expect(generatedRaw).toEqual(Buffer.from(secret));
			expect(unwrappedRaw).toEqual(Buffer.from(secret));
		} finally {
			generatedRaw.fill(0);
			unwrappedRaw.fill(0);
		}

		expect(inputs).toHaveLength(2);
		expect(inputs[0]).toMatchObject({ KeyId: KEY_ID, KeySpec: "AES_256" });
		expect(inputs[1]).toMatchObject({
			KeyId: KEY_ID,
			EncryptionAlgorithm: "SYMMETRIC_DEFAULT",
		});
		const expectedDigest = createHash("sha256").update(wrappingContext).digest("base64url");
		expect(inputs[0]?.EncryptionContext).toEqual({
			application: "billing",
			[AWS_WRAPPING_CONTEXT_KEY]: expectedDigest,
		});
		expect(inputs[1]?.EncryptionContext).toEqual(inputs[0]?.EncryptionContext);

		await provider.close();
		expect(destroy).not.toHaveBeenCalled();
	});

	it("rejects aliases and the reserved encryption-context key", () => {
		expect(() => new AwsKmsProvider({ keyId: "alias/current" })).toThrowError(
			/AWS KMS requires a stable key ID/u,
		);
		expect(
			() =>
				new AwsKmsProvider({
					keyId: KEY_ID,
					encryptionContext: { [AWS_WRAPPING_CONTEXT_KEY]: "caller-value" },
				}),
		).toThrowError(/reserved key/u);
	});

	it("rejects a response from a different key without exposing provider details", async () => {
		const plaintext = new Uint8Array(32).fill(7);
		const send = vi.fn(async () => ({
			Plaintext: plaintext,
			CiphertextBlob: new Uint8Array([1]),
			KeyId: "arn:aws:kms:us-east-1:111122223333:key/different",
		}));
		const provider = new AwsKmsProvider({
			keyId: KEY_ID,
			client: { send, destroy: vi.fn() } as unknown as KMSClient,
		});

		await expect(
			provider.generateDataKey({ wrappingContext: new Uint8Array() }),
		).rejects.toMatchObject({
			code: "KEY_PROVIDER",
			message: "The key provider operation failed.",
		});
		expect(plaintext).toEqual(new Uint8Array(32));
	});

	it("fails before calling AWS for a foreign envelope key reference", async () => {
		const send = vi.fn();
		const provider = new AwsKmsProvider({
			keyId: KEY_ID,
			client: { send, destroy: vi.fn() } as unknown as KMSClient,
		});

		await expect(
			provider.unwrapDataKey(
				{
					wrappedKey: new Uint8Array([1]),
					keyReference: "arn:aws:kms:us-east-1:111122223333:key/foreign",
					wrappingAlgorithm: AWS_KMS,
				},
				{ wrappingContext: new Uint8Array() },
			),
		).rejects.toMatchObject({ code: "KEY_NOT_FOUND" });
		expect(send).not.toHaveBeenCalled();
	});

	it("never accepts an envelope-selected ARN that only shares the configured key suffix", async () => {
		const send = vi.fn();
		const provider = new AwsKmsProvider({
			keyId: KEY_ID,
			client: { send, destroy: vi.fn() } as unknown as KMSClient,
		});

		await expect(
			provider.unwrapDataKey(
				{
					wrappedKey: new Uint8Array([1]),
					keyReference: `arn:aws:kms:eu-west-1:999999999999:key/${KEY_ID}`,
					wrappingAlgorithm: AWS_KMS,
				},
				{ wrappingContext: new Uint8Array() },
			),
		).rejects.toMatchObject({ code: "KEY_NOT_FOUND" });
		expect(send).not.toHaveBeenCalled();
	});

	it("normalizes invalid ciphertext but preserves operational failures", async () => {
		const invalidCiphertext = Object.assign(new Error("provider detail"), {
			name: "InvalidCiphertextException",
		});
		const denied = Object.assign(new Error("provider detail"), { name: "AccessDeniedException" });
		const decryptingClient = {
			send: vi.fn(async () => {
				throw invalidCiphertext;
			}),
			destroy: vi.fn(),
		} as unknown as KMSClient;
		const provider = new AwsKmsProvider({ keyId: KEY_ID, client: decryptingClient });
		const wrapped = {
			wrappedKey: new Uint8Array([1]),
			keyReference: KEY_ID,
			wrappingAlgorithm: AWS_KMS,
		};

		await expect(
			provider.unwrapDataKey(wrapped, { wrappingContext: new Uint8Array() }),
		).rejects.toMatchObject({
			code: "AUTHENTICATION_FAILED",
			message: "Ciphertext authentication failed.",
		});

		const deniedProvider = new AwsKmsProvider({
			keyId: KEY_ID,
			client: {
				send: vi.fn(async () => {
					throw denied;
				}),
				destroy: vi.fn(),
			} as unknown as KMSClient,
		});
		await expect(
			deniedProvider.unwrapDataKey(wrapped, { wrappingContext: new Uint8Array() }),
		).rejects.toMatchObject({
			code: "KEY_PROVIDER",
			message: "The key provider operation failed.",
		});
	});
});
