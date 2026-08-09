import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { CryptoError } from "../../src/core/errors.js";
import { RSA_OAEP_256, RsaOaepKeyRingProvider } from "../../src/key-wrap/rsa/index.js";

function exportSecret(key: KeyObject): Buffer {
	return Buffer.from(key.export());
}

describe("RsaOaepKeyRingProvider", () => {
	it("wraps a fresh 256-bit data key with OAEP-SHA256 and the wrapping context as label", async () => {
		const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
		const provider = new RsaOaepKeyRingProvider({
			activeKeyId: "rsa-2026-08",
			keys: {
				"rsa-2026-08": pair,
			},
		});
		const context = { wrappingContext: new TextEncoder().encode("tenant:acme") };

		const generated = await provider.generateDataKey(context);
		const unwrapped = await provider.unwrapDataKey(generated, context);
		const generatedRaw = exportSecret(generated.plaintextKey);
		const unwrappedRaw = exportSecret(unwrapped);
		try {
			expect(generated.wrappingAlgorithm).toBe(RSA_OAEP_256);
			expect(generated.keyReference).toBe("rsa-2026-08");
			expect(generated.wrappedKey.byteLength).toBe(256);
			expect(unwrappedRaw).toEqual(generatedRaw);
		} finally {
			generatedRaw.fill(0);
			unwrappedRaw.fill(0);
		}
	});

	it("fails authentication when the wrapping context changes", async () => {
		const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
		const provider = new RsaOaepKeyRingProvider({
			activeKeyId: "active",
			keys: { active: pair },
		});
		const generated = await provider.generateDataKey({
			wrappingContext: new Uint8Array([1, 2, 3]),
		});

		await expect(
			provider.unwrapDataKey(generated, { wrappingContext: new Uint8Array([1, 2, 4]) }),
		).rejects.toMatchObject({
			code: "AUTHENTICATION_FAILED",
			message: "Ciphertext authentication failed.",
		});
	});

	it("keeps legacy private keys decrypt-only while using the active public key for writes", async () => {
		const oldPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
		const newPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
		const oldProvider = new RsaOaepKeyRingProvider({
			activeKeyId: "old",
			keys: { old: oldPair },
		});
		const context = { wrappingContext: new Uint8Array([7]) };
		const oldDataKey = await oldProvider.generateDataKey(context);
		const rotatedProvider = new RsaOaepKeyRingProvider({
			activeKeyId: "new",
			keys: {
				old: { privateKey: oldPair.privateKey },
				new: { publicKey: newPair.publicKey, privateKey: newPair.privateKey },
			},
		});

		const unwrapped = await rotatedProvider.unwrapDataKey(oldDataKey, context);
		const current = await rotatedProvider.generateDataKey(context);
		const expectedRaw = exportSecret(oldDataKey.plaintextKey);
		const actualRaw = exportSecret(unwrapped);
		try {
			expect(actualRaw).toEqual(expectedRaw);
			expect(current.keyReference).toBe("new");
		} finally {
			expectedRaw.fill(0);
			actualRaw.fill(0);
		}
	});

	it("rejects undersized RSA keys and mismatched pairs", () => {
		const weak = generateKeyPairSync("rsa", { modulusLength: 1024 });
		expect(
			() =>
				new RsaOaepKeyRingProvider({
					activeKeyId: "weak",
					keys: { weak },
				}),
		).toThrowError(CryptoError);

		const first = generateKeyPairSync("rsa", { modulusLength: 2048 });
		const second = generateKeyPairSync("rsa", { modulusLength: 2048 });
		expect(
			() =>
				new RsaOaepKeyRingProvider({
					activeKeyId: "mismatch",
					keys: {
						mismatch: {
							publicKey: first.publicKey,
							privateKey: second.privateKey,
						},
					},
				}),
		).toThrowError(CryptoError);
	});

	it("honors an already-aborted signal", async () => {
		const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
		const provider = new RsaOaepKeyRingProvider({
			activeKeyId: "active",
			keys: { active: pair },
		});
		const controller = new AbortController();
		controller.abort(new Error("cancelled"));

		await expect(
			provider.generateDataKey({
				wrappingContext: new Uint8Array(),
				signal: controller.signal,
			}),
		).rejects.toMatchObject({ code: "ABORTED" });
	});
});
