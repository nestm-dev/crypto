import { createSecretKey, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	Aes256GcmCipher,
	AesKeyRingProvider,
	CipherEngine,
	CryptoError,
	frame,
	isCryptoError,
	utf8,
	type DataKeyContext,
	type DataKeyProvider,
	type GeneratedDataKey,
	type WrappedDataKey,
	type CipherAlgorithm,
} from "../../src/core/index.js";

function engine(
	key = new Uint8Array(randomBytes(32)),
	options: { readonly maxPayloadBytes?: number; readonly noncePrefix?: Uint8Array } = {},
): CipherEngine {
	const noncePrefix = options.noncePrefix;
	return new CipherEngine({
		providers: [
			{
				name: "local",
				provider: new AesKeyRingProvider({ activeKeyId: "k1", keys: { k1: key } }),
			},
		],
		defaultProvider: "local",
		...(options.maxPayloadBytes === undefined ? {} : { maxPayloadBytes: options.maxPayloadBytes }),
		...(noncePrefix
			? {
					nonceSource: (length: number) => {
						expect(length).toBe(8);
						return noncePrefix;
					},
				}
			: {}),
	});
}

function mutateSegment(envelope: string, index: number): string {
	const parts = envelope.split(".");
	const value = parts[index];
	if (!value) throw new Error("Missing test envelope segment.");
	parts[index] = `${value[0] === "A" ? "B" : "A"}${value.slice(1)}`;
	return parts.join(".");
}

describe("Aes256GcmCipher", () => {
	it("matches the empty-message AES-256-GCM vector", () => {
		const cipher = new Aes256GcmCipher();
		const result = cipher.encrypt({
			plaintext: new Uint8Array(),
			key: createSecretKey(new Uint8Array(32)),
			nonce: new Uint8Array(12),
			aad: new Uint8Array(),
		});

		expect(Buffer.from(result.ciphertext).toString("hex")).toBe("");
		expect(Buffer.from(result.tag).toString("hex")).toBe("530f8afbc74536b9a963b4f1c4cb738b");
	});
});

describe("CipherEngine", () => {
	it.each(["", "hello 👋", "\u0000binary-safe text"])("round trips text %j", async (value) => {
		const cipher = engine();
		const envelope = await cipher.encryptText(value);
		await expect(cipher.decryptText(envelope)).resolves.toBe(value);
	});

	it("round trips binary without mutating input", async () => {
		const cipher = engine();
		const input = new Uint8Array([0, 1, 2, 255]);
		const before = new Uint8Array(input);
		const envelope = await cipher.encryptBytes(input);
		expect(input).toEqual(before);
		expect(await cipher.decryptBytes(envelope)).toEqual(before);
	});

	it("uses fresh data keys and nonces", async () => {
		const cipher = engine();
		const first = await cipher.encryptText("same");
		const second = await cipher.encryptText("same");
		expect(first).not.toBe(second);
		expect(first.split(".")[3]).not.toBe(second.split(".")[3]);
	});

	it("round trips a named cipher alias and records the alias in the envelope", async () => {
		const cipher = new CipherEngine({
			providers: [
				{
					name: "local",
					provider: new AesKeyRingProvider({
						activeKeyId: "k1",
						keys: { k1: new Uint8Array(randomBytes(32)) },
					}),
				},
			],
			defaultProvider: "local",
			ciphers: [{ name: "records-v1", cipher: new Aes256GcmCipher() }],
			defaultCipher: "records-v1",
		});
		const envelope = await cipher.encryptText("aliased");
		expect(cipher.inspect(envelope).cipher).toBe("records-v1");
		await expect(cipher.decryptText(envelope)).resolves.toBe("aliased");
	});

	it("guarantees unique batch nonces while wrapping one data key", async () => {
		const cipher = engine(new Uint8Array(randomBytes(32)), {
			noncePrefix: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
		});
		const envelopes = await cipher.encryptBatch([
			{ plaintext: utf8("a") },
			{ plaintext: utf8("b") },
		]);
		const [first, second] = envelopes;
		expect(first?.split(".")[2]).toBe(second?.split(".")[2]);
		expect(first?.split(".")[3]).not.toBe(second?.split(".")[3]);
	});

	it("matches a deterministic envelope vector through the nonce test seam", async () => {
		const key = createSecretKey(new Uint8Array(32));
		const provider: DataKeyProvider = {
			generateDataKey: async () => ({
				plaintextKey: key,
				wrappedKey: new Uint8Array([1, 2, 3]),
				keyReference: "fixed-key",
				wrappingAlgorithm: "TEST-WRAP",
			}),
			unwrapDataKey: async () => key,
		};
		const cipher = new CipherEngine({
			providers: [{ name: "fixed", provider }],
			defaultProvider: "fixed",
			nonceSource: () => new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
		});
		const envelope = await cipher.encryptText("deterministic", {
			aad: "vector-aad",
			keyContext: "vector-key-context",
		});
		expect(envelope).toBe(
			"nmc1.eyJ2IjoxLCJjaXBoZXIiOiJBRVMtMjU2LUdDTSIsInByb3ZpZGVyIjoiZml4ZWQiLCJrZXkiOiJmaXhlZC1rZXkiLCJ3cmFwIjoiVEVTVC1XUkFQIn0.AQID.AAECAwQFBgcAAAAA.LimBHiZrVPM0WiN8Iw.6V39BNQ2YaEi_B-actGzQA",
		);
		await expect(
			cipher.decryptText(envelope, {
				aad: "vector-aad",
				keyContext: "vector-key-context",
			}),
		).resolves.toBe("deterministic");
	});

	it("binds caller AAD and key context", async () => {
		const cipher = engine();
		const envelope = await cipher.encryptText("secret", {
			aad: frame(utf8("tenant"), utf8("purpose")),
			keyContext: "tenant-key-context",
		});
		await expect(
			cipher.decryptText(envelope, {
				aad: frame(utf8("tenant"), utf8("purpose")),
				keyContext: "tenant-key-context",
			}),
		).resolves.toBe("secret");
		await expect(
			cipher.decryptText(envelope, { aad: "wrong", keyContext: "tenant-key-context" }),
		).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
		await expect(
			cipher.decryptText(envelope, {
				aad: frame(utf8("tenant"), utf8("purpose")),
				keyContext: "wrong",
			}),
		).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
	});

	it.each([1, 2, 3, 4, 5])("rejects tampering in envelope segment %s", async (segment) => {
		const cipher = engine();
		const envelope = await cipher.encryptText("secret");
		await expect(cipher.decryptText(mutateSegment(envelope, segment))).rejects.toBeInstanceOf(
			CryptoError,
		);
	});

	it("rejects wrong keys with a normalized authentication error", async () => {
		const first = engine();
		const second = engine();
		const envelope = await first.encryptText("do not leak");
		await expect(second.decryptText(envelope)).rejects.toMatchObject({
			code: "AUTHENTICATION_FAILED",
			message: "Ciphertext authentication failed.",
		});
	});

	it("rejects malformed and unsupported envelopes", async () => {
		const cipher = engine();
		await expect(cipher.decryptText("nope")).rejects.toMatchObject({ code: "MALFORMED_ENVELOPE" });
		await expect(cipher.decryptText("nmc2.a.b.c.d.e")).rejects.toMatchObject({
			code: "UNSUPPORTED_VERSION",
		});
	});

	it("classifies invalid UTF-8 headers and noncanonical segments as malformed", async () => {
		const cipher = engine();
		const nonce = Buffer.alloc(12).toString("base64url");
		const tag = Buffer.alloc(16).toString("base64url");
		await expect(cipher.decryptText(`nmc1._w.AA.${nonce}..${tag}`)).rejects.toMatchObject({
			code: "MALFORMED_ENVELOPE",
		});
		const envelope = await cipher.encryptText("canonical");
		const segments = envelope.split(".");
		segments[3] = `${segments[3]}=`;
		await expect(cipher.decryptText(segments.join("."))).rejects.toMatchObject({
			code: "MALFORMED_ENVELOPE",
		});
	});

	it("rejects truncated and pre-decode oversized envelopes", async () => {
		const cipher = engine(new Uint8Array(randomBytes(32)), { maxPayloadBytes: 3 });
		const envelope = await cipher.encryptText("abc");
		const parts = envelope.split(".");
		for (let length = 1; length < 6; length += 1) {
			await expect(cipher.decryptText(parts.slice(0, length).join("."))).rejects.toBeInstanceOf(
				CryptoError,
			);
		}
		parts[4] = "A".repeat(6);
		await expect(cipher.decryptText(parts.join("."))).rejects.toMatchObject({
			code: "LIMIT_EXCEEDED",
		});
		parts[4] = "";
		parts[2] = "A".repeat(87_383);
		await expect(cipher.decryptText(parts.join("."))).rejects.toMatchObject({
			code: "MALFORMED_ENVELOPE",
		});
	});

	it("enforces payload limits", async () => {
		const cipher = engine(new Uint8Array(randomBytes(32)), { maxPayloadBytes: 3 });
		await expect(cipher.encryptText("four")).rejects.toMatchObject({ code: "LIMIT_EXCEEDED" });
	});

	it("rejects invalid local and provider-generated data keys before emitting an envelope", async () => {
		expect(
			() =>
				new AesKeyRingProvider({
					activeKeyId: "bad",
					keys: { bad: new Uint8Array(31) },
				}),
		).toThrowError(CryptoError);

		const invalidProvider: DataKeyProvider = {
			generateDataKey: async (): Promise<GeneratedDataKey> => ({
				plaintextKey: createSecretKey(new Uint8Array(32)),
				wrappedKey: new Uint8Array(),
				keyReference: "invalid",
				wrappingAlgorithm: "TEST",
			}),
			unwrapDataKey: async () => createSecretKey(new Uint8Array(32)),
		};
		const cipher = new CipherEngine({
			providers: [{ name: "invalid", provider: invalidProvider }],
			defaultProvider: "invalid",
		});
		await expect(cipher.encryptText("must not emit")).rejects.toMatchObject({
			code: "INVALID_KEY",
		});
	});

	it("snapshots mutable byte inputs and AAD before awaiting a provider", async () => {
		let release: (() => void) | undefined;
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		const delegate = new AesKeyRingProvider({
			activeKeyId: "k1",
			keys: { k1: new Uint8Array(randomBytes(32)) },
		});
		const delayed: DataKeyProvider = {
			generateDataKey: async (context: DataKeyContext) => {
				await gate;
				return delegate.generateDataKey(context);
			},
			unwrapDataKey: (dataKey: WrappedDataKey, context: DataKeyContext) =>
				delegate.unwrapDataKey(dataKey, context),
		};
		const cipher = new CipherEngine({
			providers: [{ name: "delayed", provider: delayed }],
			defaultProvider: "delayed",
		});
		const plaintext = new Uint8Array([1, 2, 3]);
		const aad = new Uint8Array([4, 5]);
		const keyContext = new Uint8Array([6, 7]);
		const pending = cipher.encryptBytes(plaintext, { aad, keyContext });
		plaintext.fill(9);
		aad.fill(9);
		keyContext.fill(9);
		release?.();
		const envelope = await pending;
		await expect(
			cipher.decryptBytes(envelope, {
				aad: new Uint8Array([4, 5]),
				keyContext: new Uint8Array([6, 7]),
			}),
		).resolves.toEqual(new Uint8Array([1, 2, 3]));
	});

	it("aborts promptly when a provider ignores the signal", async () => {
		let started: (() => void) | undefined;
		const providerStarted = new Promise<void>((resolve) => {
			started = resolve;
		});
		const never = new Promise<GeneratedDataKey>(() => undefined);
		const provider: DataKeyProvider = {
			generateDataKey: () => {
				started?.();
				return never;
			},
			unwrapDataKey: async () => createSecretKey(new Uint8Array(32)),
		};
		const cipher = new CipherEngine({
			providers: [{ name: "pending", provider }],
			defaultProvider: "pending",
		});
		const controller = new AbortController();
		const pending = cipher.encryptText("cancel", { signal: controller.signal });
		await providerStarted;
		controller.abort();
		await expect(pending).rejects.toMatchObject({ code: "ABORTED" });
	});

	it("redacts arbitrary provider causes", async () => {
		const provider: DataKeyProvider = {
			generateDataKey: async () => {
				throw new Error("PLAINTEXT_SENTINEL KEY_SENTINEL");
			},
			unwrapDataKey: async () => createSecretKey(new Uint8Array(32)),
		};
		const cipher = new CipherEngine({
			providers: [{ name: "failing", provider }],
			defaultProvider: "failing",
		});
		try {
			await cipher.encryptText("PLAINTEXT_SENTINEL");
			throw new Error("Expected encryption to fail.");
		} catch (error: unknown) {
			expect(isCryptoError(error, "KEY_PROVIDER")).toBe(true);
			const rendered = `${String(error)} ${JSON.stringify(error)} ${String(
				error instanceof Error ? error.cause : undefined,
			)}`;
			expect(rendered).not.toContain("PLAINTEXT_SENTINEL");
			expect(rendered).not.toContain("KEY_SENTINEL");
		}
	});

	it("does not trust provider-authored CryptoError messages or hostile cause accessors", async () => {
		const authored: DataKeyProvider = {
			generateDataKey: async () => {
				throw new CryptoError("KEY_PROVIDER", "PLAINTEXT_SENTINEL KEY_SENTINEL");
			},
			unwrapDataKey: async () => createSecretKey(new Uint8Array(32)),
		};
		const authoredEngine = new CipherEngine({
			providers: [{ name: "authored", provider: authored }],
			defaultProvider: "authored",
		});
		try {
			await authoredEngine.encryptText("PLAINTEXT_SENTINEL");
			throw new Error("Expected encryption to fail.");
		} catch (error: unknown) {
			expect(isCryptoError(error, "KEY_PROVIDER")).toBe(true);
			expect(String(error)).not.toContain("SENTINEL");
		}

		const hostileCause = new Proxy(
			{},
			{
				has: () => true,
				get: () => {
					throw new Error("KEY_SENTINEL");
				},
			},
		);
		const hostile: DataKeyProvider = {
			generateDataKey: async () => {
				throw hostileCause;
			},
			unwrapDataKey: async () => createSecretKey(new Uint8Array(32)),
		};
		const hostileEngine = new CipherEngine({
			providers: [{ name: "hostile", provider: hostile }],
			defaultProvider: "hostile",
		});
		await expect(hostileEngine.encryptText("secret")).rejects.toMatchObject({
			code: "KEY_PROVIDER",
			message: "The key provider operation failed.",
		});
	});

	it("normalizes hostile byte-view accessors at public input boundaries", async () => {
		const hostile = new Uint8Array([1]);
		Object.defineProperty(hostile, "buffer", {
			get: () => {
				throw new Error("PLAINTEXT_SENTINEL");
			},
		});
		const hostileLength = new Uint8Array([1]);
		Object.setPrototypeOf(
			hostileLength,
			Object.create(Uint8Array.prototype, {
				byteLength: {
					get: () => {
						throw new Error("PLAINTEXT_SENTINEL");
					},
				},
			}),
		);
		const cipher = engine();
		for (const operation of [
			() => cipher.encryptBytes(hostile),
			() => cipher.encryptBytes(hostileLength),
			() => cipher.encryptText("secret", { aad: hostile }),
			() => cipher.encryptText("secret", { keyContext: hostile }),
		]) {
			try {
				await operation();
				throw new Error("Expected hostile bytes to fail.");
			} catch (error: unknown) {
				expect(isCryptoError(error, "INVALID_ARGUMENT")).toBe(true);
				expect(String(error)).not.toContain("SENTINEL");
			}
		}
	});

	it("normalizes hostile provider and cipher result getters", async () => {
		const generated: GeneratedDataKey = {
			get plaintextKey(): never {
				throw new Error("KEY_SENTINEL");
			},
			wrappedKey: new Uint8Array([1]),
			keyReference: "key",
			wrappingAlgorithm: "TEST",
		};
		const provider: DataKeyProvider = {
			generateDataKey: async () => generated,
			unwrapDataKey: async () => createSecretKey(new Uint8Array(32)),
		};
		const providerEngine = new CipherEngine({
			providers: [{ name: "getter", provider }],
			defaultProvider: "getter",
		});
		await expect(providerEngine.encryptText("secret")).rejects.toMatchObject({
			code: "INVALID_KEY",
			message: "The key provider returned invalid key material.",
		});

		const delegate = new Aes256GcmCipher();
		const cipherWithGetter: CipherAlgorithm = {
			name: "GETTER",
			keyLength: delegate.keyLength,
			nonceLength: delegate.nonceLength,
			tagLength: delegate.tagLength,
			encrypt: () => ({
				get ciphertext(): never {
					throw new Error("PLAINTEXT_SENTINEL");
				},
				tag: new Uint8Array(delegate.tagLength),
			}),
			decrypt: (input) => delegate.decrypt(input),
		};
		const key = new Uint8Array(randomBytes(32));
		const cipherEngine = new CipherEngine({
			providers: [
				{
					name: "local",
					provider: new AesKeyRingProvider({ activeKeyId: "k1", keys: { k1: key } }),
				},
			],
			defaultProvider: "local",
			ciphers: [{ name: "getter", cipher: cipherWithGetter }],
			defaultCipher: "getter",
		});
		try {
			await cipherEngine.encryptText("PLAINTEXT_SENTINEL");
			throw new Error("Expected encryption to fail.");
		} catch (error: unknown) {
			expect(isCryptoError(error, "CIPHER_FAILURE")).toBe(true);
			expect(String(error)).not.toContain("PLAINTEXT_SENTINEL");
		}
	});

	it("snapshots registry entries and redacts provider close failures", async () => {
		const first = new AesKeyRingProvider({
			activeKeyId: "first",
			keys: { first: new Uint8Array(randomBytes(32)) },
		});
		const second = new AesKeyRingProvider({
			activeKeyId: "second",
			keys: { second: new Uint8Array(randomBytes(32)) },
		});
		const registration: { name: string; provider: DataKeyProvider } = {
			name: "route",
			provider: first,
		};
		const routed = new CipherEngine({
			providers: [registration],
			defaultProvider: "route",
		});
		registration.provider = second;
		const envelope = await routed.encryptText("stable");
		expect(routed.inspect(envelope).keyReference).toBe("first");

		const failingClose: DataKeyProvider = {
			generateDataKey: (context) => first.generateDataKey(context),
			unwrapDataKey: (dataKey, context) => first.unwrapDataKey(dataKey, context),
			close: async () => {
				throw new Error("KEY_SENTINEL");
			},
		};
		const closable = new CipherEngine({
			providers: [{ name: "close", provider: failingClose }],
			defaultProvider: "close",
		});
		await expect(closable.close()).rejects.toMatchObject({
			code: "KEY_PROVIDER",
			message: "The key provider operation failed.",
		});
	});

	it("normalizes and redacts pluggable cipher exceptions", async () => {
		const delegate = new Aes256GcmCipher();
		const throwingEncrypt: CipherAlgorithm = {
			name: "THROW-ENCRYPT",
			keyLength: delegate.keyLength,
			nonceLength: delegate.nonceLength,
			tagLength: delegate.tagLength,
			encrypt: () => {
				throw new Error("PLAINTEXT_SENTINEL");
			},
			decrypt: (input) => delegate.decrypt(input),
		};
		const key = new Uint8Array(randomBytes(32));
		const provider = new AesKeyRingProvider({ activeKeyId: "k1", keys: { k1: key } });
		const encrypting = new CipherEngine({
			providers: [{ name: "local", provider }],
			defaultProvider: "local",
			ciphers: [{ name: "throwing", cipher: throwingEncrypt }],
			defaultCipher: "throwing",
		});
		await expect(encrypting.encryptText("secret")).rejects.toMatchObject({
			code: "CIPHER_FAILURE",
			message: "Encryption failed.",
		});

		const throwingDecrypt: CipherAlgorithm = {
			name: "THROW-DECRYPT",
			keyLength: delegate.keyLength,
			nonceLength: delegate.nonceLength,
			tagLength: delegate.tagLength,
			encrypt: (input) => delegate.encrypt(input),
			decrypt: () => {
				throw new Error("PLAINTEXT_SENTINEL");
			},
		};
		const decrypting = new CipherEngine({
			providers: [{ name: "local", provider }],
			defaultProvider: "local",
			ciphers: [{ name: "throwing", cipher: throwingDecrypt }],
			defaultCipher: "throwing",
		});
		const envelope = await decrypting.encryptText("secret");
		try {
			await decrypting.decryptText(envelope);
			throw new Error("Expected decryption to fail.");
		} catch (error: unknown) {
			expect(isCryptoError(error, "AUTHENTICATION_FAILED")).toBe(true);
			expect(
				`${String(error)} ${String(error instanceof Error ? error.cause : undefined)}`,
			).not.toContain("PLAINTEXT_SENTINEL");
		}
	});

	it("rejects cipher configurations that cannot fit the v1 envelope", () => {
		const provider = new AesKeyRingProvider({
			activeKeyId: "k1",
			keys: { k1: new Uint8Array(randomBytes(32)) },
		});
		const delegate = new Aes256GcmCipher();
		const configured = (overrides: Partial<CipherAlgorithm>): CipherAlgorithm => ({
			name: "TEST",
			keyLength: 32,
			nonceLength: 12,
			tagLength: 16,
			encrypt: (input) => delegate.encrypt(input),
			decrypt: (input) => delegate.decrypt(input),
			...overrides,
		});
		for (const cipher of [configured({ nonceLength: 13 }), configured({ tagLength: 65 })]) {
			expect(
				() =>
					new CipherEngine({
						providers: [{ name: "local", provider }],
						defaultProvider: "local",
						ciphers: [{ name: "custom", cipher }],
						defaultCipher: "custom",
					}),
			).toThrowError(CryptoError);
		}
		expect(
			() =>
				new CipherEngine({
					providers: [{ name: "local", provider }],
					defaultProvider: "local",
					ciphers: [{ name: "x".repeat(129), cipher: delegate }],
					defaultCipher: "x".repeat(129),
				}),
		).toThrowError(CryptoError);
	});

	it("inspects metadata without claiming authentication", async () => {
		const cipher = engine();
		const envelope = await cipher.encryptText("secret");
		expect(cipher.inspect(envelope)).toMatchObject({
			version: 1,
			cipher: "AES-256-GCM",
			provider: "local",
			keyReference: "k1",
			authenticated: false,
		});
	});

	it("reencrypts to a new provider route", async () => {
		const oldProvider = new AesKeyRingProvider({
			activeKeyId: "old-key",
			keys: { "old-key": new Uint8Array(randomBytes(32)) },
		});
		const newProvider = new AesKeyRingProvider({
			activeKeyId: "new-key",
			keys: { "new-key": new Uint8Array(randomBytes(32)) },
		});
		const cipher = new CipherEngine({
			providers: [
				{ name: "old", provider: oldProvider },
				{ name: "new", provider: newProvider },
			],
			defaultProvider: "new",
		});
		const oldEnvelope = await cipher.encryptText("rotate", { provider: "old" });
		const rotated = await cipher.reencrypt(oldEnvelope, {
			allowedProviders: ["old", "new"],
			provider: "new",
		});
		expect(cipher.inspect(rotated).provider).toBe("new");
		await expect(cipher.decryptText(rotated, { allowedProviders: ["new"] })).resolves.toBe(
			"rotate",
		);
	});

	it("isolates concurrent calls", async () => {
		const cipher = engine();
		const values = Array.from({ length: 50 }, (_, index) => `value-${index}`);
		const encrypted = await Promise.all(values.map((value) => cipher.encryptText(value)));
		await expect(Promise.all(encrypted.map((value) => cipher.decryptText(value)))).resolves.toEqual(
			values,
		);
	});
});
