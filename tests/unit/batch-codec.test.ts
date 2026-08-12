import { randomBytes } from "node:crypto";
import { type TenantContextReader, type TenantTarget } from "@nestm/tenant/context";
import { describe, expect, it } from "vitest";
import { CipherService } from "../../src/cipher.service.js";
import {
	AesKeyRingProvider,
	CipherEngine,
	jsonCodec,
	type CipherCodec,
	type DataKeyContext,
	type DataKeyProvider,
	type GeneratedDataKey,
	type WrappedDataKey,
} from "../../src/core/index.js";
import { TenantCipherService, type TenantCryptoPolicy } from "../../src/tenant/index.js";
import { TenantCryptoScopeService } from "../../src/tenant/tenant-cipher.service.js";

class CountingProvider implements DataKeyProvider {
	generateCalls = 0;
	unwrapCalls = 0;
	readonly #delegate = new AesKeyRingProvider({
		activeKeyId: "batch-key",
		keys: { "batch-key": new Uint8Array(randomBytes(32)) },
	});

	generateDataKey(context: DataKeyContext): Promise<GeneratedDataKey> {
		this.generateCalls += 1;
		return this.#delegate.generateDataKey(context);
	}

	unwrapDataKey(dataKey: WrappedDataKey, context: DataKeyContext) {
		this.unwrapCalls += 1;
		return this.#delegate.unwrapDataKey(dataKey, context);
	}
}

function tenantTarget(id: string): TenantTarget {
	return Object.freeze({
		tenant: Object.freeze({ id, settings: Object.freeze({}), source: "test" }),
		authority: "tenant",
	});
}

class MutableTenantContext implements TenantContextReader {
	target = tenantTarget("alpha");

	current(): ReturnType<TenantContextReader["current"]> {
		return { mode: "tenant", tenant: this.target.tenant };
	}

	require(): ReturnType<TenantContextReader["require"]> {
		const state = this.current();
		if (!state) throw new Error("Missing test tenant context.");
		return state;
	}

	requireTenant(): ReturnType<TenantContextReader["requireTenant"]> {
		return this.target.tenant;
	}

	requireTenantId(): string {
		return this.target.tenant.id;
	}

	requireTenantTarget(): TenantTarget {
		return this.target;
	}
}

function createCipher(provider = new CountingProvider()): {
	readonly cipher: CipherService;
	readonly provider: CountingProvider;
} {
	return {
		provider,
		cipher: new CipherService(
			new CipherEngine({
				providers: [{ name: "local", provider }],
				defaultProvider: "local",
			}),
		),
	};
}

function createTenant(): {
	readonly cipher: CipherService;
	readonly context: MutableTenantContext;
	readonly provider: CountingProvider;
	readonly policyCalls: () => number;
	readonly tenant: TenantCipherService;
} {
	const { cipher, provider } = createCipher();
	const context = new MutableTenantContext();
	let calls = 0;
	const policy: TenantCryptoPolicy = {
		resolve: () => {
			calls += 1;
			return { writeProvider: "local", readProviders: ["local"] };
		},
	};
	const scope = new TenantCryptoScopeService(context, cipher, policy, {
		namespace: "batch-codec-test",
	});
	return {
		cipher,
		context,
		provider,
		policyCalls: () => calls,
		tenant: new TenantCipherService(cipher, scope),
	};
}

interface Profile {
	readonly id: string;
	readonly flags: readonly string[];
}

function profileValidator(value: unknown): Profile {
	if (
		typeof value !== "object" ||
		value === null ||
		!("id" in value) ||
		typeof value.id !== "string" ||
		!("flags" in value) ||
		!Array.isArray(value.flags) ||
		!value.flags.every((flag: unknown) => typeof flag === "string")
	) {
		throw new TypeError("Invalid profile.");
	}
	return { id: value.id, flags: Object.freeze([...value.flags]) };
}

describe("text batches and typed codecs", () => {
	it("round trips text batches with one generated and unwrapped data key", async () => {
		const { cipher, provider } = createCipher();
		const encrypted = await cipher.encryptTextBatch([
			{ plaintext: "first", aad: "field-a" },
			{ plaintext: "second 👋", aad: "field-b" },
		]);

		expect(Object.isFrozen(encrypted)).toBe(true);
		expect(provider.generateCalls).toBe(1);
		await expect(
			cipher.decryptTextBatch([
				{ envelope: encrypted[0] ?? "", aad: "field-a" },
				{ envelope: encrypted[1] ?? "", aad: "field-b" },
			]),
		).resolves.toEqual(["first", "second 👋"]);
		expect(provider.unwrapCalls).toBe(1);

		await expect(
			cipher.decryptTextBatch([{ envelope: encrypted[0] ?? "", aad: "field-b" }]),
		).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
	});

	it("bounds batch item counts and aggregate bytes before provider calls", async () => {
		const provider = new CountingProvider();
		const cipher = new CipherService(
			new CipherEngine({
				providers: [{ name: "local", provider }],
				defaultProvider: "local",
				maxBatchItems: 2,
				maxBatchBytes: 4,
			}),
		);

		await expect(
			cipher.encryptTextBatch([{ plaintext: "a" }, { plaintext: "b" }, { plaintext: "c" }]),
		).rejects.toMatchObject({ code: "LIMIT_EXCEEDED" });
		await expect(cipher.encryptTextBatch([{ plaintext: "12345" }])).rejects.toMatchObject({
			code: "LIMIT_EXCEEDED",
		});
		expect(provider.generateCalls).toBe(0);

		const first = await cipher.encryptText("abc");
		const second = await cipher.encryptText("def");
		provider.unwrapCalls = 0;
		await expect(
			cipher.decryptTextBatch([{ envelope: first }, { envelope: second }]),
		).rejects.toMatchObject({ code: "LIMIT_EXCEEDED" });
		expect(provider.unwrapCalls).toBe(0);
	});

	it("rejects oversized tenant protection batches before policy or provider work", async () => {
		const { tenant, provider, policyCalls } = createTenant();
		const items = Array.from({ length: 257 }, (_, index) => ({
			value: `value-${index}`,
			purpose: "bounded.field",
		}));

		await expect(tenant.protectTextBatch(items)).rejects.toMatchObject({
			code: "LIMIT_EXCEEDED",
		});
		expect(policyCalls()).toBe(0);
		expect(provider.generateCalls).toBe(0);
		expect(provider.unwrapCalls).toBe(0);
	});

	it("round trips validated JSON and clears the decoder's ephemeral view", async () => {
		const { cipher } = createCipher();
		const profile: Profile = { id: "p1", flags: ["admin"] };
		const codec = jsonCodec(profileValidator);
		const envelope = await cipher.encryptValue(profile, codec, { aad: "profile" });
		await expect(cipher.decryptValue(envelope, codec, { aad: "profile" })).resolves.toEqual(
			profile,
		);

		let decoderView: Uint8Array | undefined;
		const inspectingCodec: CipherCodec<string> = {
			encode: (value) => new TextEncoder().encode(value),
			decode: (plaintext) => {
				decoderView = plaintext;
				return new TextDecoder().decode(plaintext);
			},
		};
		const textEnvelope = await cipher.encryptValue("ephemeral", inspectingCodec);
		await expect(cipher.decryptValue(textEnvelope, inspectingCodec)).resolves.toBe("ephemeral");
		expect(decoderView).toEqual(new Uint8Array("ephemeral".length));
	});

	it("fails closed when a JSON validator rejects authenticated plaintext", async () => {
		const { cipher } = createCipher();
		const envelope = await cipher.encryptValue(
			{ id: "p1", flags: [] },
			jsonCodec(profileValidator),
		);
		const rejecting = jsonCodec<Profile>(() => {
			throw new Error("PLAINTEXT_SENTINEL");
		});

		try {
			await cipher.decryptValue(envelope, rejecting);
			throw new Error("Expected codec validation to fail.");
		} catch (error: unknown) {
			expect(error).toMatchObject({
				code: "CIPHER_FAILURE",
				message: "The cipher codec could not decode the value.",
			});
			expect(String(error)).not.toContain("SENTINEL");
		}
	});

	it("normalizes invalid codec contracts, encoded bytes, and JSON payloads", async () => {
		const { cipher } = createCipher();
		const missingDecode = {
			encode: (value: string) => new TextEncoder().encode(value),
		};
		await expect(
			// @ts-expect-error Exercises runtime validation of an incomplete codec contract.
			cipher.encryptValue("value", missingDecode),
		).rejects.toMatchObject({
			code: "INVALID_ARGUMENT",
			message: "The cipher codec is invalid.",
		});

		const attachedPropertyCodec: CipherCodec<string> = {
			encode: (value) => {
				const encoded = new TextEncoder().encode(value);
				Object.defineProperty(encoded, "attached", { value: true });
				return encoded;
			},
			decode: (plaintext) => new TextDecoder().decode(plaintext),
		};
		await expect(cipher.encryptValue("value", attachedPropertyCodec)).rejects.toMatchObject({
			code: "INVALID_ARGUMENT",
			message: "The cipher codec could not encode the value.",
		});

		const circular: { self?: unknown } = {};
		circular.self = circular;
		await expect(
			cipher.encryptValue(
				circular,
				jsonCodec((value) => value),
			),
		).rejects.toMatchObject({
			code: "INVALID_ARGUMENT",
		});
		await expect(
			cipher.encryptValue(
				undefined,
				jsonCodec<undefined>(() => undefined),
			),
		).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });

		const nonJsonEnvelope = await cipher.encryptText("not-json");
		await expect(
			cipher.decryptValue(
				nonJsonEnvelope,
				jsonCodec((value) => value),
			),
		).rejects.toMatchObject({ code: "CIPHER_FAILURE" });
		expect(() =>
			// @ts-expect-error Exercises runtime validation of the JSON validator contract.
			jsonCodec("not-a-validator"),
		).toThrow(expect.objectContaining({ code: "INVALID_ARGUMENT" }));
	});

	it("resolves one tenant route for each batch and binds every item independently", async () => {
		const { tenant, provider, policyCalls } = createTenant();
		const encrypted = await tenant.encryptTextBatch([
			{ plaintext: "one", purpose: "account.email", aad: "account-1" },
			{ plaintext: "two", purpose: "account.phone", aad: "account-1" },
		]);
		expect(policyCalls()).toBe(1);
		expect(provider.generateCalls).toBe(1);

		await expect(
			tenant.decryptTextBatch([
				{
					envelope: encrypted[0] ?? "",
					purpose: "account.email",
					aad: "account-1",
				},
				{
					envelope: encrypted[1] ?? "",
					purpose: "account.phone",
					aad: "account-1",
				},
			]),
		).resolves.toEqual(["one", "two"]);
		expect(policyCalls()).toBe(2);
		expect(provider.unwrapCalls).toBe(1);

		await expect(
			tenant.decryptTextBatch([
				{ envelope: encrypted[0] ?? "", purpose: "account.phone", aad: "account-1" },
			]),
		).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
	});

	it("protects plaintext in one write batch and authenticates reserved values first", async () => {
		const { tenant, provider, policyCalls } = createTenant();
		const existing = await tenant.encryptText("already protected", {
			purpose: "customer.tax-id",
			aad: "customer-1",
		});
		const callsBefore = policyCalls();
		provider.generateCalls = 0;
		provider.unwrapCalls = 0;

		const protectedValues = await tenant.protectTextBatch([
			{ value: existing, purpose: "customer.tax-id", aad: "customer-1" },
			{ value: "new value", purpose: "customer.name", aad: "customer-1" },
		]);
		expect(policyCalls() - callsBefore).toBe(1);
		expect(provider.unwrapCalls).toBe(1);
		expect(provider.generateCalls).toBe(1);
		expect(protectedValues[0]).toBe(existing);
		await expect(
			tenant.decryptTextBatch([
				{
					envelope: protectedValues[0] ?? "",
					purpose: "customer.tax-id",
					aad: "customer-1",
				},
				{
					envelope: protectedValues[1] ?? "",
					purpose: "customer.name",
					aad: "customer-1",
				},
			]),
		).resolves.toEqual(["already protected", "new value"]);

		provider.generateCalls = 0;
		await expect(
			tenant.protectTextBatch([
				{ value: existing, purpose: "customer.name", aad: "customer-1" },
				{ value: "must not encrypt", purpose: "customer.name", aad: "customer-1" },
			]),
		).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
		expect(provider.generateCalls).toBe(0);

		await expect(
			tenant.protectTextBatch([
				{ value: "nmc-not-an-envelope", purpose: "customer.name" },
				{ value: "must not encrypt", purpose: "customer.name" },
			]),
		).rejects.toMatchObject({ code: "MALFORMED_ENVELOPE" });
		expect(provider.generateCalls).toBe(0);
	});

	it("captures a tenant value through its codec before asynchronous policy resolution", async () => {
		const { cipher } = createCipher();
		const context = new MutableTenantContext();
		let release: (() => void) | undefined;
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		const policy: TenantCryptoPolicy = {
			resolve: async () => {
				await gate;
				return { writeProvider: "local" };
			},
		};
		const tenant = new TenantCipherService(
			cipher,
			new TenantCryptoScopeService(context, cipher, policy, {
				namespace: "codec-snapshot-test",
			}),
		);
		const mutable = { id: "before", flags: ["first"] };
		const codec = jsonCodec(profileValidator);
		const pending = tenant.encryptValue(mutable, codec, { purpose: "profile.document" });
		mutable.id = "after";
		mutable.flags[0] = "changed";
		release?.();

		const envelope = await pending;
		await expect(
			tenant.decryptValue(envelope, codec, { purpose: "profile.document" }),
		).resolves.toEqual({ id: "before", flags: ["first"] });
	});
});
