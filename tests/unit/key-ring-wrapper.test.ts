import {
	createDecipheriv,
	createHash,
	createSecretKey,
	hkdfSync,
	type KeyObject,
} from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	AesKeyRingProvider,
	AES_GCM_HKDF_SHA256_KEY_WRAP,
	isCryptoError,
	utf8,
	type WrappedDataKey,
} from "../../src/core/index.js";

/**
 * The key-ring wrapper format itself.
 *
 * The rest of the suite drives `AesKeyRingProvider` through `CipherEngine`, which
 * round-trips whatever the provider produces and therefore passes for any
 * self-consistent format. These tests pin the bytes, the bindings, and every
 * rejection path instead.
 */

const KEK = Uint8Array.from({ length: 32 }, (_, index) => index);
const OTHER_KEK = Uint8Array.from({ length: 32 }, (_, index) => 0xff - index);
const DATA_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 32);

const V2_LENGTH = 81;
const V2_VERSION = 2;
const SALT_BYTES = 32;
const FIXED_WRAP_IV = new Uint8Array(12);
const KEY_DERIVATION_INFO = "nestm:aes-key-ring:a256gcm-hkdf-sha256-salt256:v2\0";
const KEY_REFERENCE_CONTEXT = "nestm:aes-key-ring:key-reference:v2\0";
const WRAPPING_CONTEXT = "nestm:aes-key-ring:wrapping-context:v2\0";
const WRAP_AUTHENTICATED_DATA = Buffer.concat([
	Buffer.from("nestm:aes-key-ring:wrapped-data-key:v2\0", "utf8"),
	Buffer.of(V2_VERSION),
]);
const V2_KAT_WRAPPED_HEX =
	"02404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5fdc406ffc3797bc020bd3296bd5a3e63c660e43247fc596d97cc1dd36573597f5e787f3a342b7b63378d751ff621cf48f";

function ring(keys: Readonly<Record<string, Uint8Array>> = { k1: KEK }, active = "k1") {
	return new AesKeyRingProvider({ activeKeyId: active, keys });
}

function context(value = "scope:a|domain:b|v1") {
	return { wrappingContext: utf8(value) };
}

function exported(key: KeyObject): string {
	return Buffer.from(key.export()).toString("hex");
}

function framedDigest(domain: string, value: Uint8Array): Buffer {
	const length = Buffer.alloc(8);
	length.writeBigUInt64BE(BigInt(value.byteLength));
	return createHash("sha256").update(domain, "utf8").update(length).update(value).digest();
}

function deriveWrappingKey(
	kek: Uint8Array,
	salt: Uint8Array,
	keyReference: string,
	wrappingContext: Uint8Array,
): Buffer {
	const info = Buffer.concat([
		Buffer.from(KEY_DERIVATION_INFO, "utf8"),
		Buffer.of(V2_VERSION),
		framedDigest(KEY_REFERENCE_CONTEXT, Buffer.from(keyReference, "utf8")),
		framedDigest(WRAPPING_CONTEXT, wrappingContext),
	]);
	return Buffer.from(hkdfSync("sha256", kek, salt, info, 32));
}

function frozenWrappedKey(
	hex: string,
	wrappingAlgorithm: string,
	keyReference = "k1",
): WrappedDataKey {
	return { wrappedKey: Buffer.from(hex, "hex"), keyReference, wrappingAlgorithm };
}

function corrupt(wrappedKey: Uint8Array, index: number): Uint8Array {
	const copy = new Uint8Array(wrappedKey);
	const byte = copy[index];
	if (byte === undefined) throw new Error(`The envelope has no byte at offset ${index}.`);
	copy[index] = byte ^ 0x01;
	return copy;
}

async function expectAuthenticationFailure(work: Promise<unknown>): Promise<void> {
	await expect(work).rejects.toSatisfy(
		(error: unknown) => isCryptoError(error) && error.code === "AUTHENTICATION_FAILED",
	);
}

describe("AesKeyRingProvider wrapper format", () => {
	it("writes an 81-byte salted envelope tagged version 2", async () => {
		const generated = await ring().generateDataKey(context());

		expect(generated.wrappingAlgorithm).toBe(AES_GCM_HKDF_SHA256_KEY_WRAP);
		expect(generated.keyReference).toBe("k1");
		expect(generated.wrappedKey.byteLength).toBe(V2_LENGTH);
		expect(generated.wrappedKey[0]).toBe(V2_VERSION);
		expect(generated.plaintextKey.symmetricKeySize).toBe(32);
	});

	it("round-trips the exact data key", async () => {
		const provider = ring();
		const generated = await provider.generateDataKey(context());
		const unwrapped = await provider.unwrapDataKey(generated, context());

		expect(exported(unwrapped)).toBe(exported(generated.plaintextKey));
	});

	it("emits a fresh 256-bit salt and distinct envelope per generated key", async () => {
		const provider = ring();
		const first = await provider.generateDataKey(context());
		const second = await provider.generateDataKey(context());

		expect(first.wrappedKey.subarray(1, 1 + SALT_BYTES)).not.toEqual(
			second.wrappedKey.subarray(1, 1 + SALT_BYTES),
		);
		expect(Buffer.from(first.wrappedKey).toString("hex")).not.toBe(
			Buffer.from(second.wrappedKey).toString("hex"),
		);
	});

	it("matches the frozen v2 unwrap known-answer vector", async () => {
		const wrapped = frozenWrappedKey(V2_KAT_WRAPPED_HEX, AES_GCM_HKDF_SHA256_KEY_WRAP);

		const unwrapped = await ring().unwrapDataKey(wrapped, context());

		expect(exported(unwrapped)).toBe(Buffer.from(DATA_KEY).toString("hex"));
	});

	it("writes the specified HKDF-SHA256 plus fixed-IV AES-256-GCM construction", async () => {
		const generated = await ring().generateDataKey(context());
		const salt = generated.wrappedKey.subarray(1, 1 + SALT_BYTES);
		const ciphertext = generated.wrappedKey.subarray(1 + SALT_BYTES, V2_LENGTH - 16);
		const tag = generated.wrappedKey.subarray(V2_LENGTH - 16);
		const wrappingKey = deriveWrappingKey(
			KEK,
			salt,
			generated.keyReference,
			context().wrappingContext,
		);
		const decipher = createDecipheriv("aes-256-gcm", wrappingKey, FIXED_WRAP_IV, {
			authTagLength: 16,
		});
		decipher.setAAD(WRAP_AUTHENTICATED_DATA, { plaintextLength: 32 });
		decipher.setAuthTag(tag);
		const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

		expect(plaintext.toString("hex")).toBe(exported(generated.plaintextKey));
	});
});

describe("AesKeyRingProvider wrapper bindings", () => {
	it("binds the envelope to its exact wrapping context", async () => {
		const provider = ring();
		const generated = await provider.generateDataKey(context("scope:a"));

		await expectAuthenticationFailure(provider.unwrapDataKey(generated, context("scope:b")));
		await expectAuthenticationFailure(provider.unwrapDataKey(generated, context("")));
	});

	it("rejects a context that only differs in length framing", async () => {
		const provider = ring();
		// The context digest is length-prefixed, so these two must not collide.
		const generated = await provider.generateDataKey(context("ab|c"));

		await expectAuthenticationFailure(provider.unwrapDataKey(generated, context("a|bc")));
	});

	it("binds the envelope to its exact key reference", async () => {
		const provider = ring({ k1: KEK, k2: OTHER_KEK });
		const generated = await provider.generateDataKey(context());

		await expectAuthenticationFailure(
			provider.unwrapDataKey({ ...generated, keyReference: "k2" }, context()),
		);
	});

	it("binds the key reference independently of the key bytes it selects", async () => {
		// Two identifiers, one key. Only the authenticated reference separates
		// them, so this fails if the reference stops being covered by the tag.
		const provider = ring({ k1: KEK, alias: KEK });
		const generated = await provider.generateDataKey(context());

		expect(generated.keyReference).toBe("k1");
		await expectAuthenticationFailure(
			provider.unwrapDataKey({ ...generated, keyReference: "alias" }, context()),
		);
	});

	it("does not unwrap under a different key ring", async () => {
		const generated = await ring().generateDataKey(context());

		await expectAuthenticationFailure(ring({ k1: OTHER_KEK }).unwrapDataKey(generated, context()));
	});

	it("reports an unregistered key reference distinctly from a forgery", async () => {
		const provider = ring();
		const generated = await provider.generateDataKey(context());

		await expect(
			provider.unwrapDataKey({ ...generated, keyReference: "absent" }, context()),
		).rejects.toSatisfy((error: unknown) => isCryptoError(error) && error.code === "KEY_NOT_FOUND");
	});

	it("rejects an unsupported wrapping algorithm", async () => {
		const provider = ring();
		const generated = await provider.generateDataKey(context());

		await expect(
			provider.unwrapDataKey({ ...generated, wrappingAlgorithm: "A128GCMKW" }, context()),
		).rejects.toSatisfy((error: unknown) => isCryptoError(error) && error.code === "INVALID_KEY");
	});
});

describe("AesKeyRingProvider wrapper tampering", () => {
	it("rejects a changed derivation salt", async () => {
		const provider = ring();
		const generated = await provider.generateDataKey(context());

		for (const index of [1, SALT_BYTES]) {
			await expectAuthenticationFailure(
				provider.unwrapDataKey(
					{ ...generated, wrappedKey: corrupt(generated.wrappedKey, index) },
					context(),
				),
			);
		}
	});

	it("rejects changed ciphertext or authentication tags", async () => {
		const provider = ring();
		const generated = await provider.generateDataKey(context());

		for (const index of [1 + SALT_BYTES, V2_LENGTH - 17, V2_LENGTH - 16, V2_LENGTH - 1]) {
			await expectAuthenticationFailure(
				provider.unwrapDataKey(
					{ ...generated, wrappedKey: corrupt(generated.wrappedKey, index) },
					context(),
				),
			);
		}
	});

	it("rejects a truncated, extended, or empty envelope", async () => {
		const provider = ring();
		const generated = await provider.generateDataKey(context());

		for (const wrappedKey of [
			generated.wrappedKey.subarray(0, V2_LENGTH - 1),
			new Uint8Array([...generated.wrappedKey, 0]),
			new Uint8Array(),
		]) {
			await expectAuthenticationFailure(
				provider.unwrapDataKey({ ...generated, wrappedKey }, context()),
			);
		}
	});

	it("rejects a version byte it did not write", async () => {
		const provider = ring();
		const generated = await provider.generateDataKey(context());

		for (const version of [0, 1, 3, 255]) {
			const wrappedKey = new Uint8Array(generated.wrappedKey);
			wrappedKey[0] = version;
			await expectAuthenticationFailure(
				provider.unwrapDataKey({ ...generated, wrappedKey }, context()),
			);
		}
	});
});

describe("AesKeyRingProvider cancellation", () => {
	it("honours an already-aborted signal before generating", async () => {
		const provider = ring();
		const controller = new AbortController();
		controller.abort();

		await expect(
			provider.generateDataKey({ wrappingContext: utf8("scope:a"), signal: controller.signal }),
		).rejects.toSatisfy(isCryptoError);
	});

	it("honours an already-aborted signal before unwrapping", async () => {
		const provider = ring();
		const generated = await provider.generateDataKey(context());
		const controller = new AbortController();
		controller.abort();

		await expect(
			provider.unwrapDataKey(generated, {
				wrappingContext: utf8("scope:a|domain:b|v1"),
				signal: controller.signal,
			}),
		).rejects.toSatisfy(isCryptoError);
	});
});

describe("AesKeyRingProvider key material hygiene", () => {
	it("accepts a KeyObject key ring and never returns the wrapping key", async () => {
		const provider = new AesKeyRingProvider({
			activeKeyId: "k1",
			keys: { k1: createSecretKey(Buffer.from(KEK)) },
		});
		const generated = await provider.generateDataKey(context());

		expect(exported(generated.plaintextKey)).not.toBe(Buffer.from(KEK).toString("hex"));
		expect(Buffer.from(generated.wrappedKey).toString("hex")).not.toContain(
			Buffer.from(KEK).toString("hex"),
		);
	});
});
