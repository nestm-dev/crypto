import { createSecretKey, generateKeyPairSync, randomBytes, type KeyObject } from "node:crypto";
import {
	generateX25519KeyPair,
	hkdfSha256,
	inspectSealed,
	openFrom,
	openKeyFrom,
	sealTo,
	SEAL_X25519_HKDF_SHA256_A256GCM,
	SEALED_OVERHEAD_BYTES,
	x25519PrivateKeyBytes,
	x25519PrivateKeyFromRaw,
	x25519PublicKeyBytes,
	x25519PublicKeyFromRaw,
} from "../../src/keys/index.js";

const hex = (value: Uint8Array): string => Buffer.from(value).toString("hex");

// First ciphertext byte of a sealed blob: 2-byte header + 32-byte ephemeral key.
const HEADER_OFFSET = 34;

describe("x25519 key conversion", () => {
	it("round-trips public and private keys through raw bytes", () => {
		const pair = generateX25519KeyPair();
		const publicRaw = x25519PublicKeyBytes(pair.publicKey);
		const privateRaw = x25519PrivateKeyBytes(pair.privateKey);

		expect(publicRaw.byteLength).toBe(32);
		expect(privateRaw.byteLength).toBe(32);
		expect(hex(x25519PublicKeyBytes(x25519PublicKeyFromRaw(publicRaw)))).toBe(hex(publicRaw));
		expect(hex(x25519PrivateKeyBytes(x25519PrivateKeyFromRaw(privateRaw)))).toBe(hex(privateRaw));
	});

	it("derives the public coordinate consistently from a private key", () => {
		const pair = generateX25519KeyPair();
		expect(hex(x25519PublicKeyBytes(pair.privateKey))).toBe(
			hex(x25519PublicKeyBytes(pair.publicKey)),
		);
	});

	it("rejects non-X25519 keys and malformed raw lengths", () => {
		const ed = generateKeyPairSync("ed25519");
		expect(() => x25519PublicKeyBytes(ed.publicKey)).toThrowError(/X25519/);
		expect(() => x25519PublicKeyFromRaw(new Uint8Array(31))).toThrowError(/32 bytes/);
		expect(() => x25519PrivateKeyFromRaw(new Uint8Array(33))).toThrowError(/32 bytes/);
	});
});

describe("sealTo / openFrom", () => {
	it("round-trips a byte payload for the intended recipient", () => {
		const pair = generateX25519KeyPair();
		const payload = randomBytes(32);
		const sealed = sealTo(pair.publicKey, payload);

		expect(sealed.byteLength).toBe(payload.byteLength + SEALED_OVERHEAD_BYTES);
		expect(hex(openFrom(pair.privateKey, sealed))).toBe(hex(payload));
	});

	it("round-trips through raw recipient keys", () => {
		const pair = generateX25519KeyPair();
		const payload = randomBytes(32);
		const sealed = sealTo(x25519PublicKeyBytes(pair.publicKey), payload);
		const opened = openFrom(x25519PrivateKeyBytes(pair.privateKey), sealed);
		expect(hex(opened)).toBe(hex(payload));
	});

	it("seals a secret KeyObject and opens it back into one", () => {
		const pair = generateX25519KeyPair();
		const secret = createSecretKey(randomBytes(32));
		const sealed = sealTo(pair.publicKey, secret);
		const opened: KeyObject = openKeyFrom(pair.privateKey, sealed);
		expect(opened.type).toBe("secret");
		expect(hex(opened.export())).toBe(hex(secret.export()));
	});

	it("binds info and aad — a mismatch fails authentication", () => {
		const pair = generateX25519KeyPair();
		const payload = randomBytes(32);
		const sealed = sealTo(pair.publicKey, payload, { info: "domain:v1", aad: "grant:42" });

		expect(hex(openFrom(pair.privateKey, sealed, { info: "domain:v1", aad: "grant:42" }))).toBe(
			hex(payload),
		);
		expect(() =>
			openFrom(pair.privateKey, sealed, { info: "domain:v2", aad: "grant:42" }),
		).toThrowError(/authentication failed/i);
		expect(() =>
			openFrom(pair.privateKey, sealed, { info: "domain:v1", aad: "grant:43" }),
		).toThrowError(/authentication failed/i);
		expect(() => openFrom(pair.privateKey, sealed)).toThrowError(/authentication failed/i);
	});

	it("cannot be opened by a different recipient", () => {
		const recipient = generateX25519KeyPair();
		const stranger = generateX25519KeyPair();
		const sealed = sealTo(recipient.publicKey, randomBytes(32));
		expect(() => openFrom(stranger.privateKey, sealed)).toThrowError(/authentication failed/i);
	});

	it("rejects a tampered ciphertext, tag, or ephemeral key", () => {
		const pair = generateX25519KeyPair();
		const sealed = sealTo(pair.publicKey, randomBytes(32));

		const flipCipher = Uint8Array.from(sealed);
		flipCipher[HEADER_OFFSET] = (flipCipher[HEADER_OFFSET] ?? 0) ^ 0x01;
		expect(() => openFrom(pair.privateKey, flipCipher)).toThrowError(/authentication failed/i);

		const flipTag = Uint8Array.from(sealed);
		const lastIndex = flipTag.byteLength - 1;
		flipTag[lastIndex] = (flipTag[lastIndex] ?? 0) ^ 0x01;
		expect(() => openFrom(pair.privateKey, flipTag)).toThrowError(/authentication failed/i);

		const zeroEphemeral = Uint8Array.from(sealed);
		zeroEphemeral.fill(0, 2, 34);
		expect(() => openFrom(pair.privateKey, zeroEphemeral)).toThrowError(/authentication failed/i);
	});

	it("rejects truncated, oversized, and mis-tagged blobs", () => {
		const pair = generateX25519KeyPair();
		expect(() => openFrom(pair.privateKey, new Uint8Array(SEALED_OVERHEAD_BYTES))).toThrowError(
			/truncated/i,
		);
		expect(() =>
			openFrom(pair.privateKey, new Uint8Array(64 * 1024 + SEALED_OVERHEAD_BYTES + 1)),
		).toThrowError(/too large/i);

		const sealed = sealTo(pair.publicKey, randomBytes(32));
		const badVersion = Uint8Array.from(sealed);
		badVersion[0] = 0x02;
		expect(() => openFrom(pair.privateKey, badVersion)).toThrowError(/version is unsupported/i);
		const badSuite = Uint8Array.from(sealed);
		badSuite[1] = 0x02;
		expect(() => openFrom(pair.privateKey, badSuite)).toThrowError(/suite is unsupported/i);
	});

	it("rejects an empty payload", () => {
		const pair = generateX25519KeyPair();
		expect(() => sealTo(pair.publicKey, new Uint8Array())).toThrowError(/non-empty/i);
	});

	it("exposes framing metadata without authenticating", () => {
		const pair = generateX25519KeyPair();
		const sealed = sealTo(pair.publicKey, randomBytes(32));
		const info = inspectSealed(sealed);
		expect(info).toMatchObject({
			version: 1,
			suite: SEAL_X25519_HKDF_SHA256_A256GCM,
			ciphertextBytes: 32,
			authenticated: false,
		});
		expect(info.ephemeralPublicKey.byteLength).toBe(32);
	});

	it("produces a fresh ephemeral key per seal", () => {
		const pair = generateX25519KeyPair();
		const a = sealTo(pair.publicKey, randomBytes(32));
		const b = sealTo(pair.publicKey, randomBytes(32));
		expect(hex(a.subarray(2, 34))).not.toBe(hex(b.subarray(2, 34)));
	});
});

describe("hkdfSha256 (RFC 5869 SHA-256 vectors)", () => {
	it("matches test case 1", () => {
		const okm = hkdfSha256(
			Buffer.from("0b".repeat(22), "hex"),
			Buffer.from("000102030405060708090a0b0c", "hex"),
			Buffer.from("f0f1f2f3f4f5f6f7f8f9", "hex"),
			42,
		);
		expect(hex(okm)).toBe(
			"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		);
	});

	it("matches test case 3 (empty salt and info)", () => {
		const okm = hkdfSha256(
			Buffer.from("0b".repeat(22), "hex"),
			new Uint8Array(),
			new Uint8Array(),
			42,
		);
		expect(hex(okm)).toBe(
			"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		);
	});

	it("rejects empty keying material and out-of-range lengths", () => {
		expect(() => hkdfSha256(new Uint8Array(), new Uint8Array(), new Uint8Array(), 42)).toThrowError(
			/non-empty/i,
		);
		expect(() =>
			hkdfSha256(new Uint8Array([1]), new Uint8Array(), new Uint8Array(), 0),
		).toThrowError(/out of range/i);
		expect(() =>
			hkdfSha256(new Uint8Array([1]), new Uint8Array(), new Uint8Array(), 255 * 32 + 1),
		).toThrowError(/out of range/i);
	});
});
