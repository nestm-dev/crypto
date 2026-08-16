import { createSecretKey, randomBytes } from "node:crypto";
import {
	decodeKeyWrapRecord,
	decodeKeyWrapRecords,
	encodeKeyWrapRecord,
	encodeKeyWrapRecords,
	generateX25519KeyPair,
	hmacSha256,
	keyWrapRecordLength,
	selectKeyWrapRecord,
	timingSafeEqualBytes,
	unwrapKeyFromRecipient,
	unwrapKeyWithSecret,
	wrapKeyToRecipient,
	wrapKeyWithSecret,
	KEY_WRAP_A256GCMKW,
	KEY_WRAP_SEAL_X25519,
	type KeyWrapRecord,
} from "../../src/keys/index.js";
import { decodeKeyWrapRecordSequence } from "../../src/keys/key-wrap-record.js";

const hex = (value: Uint8Array): string => Buffer.from(value).toString("hex");

describe("wrapKeyWithSecret / unwrapKeyWithSecret", () => {
	it("round-trips a secret key under a shared KEK", () => {
		const kek = randomBytes(32);
		const key = createSecretKey(randomBytes(32));
		const record = wrapKeyWithSecret(kek, key, { recipientId: "user:42" });

		expect(record).toMatchObject({
			version: 1,
			algorithm: KEY_WRAP_A256GCMKW,
			recipientType: "secret",
			recipientId: "user:42",
		});
		// version + nonce(12) + ciphertext(32) + tag(16)
		expect(record.wrapped.byteLength).toBe(61);
		expect(hex(unwrapKeyWithSecret(kek, record).export())).toBe(hex(key.export()));
	});

	it("binds caller aad", () => {
		const kek = randomBytes(32);
		const key = createSecretKey(randomBytes(32));
		const record = wrapKeyWithSecret(kek, key, { recipientId: "user:42", aad: "epoch:1" });

		expect(hex(unwrapKeyWithSecret(kek, record, { aad: "epoch:1" }).export())).toBe(
			hex(key.export()),
		);
		expect(() => unwrapKeyWithSecret(kek, record, { aad: "epoch:2" })).toThrowError(
			/authentication failed/i,
		);
		expect(() => unwrapKeyWithSecret(kek, record)).toThrowError(/authentication failed/i);
	});

	it("refuses a record retargeted at another recipient", () => {
		const kek = randomBytes(32);
		const record = wrapKeyWithSecret(kek, createSecretKey(randomBytes(32)), {
			recipientId: "user:42",
		});
		const swapped: KeyWrapRecord = { ...record, recipientId: "user:43" };
		expect(() => unwrapKeyWithSecret(kek, swapped)).toThrowError(/authentication failed/i);
	});

	it("cannot be unwrapped by a different KEK", () => {
		const record = wrapKeyWithSecret(randomBytes(32), createSecretKey(randomBytes(32)), {
			recipientId: "user:42",
		});
		expect(() => unwrapKeyWithSecret(randomBytes(32), record)).toThrowError(
			/authentication failed/i,
		);
	});

	it("rejects invalid KEKs, keys, and recipient identifiers", () => {
		const key = createSecretKey(randomBytes(32));
		expect(() => wrapKeyWithSecret(randomBytes(16), key, { recipientId: "a" })).toThrowError(
			/32 bytes/i,
		);
		expect(() =>
			wrapKeyWithSecret(randomBytes(32), new Uint8Array(8), { recipientId: "a" }),
		).toThrowError(/out of range/i);
		expect(() => wrapKeyWithSecret(randomBytes(32), key, { recipientId: " a" })).toThrowError(
			/recipient identifier is invalid/i,
		);
		expect(() =>
			wrapKeyWithSecret(randomBytes(32), key, { recipientId: "a".repeat(256) }),
		).toThrowError(/too long/i);
	});
});

describe("wrapKeyToRecipient / unwrapKeyFromRecipient", () => {
	it("round-trips a data key sealed to a public key", () => {
		const pair = generateX25519KeyPair();
		const dek = createSecretKey(randomBytes(32));
		const record = wrapKeyToRecipient(pair.publicKey, dek, { recipientId: "ws:7" });

		expect(record).toMatchObject({
			version: 1,
			algorithm: KEY_WRAP_SEAL_X25519,
			recipientType: "x25519",
			recipientId: "ws:7",
		});
		expect(hex(unwrapKeyFromRecipient(pair.privateKey, record).export())).toBe(hex(dek.export()));
	});

	it("binds info, aad, and the recipient identifier", () => {
		const pair = generateX25519KeyPair();
		const dek = createSecretKey(randomBytes(32));
		const record = wrapKeyToRecipient(pair.publicKey, dek, {
			recipientId: "ws:7",
			info: "wsk.seal",
			aad: "epoch:3",
		});

		expect(
			hex(
				unwrapKeyFromRecipient(pair.privateKey, record, {
					info: "wsk.seal",
					aad: "epoch:3",
				}).export(),
			),
		).toBe(hex(dek.export()));
		expect(() =>
			unwrapKeyFromRecipient(pair.privateKey, record, { info: "other", aad: "epoch:3" }),
		).toThrowError(/authentication failed/i);
		expect(() =>
			unwrapKeyFromRecipient(pair.privateKey, record, { info: "wsk.seal", aad: "epoch:4" }),
		).toThrowError(/authentication failed/i);

		const swapped: KeyWrapRecord = { ...record, recipientId: "ws:8" };
		expect(() =>
			unwrapKeyFromRecipient(pair.privateKey, swapped, { info: "wsk.seal", aad: "epoch:3" }),
		).toThrowError(/authentication failed/i);
	});

	it("cannot be opened by another recipient", () => {
		const recipient = generateX25519KeyPair();
		const stranger = generateX25519KeyPair();
		const record = wrapKeyToRecipient(recipient.publicKey, createSecretKey(randomBytes(32)), {
			recipientId: "ws:7",
		});
		expect(() => unwrapKeyFromRecipient(stranger.privateKey, record)).toThrowError(
			/authentication failed/i,
		);
	});

	it("refuses to cross record flavours", () => {
		const pair = generateX25519KeyPair();
		const sealed = wrapKeyToRecipient(pair.publicKey, createSecretKey(randomBytes(32)), {
			recipientId: "ws:7",
		});
		const secret = wrapKeyWithSecret(randomBytes(32), createSecretKey(randomBytes(32)), {
			recipientId: "user:1",
		});
		expect(() => unwrapKeyWithSecret(randomBytes(32), sealed)).toThrowError(
			/not a secret-KEK record/i,
		);
		expect(() => unwrapKeyFromRecipient(pair.privateKey, secret)).toThrowError(
			/not a recipient record/i,
		);
	});
});

describe("key-wrap record encoding", () => {
	it("round-trips a single record of each type", () => {
		const pair = generateX25519KeyPair();
		const records = [
			wrapKeyWithSecret(randomBytes(32), createSecretKey(randomBytes(32)), {
				recipientId: "user:1",
			}),
			wrapKeyToRecipient(pair.publicKey, createSecretKey(randomBytes(32)), {
				recipientId: "ws:2",
			}),
		];
		for (const record of records) {
			const encoded = encodeKeyWrapRecord(record);
			expect(encoded.byteLength).toBe(keyWrapRecordLength(record));
			const decoded = decodeKeyWrapRecord(encoded);
			expect(decoded.algorithm).toBe(record.algorithm);
			expect(decoded.recipientType).toBe(record.recipientType);
			expect(decoded.recipientId).toBe(record.recipientId);
			expect(hex(decoded.wrapped)).toBe(hex(record.wrapped));
		}
	});

	it("round-trips a record list and preserves order", () => {
		const kek = randomBytes(32);
		const records = ["user:1", "user:2", "user:3"].map((recipientId) =>
			wrapKeyWithSecret(kek, createSecretKey(randomBytes(32)), { recipientId }),
		);
		const decoded = decodeKeyWrapRecords(encodeKeyWrapRecords(records));
		expect(decoded.map((record) => record.recipientId)).toEqual(["user:1", "user:2", "user:3"]);
	});

	it("round-trips an empty list", () => {
		expect(decodeKeyWrapRecords(encodeKeyWrapRecords([]))).toHaveLength(0);
	});

	it("rejects truncated, trailing, and over-count encodings", () => {
		const kek = randomBytes(32);
		const record = wrapKeyWithSecret(kek, createSecretKey(randomBytes(32)), {
			recipientId: "user:1",
		});
		const encoded = encodeKeyWrapRecord(record);

		expect(() => decodeKeyWrapRecord(encoded.subarray(0, encoded.byteLength - 1))).toThrowError(
			/truncated/i,
		);
		const trailing = new Uint8Array(encoded.byteLength + 1);
		trailing.set(encoded, 0);
		expect(() => decodeKeyWrapRecord(trailing)).toThrowError(/trailing bytes/i);

		const list = encodeKeyWrapRecords([record, record]);
		expect(() => decodeKeyWrapRecords(list, 1)).toThrowError(/too many/i);
		expect(() => decodeKeyWrapRecords(new Uint8Array(1))).toThrowError(/truncated/i);
	});

	it("rejects unknown versions and recipient types", () => {
		const record = wrapKeyWithSecret(randomBytes(32), createSecretKey(randomBytes(32)), {
			recipientId: "user:1",
		});
		const encoded = encodeKeyWrapRecord(record);

		const badVersion = Uint8Array.from(encoded);
		badVersion[0] = 0x02;
		expect(() => decodeKeyWrapRecord(badVersion)).toThrowError(/version is unsupported/i);

		const badType = Uint8Array.from(encoded);
		badType[1] = 0x09;
		expect(() => decodeKeyWrapRecord(badType)).toThrowError(/recipient type is unknown/i);
	});

	it("selects records by recipient", () => {
		const kek = randomBytes(32);
		const records = ["user:1", "user:2"].map((recipientId) =>
			wrapKeyWithSecret(kek, createSecretKey(randomBytes(32)), { recipientId }),
		);
		expect(
			selectKeyWrapRecord(records, { recipientType: "secret", recipientId: "user:2" })?.recipientId,
		).toBe("user:2");
		expect(
			selectKeyWrapRecord(records, { recipientType: "x25519", recipientId: "user:2" }),
		).toBeUndefined();
		expect(
			selectKeyWrapRecord(records, { recipientType: "secret", recipientId: "user:9" }),
		).toBeUndefined();
	});
});

describe("hmacSha256 / timingSafeEqualBytes", () => {
	it("matches RFC 4231 test case 1", () => {
		const mac = hmacSha256(Buffer.from("0b".repeat(20), "hex"), Buffer.from("Hi There"));
		expect(hex(mac)).toBe("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
	});

	it("concatenates parts without separation", () => {
		const key = randomBytes(32);
		expect(hex(hmacSha256(key, Buffer.from("ab"), Buffer.from("c")))).toBe(
			hex(hmacSha256(key, Buffer.from("abc"))),
		);
	});

	it("compares equal and unequal lengths without throwing", () => {
		expect(timingSafeEqualBytes(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 3))).toBe(true);
		expect(timingSafeEqualBytes(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 4))).toBe(false);
		expect(timingSafeEqualBytes(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2))).toBe(false);
		expect(timingSafeEqualBytes(new Uint8Array(), new Uint8Array())).toBe(true);
	});
});

describe("key-wrap record hardening regressions", () => {
	it("refuses to mint a record with no recipient binding", () => {
		const kek = randomBytes(32);
		const dek = randomBytes(32);
		const { publicKey } = generateX25519KeyPair();
		// An empty identifier binds nothing, so the wrap would be replayable to anyone.
		expect(() => wrapKeyWithSecret(kek, dek, { recipientId: "" })).toThrowError(
			/recipient identifier is invalid/i,
		);
		expect(() => wrapKeyToRecipient(publicKey, dek, { recipientId: "" })).toThrowError(
			/recipient identifier is invalid/i,
		);
		// Omitting it entirely must throw rather than silently default.
		expect(() =>
			wrapKeyWithSecret(kek, dek, undefined as unknown as { recipientId: string }),
		).toThrowError(/options are required|recipient identifier is invalid/i);
		expect(() =>
			wrapKeyWithSecret(kek, dek, {} as unknown as { recipientId: string }),
		).toThrowError(/recipient identifier is invalid/i);
	});

	it("caps the header record-sequence count before decoding, matching the encoder limit", () => {
		// The nmcs1 header path decodes a caller-declared record count; without a cap a
		// hostile wrapCount could drive an unbounded decode loop. The encoder rejects >64,
		// so the sequence decoder must too — before it reads any record bytes.
		expect(() => decodeKeyWrapRecordSequence(new Uint8Array(0), 0, 65)).toThrowError(
			/too many key-wrap records/i,
		);
	});

	it("rejects a recipient identifier that would not survive encoding", () => {
		const kek = randomBytes(32);
		// A lone surrogate is folded onto U+FFFD by UTF-8, which would collapse distinct
		// recipients onto one identifier and break the wire round trip.
		expect(() =>
			wrapKeyWithSecret(kek, randomBytes(32), { recipientId: "user:\uD800" }),
		).toThrowError(/recipient identifier is invalid/i);
	});

	it("length-checks a key recovered from an attacker-minted record", () => {
		const { publicKey, privateKey } = generateX25519KeyPair();
		const wrapped = wrapKeyToRecipient(publicKey, randomBytes(32), { recipientId: "user:1" });
		expect(unwrapKeyFromRecipient(privateKey, wrapped).symmetricKeySize).toBe(32);
		// Pinning the expected size rejects a record that carries a different-sized key.
		expect(() =>
			unwrapKeyFromRecipient(privateKey, wrapped, { expectedKeyBytes: 16 }),
		).toThrowError(/not the expected length/i);

		const secretWrap = wrapKeyWithSecret(randomBytes(32), randomBytes(16), {
			recipientId: "user:1",
		});
		expect(() =>
			unwrapKeyWithSecret(randomBytes(32), secretWrap, { expectedKeyBytes: 32 }),
		).toThrowError(/authentication failed/i);
	});

	it("reports hostile wire bytes as malformed rather than as a cipher failure", () => {
		const record = wrapKeyWithSecret(randomBytes(32), randomBytes(32), { recipientId: "user:1" });
		const encoded = encodeKeyWrapRecord(record);

		const badText = Uint8Array.from(encoded);
		badText[6] = 0x80; // first algorithm byte: a bare UTF-8 continuation byte
		expect(() => decodeKeyWrapRecord(badText)).toThrowError(/malformed/i);

		const noRecipient = Uint8Array.from(encoded);
		noRecipient[3] = 0; // recipientIdLength
		expect(() => decodeKeyWrapRecord(noRecipient)).toThrowError(/malformed|missing/i);
	});

	it("never encodes a list its own decoder would refuse", () => {
		const kek = randomBytes(32);
		const record = wrapKeyWithSecret(kek, randomBytes(32), { recipientId: "user:1" });
		const tooMany = Array.from({ length: 65 }, () => record);
		expect(() => encodeKeyWrapRecords(tooMany)).toThrowError(/too many/i);

		const atLimit = Array.from({ length: 64 }, () => record);
		expect(decodeKeyWrapRecords(encodeKeyWrapRecords(atLimit))).toHaveLength(64);
	});

	it("rejects a non-secret KeyObject as an HMAC key", () => {
		const { publicKey } = generateX25519KeyPair();
		expect(() => hmacSha256(publicKey, Buffer.from("x"))).toThrowError(/must be a secret key/i);
		expect(() => hmacSha256(undefined as unknown as Uint8Array, Buffer.from("x"))).toThrowError(
			/must be bytes or a secret key/i,
		);
	});
});
