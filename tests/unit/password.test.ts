import {
	createPasswordKdf,
	decodePasswordKdfParams,
	deriveRecoveryKey,
	encodePasswordKdfParams,
	generatePasswordSalt,
	generateRecoveryCode,
	parseRecoveryCode,
	PASSWORD_KDF_SCRYPT_DEFAULT,
	RECOVERY_CODE_PREFIX,
	scryptPasswordKdf,
	type PasswordKdfAlgorithm,
	type PasswordKdfParams,
} from "../../src/password/index.js";

const hex = (value: Uint8Array): string => Buffer.from(value).toString("hex");

// Interactive scrypt defaults cost ~100ms each; tests use a cheap profile except where
// the default itself is under test.
const FAST: PasswordKdfParams = { id: "scrypt-1", params: { N: 1024, r: 8, p: 1 } };
const SALT = new Uint8Array(32).fill(7);

describe("createPasswordKdf", () => {
	it("derives a deterministic 32-byte key", async () => {
		const kdf = createPasswordKdf();
		const a = await kdf.derive({ password: "correct horse", salt: SALT, kdf: FAST });
		const b = await kdf.derive({ password: "correct horse", salt: SALT, kdf: FAST });

		expect(a.type).toBe("secret");
		expect(a.symmetricKeySize).toBe(32);
		expect(hex(a.export())).toBe(hex(b.export()));
	});

	it("separates by password, salt, params, and info", async () => {
		const kdf = createPasswordKdf();
		const base = await kdf.derive({ password: "pw", salt: SALT, kdf: FAST });
		const variants = await Promise.all([
			kdf.derive({ password: "pw2", salt: SALT, kdf: FAST }),
			kdf.derive({ password: "pw", salt: new Uint8Array(32).fill(8), kdf: FAST }),
			kdf.derive({
				password: "pw",
				salt: SALT,
				kdf: { id: "scrypt-1", params: { N: 2048, r: 8, p: 1 } },
			}),
			kdf.derive({ password: "pw", salt: SALT, kdf: FAST, info: "umk.password" }),
		]);
		for (const variant of variants) {
			expect(hex(variant.export())).not.toBe(hex(base.export()));
		}
	});

	it("accepts byte passwords equivalently to text", async () => {
		const kdf = createPasswordKdf();
		const fromText = await kdf.derive({ password: "héllo", salt: SALT, kdf: FAST });
		const fromBytes = await kdf.derive({
			password: new TextEncoder().encode("héllo"),
			salt: SALT,
			kdf: FAST,
		});
		expect(hex(fromBytes.export())).toBe(hex(fromText.export()));
	});

	it("uses the interactive scrypt profile by default", async () => {
		const kdf = createPasswordKdf();
		expect(kdf.defaultParams).toEqual(PASSWORD_KDF_SCRYPT_DEFAULT);
		expect(kdf.supports("scrypt-1")).toBe(true);
		expect(kdf.supports("argon2id")).toBe(false);

		const key = await kdf.derive({
			password: "pw",
			salt: SALT,
			kdf: PASSWORD_KDF_SCRYPT_DEFAULT,
		});
		expect(key.symmetricKeySize).toBe(32);
	});

	it("rejects invalid salts, passwords, and unknown algorithms", async () => {
		const kdf = createPasswordKdf();
		await expect(
			kdf.derive({ password: "pw", salt: new Uint8Array(8), kdf: FAST }),
		).rejects.toThrowError(/salt length is out of range/i);
		await expect(kdf.derive({ password: "", salt: SALT, kdf: FAST })).rejects.toThrowError(
			/non-empty/i,
		);
		await expect(
			kdf.derive({ password: "pw", salt: SALT, kdf: { id: "argon2id", params: {} } }),
		).rejects.toThrowError(/not registered/i);
	});

	it("validates scrypt parameters", async () => {
		const kdf = createPasswordKdf();
		const bad: readonly unknown[] = [
			{ N: 1000, r: 8, p: 1 },
			{ N: 512, r: 8, p: 1 },
			{ N: 1024, r: 0, p: 1 },
			{ N: 1024, r: 8, p: 0 },
			{ N: 1024, r: 8 },
			{ N: 1024, r: 8, p: 1, extra: 1 },
		];
		for (const params of bad) {
			await expect(
				kdf.derive({ password: "pw", salt: SALT, kdf: { id: "scrypt-1", params } }),
			).rejects.toThrowError(/scrypt|invalid/i);
		}
	});

	it("rejects invalid registries and concurrency limits", () => {
		expect(() => createPasswordKdf({ algorithms: [] })).toThrowError(/registry is required/i);
		expect(() =>
			createPasswordKdf({ algorithms: [scryptPasswordKdf(), scryptPasswordKdf()] }),
		).toThrowError(/registration is invalid/i);
		expect(() => createPasswordKdf({ maxConcurrency: 0 })).toThrowError(/concurrency limit/i);
		expect(() => createPasswordKdf({ defaultParams: { id: "nope", params: {} } })).toThrowError(
			/not registered/i,
		);
		expect(() =>
			createPasswordKdf({ defaultParams: { id: "scrypt-1", params: { N: 3, r: 8, p: 1 } } }),
		).toThrowError(/default password KDF parameters are invalid/i);
	});

	it("bounds concurrent derivations", async () => {
		let active = 0;
		let peak = 0;
		const slow: PasswordKdfAlgorithm = {
			id: "slow",
			validateParams: () => undefined,
			async derive() {
				active += 1;
				peak = Math.max(peak, active);
				await new Promise((resolve) => setTimeout(resolve, 15));
				active -= 1;
				return new Uint8Array(32).fill(1);
			},
		};
		const kdf = createPasswordKdf({
			algorithms: [slow],
			defaultParams: { id: "slow", params: {} },
			maxConcurrency: 2,
		});
		await Promise.all(
			Array.from({ length: 8 }, () =>
				kdf.derive({ password: "pw", salt: SALT, kdf: { id: "slow", params: {} } }),
			),
		);
		expect(peak).toBe(2);
	});

	it("honours an abort signal", async () => {
		const kdf = createPasswordKdf();
		const controller = new AbortController();
		controller.abort();
		await expect(
			kdf.derive({ password: "pw", salt: SALT, kdf: FAST, signal: controller.signal }),
		).rejects.toThrowError(/aborted/i);
	});

	it("rejects key material of the wrong length from a custom algorithm", async () => {
		const broken: PasswordKdfAlgorithm = {
			id: "broken",
			validateParams: () => undefined,
			async derive() {
				return new Uint8Array(16);
			},
		};
		const kdf = createPasswordKdf({
			algorithms: [broken],
			defaultParams: { id: "broken", params: {} },
		});
		await expect(
			kdf.derive({ password: "pw", salt: SALT, kdf: { id: "broken", params: {} } }),
		).rejects.toThrowError(/invalid key material/i);
	});
});

describe("password KDF parameter codec", () => {
	it("round-trips canonically", () => {
		const encoded = encodePasswordKdfParams(PASSWORD_KDF_SCRYPT_DEFAULT);
		expect(encoded).toBe('{"id":"scrypt-1","params":{"N":65536,"p":1,"r":8}}');
		expect(decodePasswordKdfParams(encoded)).toEqual(PASSWORD_KDF_SCRYPT_DEFAULT);
	});

	it("sorts keys so the encoding is stable", () => {
		expect(encodePasswordKdfParams({ id: "scrypt-1", params: { r: 8, p: 1, N: 1024 } })).toBe(
			'{"id":"scrypt-1","params":{"N":1024,"p":1,"r":8}}',
		);
	});

	it("rejects non-canonical and malformed encodings", () => {
		expect(() =>
			decodePasswordKdfParams('{"params":{"N":1024,"p":1,"r":8},"id":"scrypt-1"}'),
		).toThrowError(/not canonical/i);
		expect(() =>
			decodePasswordKdfParams('{"id":"scrypt-1","params":{"r":8,"p":1,"N":1024}}'),
		).toThrowError(/not canonical/i);
		expect(() => decodePasswordKdfParams("{")).toThrowError(/malformed/i);
		expect(() => decodePasswordKdfParams('{"id":"scrypt-1"}')).toThrowError(/invalid shape/i);
		expect(() => decodePasswordKdfParams('{"id":"","params":{}}')).toThrowError(/identifier/i);
		expect(() => decodePasswordKdfParams('{"id":"x","params":1}')).toThrowError(/invalid/i);
		expect(() => decodePasswordKdfParams("")).toThrowError(/invalid/i);
	});
});

describe("generatePasswordSalt", () => {
	it("returns fresh salts of the requested size", () => {
		expect(generatePasswordSalt().byteLength).toBe(32);
		expect(generatePasswordSalt(16).byteLength).toBe(16);
		expect(hex(generatePasswordSalt())).not.toBe(hex(generatePasswordSalt()));
	});

	it("rejects lengths below the minimum", () => {
		expect(() => generatePasswordSalt(15)).toThrowError(/out of range/i);
		expect(() => generatePasswordSalt(2048)).toThrowError(/out of range/i);
	});
});

describe("recovery codes", () => {
	it("generates a grouped, prefixed code and parses it back", () => {
		const { code, secret } = generateRecoveryCode();
		expect(secret.byteLength).toBe(16);
		expect(code.startsWith(`${RECOVERY_CODE_PREFIX}-`)).toBe(true);
		// 16 secret bytes + a 4-byte checksum encode to exactly four 8-character groups.
		expect(code).toMatch(/^ASR1(?:-[0-9A-HJKMNP-TV-Z]{8}){4}$/u);
		expect(hex(parseRecoveryCode(code))).toBe(hex(secret));
	});

	it("supports 160-bit codes", () => {
		const { code, secret } = generateRecoveryCode({ entropyBits: 160 });
		expect(secret.byteLength).toBe(20);
		// 20 secret bytes + a 5-byte checksum encode to exactly five groups.
		expect(code).toMatch(/^ASR1(?:-[0-9A-HJKMNP-TV-Z]{8}){5}$/u);
		expect(hex(parseRecoveryCode(code))).toBe(hex(secret));
	});

	it("accepts lowercase, spacing, and Crockford aliases", () => {
		const { code, secret } = generateRecoveryCode();
		const mangled = code.toLowerCase().replace(/-/gu, " ");
		expect(hex(parseRecoveryCode(mangled))).toBe(hex(secret));

		// O/I/L are aliases of 0/1/1 and never appear in the alphabet, so substituting them
		// into a valid code must still parse to the same secret.
		const aliased = code.replace(/0/gu, "O").replace(/1/gu, "I");
		expect(hex(parseRecoveryCode(aliased))).toBe(hex(secret));
	});

	it("rejects every single-character corruption via the checksum", () => {
		const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
		let attempted = 0;
		// The checksum is 32 bits wide, so a mistyped character is caught with probability
		// 1 - 2^-32: asserting "every corruption is rejected" is the honest bar here, and a
		// weakened checksum would fail this immediately rather than hide behind a ratio.
		for (let trial = 0; trial < 8; trial += 1) {
			const { code } = generateRecoveryCode();
			for (let index = RECOVERY_CODE_PREFIX.length + 1; index < code.length; index += 1) {
				if (code[index] === "-") continue;
				for (const replacement of ALPHABET) {
					if (replacement === code[index]) continue;
					const tampered = `${code.slice(0, index)}${replacement}${code.slice(index + 1)}`;
					attempted += 1;
					expect(() => parseRecoveryCode(tampered)).toThrowError(/checksum|canonical/i);
				}
			}
		}
		expect(attempted).toBeGreaterThan(7000);
	});

	it("rejects a truncated or lengthened code", () => {
		const { code } = generateRecoveryCode();
		expect(() => parseRecoveryCode(code.slice(0, -1))).toThrowError(/length/i);
		expect(() => parseRecoveryCode(`${code}A`)).toThrowError(/length/i);
	});

	it("rejects malformed codes fail-closed", () => {
		expect(() => parseRecoveryCode("")).toThrowError(/invalid/i);
		expect(() => parseRecoveryCode("NOPE-ABCDE")).toThrowError(/prefix/i);
		expect(() => parseRecoveryCode("ASR1-ABC")).toThrowError(/length/i);
		expect(() => parseRecoveryCode(`ASR1-${"U".repeat(32)}`)).toThrowError(/invalid characters/i);
		expect(() => parseRecoveryCode(`ASR1-${"A".repeat(32)}`)).toThrowError(/checksum|canonical/i);
		expect(() => generateRecoveryCode({ entropyBits: 64 as 128 })).toThrowError(/entropy/i);
	});

	it("derives a stable 32-byte key bound to salt and info", () => {
		const { secret } = generateRecoveryCode();
		const salt = generatePasswordSalt();
		const key = deriveRecoveryKey(secret, salt);

		expect(key.symmetricKeySize).toBe(32);
		expect(hex(deriveRecoveryKey(secret, salt).export())).toBe(hex(key.export()));
		expect(hex(deriveRecoveryKey(secret, generatePasswordSalt()).export())).not.toBe(
			hex(key.export()),
		);
		expect(hex(deriveRecoveryKey(secret, salt, "umk.recovery").export())).not.toBe(
			hex(key.export()),
		);
	});

	it("rejects weak recovery secrets and salts", () => {
		expect(() => deriveRecoveryKey(new Uint8Array(8), SALT)).toThrowError(/secret is invalid/i);
		expect(() => deriveRecoveryKey(new Uint8Array(16), new Uint8Array(8))).toThrowError(
			/salt length is out of range/i,
		);
	});
});

describe("password KDF hardening regressions", () => {
	it("rejects parameters that would reserve gigabytes per derivation", async () => {
		const kdf = createPasswordKdf();
		// Each of these is inside the individual ranges but far outside a sane footprint;
		// 128 * N * r is what actually has to be bounded.
		for (const params of [
			{ N: 2 ** 21, r: 8, p: 1 },
			{ N: 2 ** 20, r: 32, p: 1 },
			{ N: 2 ** 22, r: 32, p: 16 },
		]) {
			await expect(
				kdf.derive({ password: "pw", salt: SALT, kdf: { id: "scrypt-1", params } }),
			).rejects.toThrowError(/out of range|too much memory/i);
		}
		// The largest still-accepted footprint sits exactly on the 1 GiB ceiling.
		expect(() => scryptPasswordKdf().validateParams({ N: 2 ** 20, r: 8, p: 1 })).not.toThrow();
	});

	it("frees the concurrency slot and rejects when a queued derivation is aborted", async () => {
		const kdf = createPasswordKdf({ maxConcurrency: 1 });
		const controller = new AbortController();
		const running = kdf.derive({
			password: "first",
			salt: SALT,
			kdf: PASSWORD_KDF_SCRYPT_DEFAULT,
		});
		const queued = kdf.derive({
			password: "second",
			salt: SALT,
			kdf: PASSWORD_KDF_SCRYPT_DEFAULT,
			signal: controller.signal,
		});
		controller.abort();

		await expect(queued).rejects.toThrowError(/aborted/i);
		expect((await running).symmetricKeySize).toBe(32);
		// The slot the aborted waiter never took must still be usable.
		const after = await kdf.derive({
			password: "third",
			salt: SALT,
			kdf: PASSWORD_KDF_SCRYPT_DEFAULT,
		});
		expect(after.symmetricKeySize).toBe(32);
	});

	it("wipes the password copy even when the derivation fails", async () => {
		const captured: Uint8Array[] = [];
		const failing = createPasswordKdf({
			algorithms: [
				{
					id: "capture",
					validateParams(): void {},
					async derive(input): Promise<Uint8Array> {
						captured.push(input.password);
						await Promise.resolve();
						throw new Error("derivation exploded");
					},
				},
			],
			defaultParams: { id: "capture", params: {} },
		});

		await expect(
			failing.derive({ password: "hunter2", salt: SALT, kdf: { id: "capture", params: {} } }),
		).rejects.toThrow();
		expect(captured).toHaveLength(1);
		// The UTF-8 copy the library made must not outlive the call with plaintext in it.
		expect(captured[0]!.every((byte) => byte === 0)).toBe(true);
	});
});
