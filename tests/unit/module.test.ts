import { Injectable, Module } from "@nestjs/common";
import { Test, type TestingModule } from "@nestjs/testing";
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { CipherService } from "../../src/cipher.service.js";
import { AesKeyRingProvider } from "../../src/core/index.js";
import { CryptoModule } from "../../src/crypto.module.js";
import { FieldCipherService } from "../../src/fields/index.js";

const CRYPTO_OPTIONS = Symbol("TEST_CRYPTO_OPTIONS");

function options(key = new Uint8Array(randomBytes(32))) {
	return {
		providers: [
			{
				name: "local",
				provider: new AesKeyRingProvider({ activeKeyId: "k1", keys: { k1: key } }),
			},
		],
		defaultProvider: "local",
	} as const;
}

@Module({
	providers: [{ provide: CRYPTO_OPTIONS, useValue: options() }],
	exports: [CRYPTO_OPTIONS],
})
class ConfigurationModule {}

@Injectable()
class SiblingCipherConsumer {
	constructor(readonly cipher: CipherService) {}
}

@Module({ providers: [SiblingCipherConsumer], exports: [SiblingCipherConsumer] })
class SiblingConsumerModule {}

describe("CryptoModule", () => {
	const modules: TestingModule[] = [];

	afterEach(async () => {
		await Promise.all(modules.splice(0).map(async (module) => module.close()));
	});

	it("resolves the cipher and field services through forRoot", async () => {
		const module = await Test.createTestingModule({
			imports: [CryptoModule.forRoot(options())],
		}).compile();
		modules.push(module);
		const cipher = module.get(CipherService);
		expect(module.get(FieldCipherService)).toBeInstanceOf(FieldCipherService);
		const envelope = await cipher.encryptText("hello");
		await expect(cipher.decryptText(envelope)).resolves.toBe("hello");
	});

	it("supports async factory injection", async () => {
		const module = await Test.createTestingModule({
			imports: [
				CryptoModule.forRootAsync({
					imports: [ConfigurationModule],
					inject: [CRYPTO_OPTIONS],
					useFactory: (value: ReturnType<typeof options>) => value,
				}),
			],
		}).compile();
		modules.push(module);
		expect(module.get(CipherService)).toBeInstanceOf(CipherService);
	});

	it("fails during module compilation for invalid configuration", async () => {
		await expect(
			Test.createTestingModule({
				imports: [
					CryptoModule.forRoot({
						providers: [],
						defaultProvider: "missing",
					}),
				],
			}).compile(),
		).rejects.toMatchObject({ code: "CONFIGURATION" });
	});

	it("keeps independent application contexts isolated", async () => {
		const first = await Test.createTestingModule({
			imports: [CryptoModule.forRoot(options())],
		}).compile();
		const second = await Test.createTestingModule({
			imports: [CryptoModule.forRoot(options())],
		}).compile();
		modules.push(first, second);
		const envelope = await first.get(CipherService).encryptText("isolated");
		await expect(second.get(CipherService).decryptText(envelope)).rejects.toMatchObject({
			code: "AUTHENTICATION_FAILED",
		});
	});

	it("is local by default and global only when requested", () => {
		expect(CryptoModule.forRoot(options()).global).toBe(false);
		expect(CryptoModule.forRoot({ ...options(), isGlobal: true }).global).toBe(true);
	});

	it("only exposes providers to sibling modules when explicitly global", async () => {
		await expect(
			Test.createTestingModule({
				imports: [CryptoModule.forRoot(options()), SiblingConsumerModule],
			}).compile(),
		).rejects.toThrow();

		const module = await Test.createTestingModule({
			imports: [CryptoModule.forRoot({ ...options(), isGlobal: true }), SiblingConsumerModule],
		}).compile();
		modules.push(module);
		expect(module.get(SiblingCipherConsumer).cipher).toBeInstanceOf(CipherService);
	});
});
