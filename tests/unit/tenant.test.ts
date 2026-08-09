import { Module } from "@nestjs/common";
import { Test, type TestingModule } from "@nestjs/testing";
import {
	TENANT_CONTEXT_READER,
	type TenantContextReader,
	type TenantTarget,
} from "@nestm/tenant/context";
import { InMemoryTenantRegistryStore, TenantModule, TenantService } from "@nestm/tenant";
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CipherService } from "../../src/cipher.service.js";
import {
	AesKeyRingProvider,
	CipherEngine,
	CryptoError,
	type DataKeyContext,
	type DataKeyProvider,
	type GeneratedDataKey,
	type WrappedDataKey,
} from "../../src/core/index.js";
import { CryptoModule } from "../../src/crypto.module.js";
import { EncryptedField, FieldCipherService } from "../../src/fields/index.js";
import {
	TenantCipherService,
	TenantCryptoModule,
	TenantFieldCipherService,
	type TenantCryptoPolicy,
} from "../../src/tenant/index.js";
import { TenantCryptoScopeService } from "../../src/tenant/tenant-cipher.service.js";

function target(id: string, authority: TenantTarget["authority"] = "tenant"): TenantTarget {
	return Object.freeze({
		tenant: Object.freeze({ id, settings: Object.freeze({}), source: "test" }),
		authority,
	});
}

class MutableTenantContext implements TenantContextReader {
	target: TenantTarget = target("alpha");
	onRequireTarget?: () => void;

	current(): ReturnType<TenantContextReader["current"]> {
		return this.target.authority === "tenant"
			? { mode: "tenant", tenant: this.target.tenant }
			: {
					mode: "bypass",
					grant: { reason: "test", auditedAt: new Date(0).toISOString() } as never,
					targetTenant: this.target.tenant,
				};
	}

	require(): ReturnType<TenantContextReader["require"]> {
		const state = this.current();
		if (!state) throw new Error("missing");
		return state;
	}

	requireTenant(): ReturnType<TenantContextReader["requireTenant"]> {
		const state = this.require();
		if (state.mode !== "tenant") throw new Error("not tenant authority");
		return state.tenant;
	}

	requireTenantId(): string {
		return this.requireTenant().id;
	}

	requireTenantTarget(): TenantTarget {
		this.onRequireTarget?.();
		return this.target;
	}
}

class CountingProvider implements DataKeyProvider {
	generateCalls = 0;
	unwrapCalls = 0;
	readonly delegate: AesKeyRingProvider;

	constructor(keyId: string) {
		this.delegate = new AesKeyRingProvider({
			activeKeyId: keyId,
			keys: { [keyId]: new Uint8Array(randomBytes(32)) },
		});
	}

	generateDataKey(context: DataKeyContext): Promise<GeneratedDataKey> {
		this.generateCalls += 1;
		return this.delegate.generateDataKey(context);
	}

	unwrapDataKey(dataKey: WrappedDataKey, context: DataKeyContext) {
		this.unwrapCalls += 1;
		return this.delegate.unwrapDataKey(dataKey, context);
	}
}

function services(policy?: TenantCryptoPolicy, namespace = "billing-api") {
	const context = new MutableTenantContext();
	const shared = new CountingProvider("shared-key");
	const alpha = new CountingProvider("alpha-key");
	const beta = new CountingProvider("beta-key");
	const cipher = new CipherService(
		new CipherEngine({
			providers: [
				{ name: "shared", provider: shared },
				{ name: "alpha", provider: alpha },
				{ name: "beta", provider: beta },
			],
			defaultProvider: "shared",
		}),
	);
	const scope = new TenantCryptoScopeService(context, cipher, policy ?? null, { namespace });
	const tenant = new TenantCipherService(cipher, scope);
	const fields = new TenantFieldCipherService(new FieldCipherService(cipher), scope);
	return { context, shared, alpha, beta, cipher, tenant, fields };
}

class TenantSecretDto {
	@EncryptedField("customer.taxId")
	taxId = "123";
}

@Module({
	providers: [
		MutableTenantContext,
		{ provide: TENANT_CONTEXT_READER, useExisting: MutableTenantContext },
	],
	exports: [TENANT_CONTEXT_READER],
})
class TestTenantContextModule {}

describe("tenant crypto integration", () => {
	const modules: TestingModule[] = [];

	afterEach(async () => {
		await Promise.all(modules.splice(0).map(async (module) => module.close()));
	});

	it("binds ciphertext to tenant, namespace, purpose, and caller AAD", async () => {
		const { context, tenant, cipher } = services();
		const envelope = await tenant.encryptText("secret", {
			purpose: "invoice.total",
			aad: "invoice-1",
		});
		await expect(
			tenant.decryptText(envelope, { purpose: "invoice.total", aad: "invoice-1" }),
		).resolves.toBe("secret");

		context.target = target("beta");
		await expect(
			tenant.decryptText(envelope, { purpose: "invoice.total", aad: "invoice-1" }),
		).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
		context.target = target("alpha");
		await expect(tenant.decryptText(envelope, { purpose: "other" })).rejects.toMatchObject({
			code: "AUTHENTICATION_FAILED",
		});

		const otherScope = new TenantCryptoScopeService(context, cipher, null, {
			namespace: "other-api",
		});
		const otherNamespace = new TenantCipherService(cipher, otherScope);
		await expect(
			otherNamespace.decryptText(envelope, { purpose: "invoice.total", aad: "invoice-1" }),
		).rejects.toBeDefined();
	});

	it("allows a targeted audited authority without exposing a tenant id argument", async () => {
		const { context, tenant } = services();
		context.target = target("alpha", "targeted-bypass");
		const envelope = await tenant.encryptText("maintenance", { purpose: "rotation" });
		await expect(tenant.decryptText(envelope, { purpose: "rotation" })).resolves.toBe(
			"maintenance",
		);
	});

	it("enforces policy routes before provider unwrap", async () => {
		let route = "alpha";
		const policy: TenantCryptoPolicy = {
			resolve: () => ({ writeProvider: route, readProviders: [route] }),
		};
		const { tenant, alpha } = services(policy);
		const envelope = await tenant.encryptText("routed", { purpose: "profile" });
		route = "beta";
		await expect(tenant.decryptText(envelope, { purpose: "profile" })).rejects.toMatchObject({
			code: "AUTHENTICATION_FAILED",
		});
		expect(alpha.unwrapCalls).toBe(0);
	});

	it("rejects a forged provider header before calling the forged route", async () => {
		const policy: TenantCryptoPolicy = {
			resolve: () => ({ writeProvider: "alpha", readProviders: ["alpha"] }),
		};
		const { tenant, alpha, beta } = services(policy);
		const envelope = await tenant.encryptText("routed", { purpose: "profile" });
		const segments = envelope.split(".");
		const protectedSegment = segments[1];
		if (protectedSegment === undefined) throw new Error("Missing protected test segment.");
		const protectedJson = Buffer.from(protectedSegment, "base64url").toString("utf8");
		segments[1] = Buffer.from(
			protectedJson.replace('"provider":"alpha"', '"provider":"beta"'),
		).toString("base64url");

		await expect(
			tenant.decryptText(segments.join("."), { purpose: "profile" }),
		).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
		expect(alpha.unwrapCalls).toBe(0);
		expect(beta.unwrapCalls).toBe(0);
	});

	it("snapshots tenant plaintext and AAD before asynchronous policy resolution", async () => {
		let release: (() => void) | undefined;
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		const policy: TenantCryptoPolicy = {
			resolve: async () => {
				await gate;
				return { writeProvider: "shared" };
			},
		};
		const { tenant } = services(policy);
		const plaintext = new Uint8Array([1, 2, 3]);
		const aad = new Uint8Array([4, 5, 6]);
		const pending = tenant.encryptBytes(plaintext, {
			purpose: "mutable.input",
			aad,
		});
		plaintext.fill(9);
		aad.fill(9);
		release?.();
		const envelope = await pending;
		await expect(
			tenant.decryptBytes(envelope, {
				purpose: "mutable.input",
				aad: new Uint8Array([4, 5, 6]),
			}),
		).resolves.toEqual(new Uint8Array([1, 2, 3]));
	});

	it("does not trust tenant-policy CryptoError messages", async () => {
		const policy: TenantCryptoPolicy = {
			resolve: () => {
				throw new CryptoError("TENANT_POLICY", "TENANT_SENTINEL KEY_SENTINEL");
			},
		};
		const { tenant } = services(policy);
		try {
			await tenant.encryptText("secret", { purpose: "policy.failure" });
			throw new Error("Expected tenant policy to fail.");
		} catch (error: unknown) {
			expect(error).toMatchObject({
				code: "TENANT_POLICY",
				message: "The tenant crypto policy failed.",
			});
			expect(String(error)).not.toContain("SENTINEL");
		}
	});

	it("aborts promptly while tenant policy resolution is pending", async () => {
		const policy: TenantCryptoPolicy = {
			resolve: () => new Promise(() => undefined),
		};
		const { tenant } = services(policy);
		const controller = new AbortController();
		const pending = tenant.encryptText("secret", {
			purpose: "policy.abort",
			signal: controller.signal,
		});
		controller.abort();

		await expect(pending).rejects.toMatchObject({ code: "ABORTED" });

		const { fields: tenantFields } = services(policy);
		const fieldController = new AbortController();
		const pendingFields = tenantFields.encryptFieldsInPlace(new TenantSecretDto(), {
			signal: fieldController.signal,
		});
		fieldController.abort();
		await expect(pendingFields).rejects.toMatchObject({ code: "ABORTED" });
	});

	it("reads legacy routes and writes the current route during re-encryption", async () => {
		let profile = { writeProvider: "alpha", readProviders: ["alpha"] };
		const policy: TenantCryptoPolicy = { resolve: () => profile };
		const { tenant, cipher } = services(policy);
		const oldEnvelope = await tenant.encryptText("rotate", { purpose: "profile" });
		profile = { writeProvider: "beta", readProviders: ["alpha", "beta"] };
		const rotated = await tenant.reencrypt(oldEnvelope, { purpose: "profile" });
		expect(cipher.inspect(rotated).provider).toBe("beta");
		profile = { writeProvider: "beta", readProviders: ["beta"] };
		await expect(tenant.decryptText(rotated, { purpose: "profile" })).resolves.toBe("rotate");
	});

	it("binds encrypted fields to the active tenant", async () => {
		const { context, fields } = services();
		const value = new TenantSecretDto();
		await fields.encryptFieldsInPlace(value);
		context.target = target("beta");
		await expect(fields.decryptFieldsInPlace(value)).rejects.toMatchObject({
			code: "AUTHENTICATION_FAILED",
		});
		context.target = target("alpha");
		await fields.decryptFieldsInPlace(value);
		expect(value.taxId).toBe("123");
	});

	it("rechecks the graph after a tenant context reader runs the commit guard", async () => {
		class RootDto {
			child = new TenantSecretDto();
		}
		const { context, fields: tenantFields } = services();
		const root = new RootDto();
		let calls = 0;
		context.onRequireTarget = () => {
			calls += 1;
			if (calls === 4) {
				root.child = new TenantSecretDto();
				root.child.taxId = "PLAINTEXT_SENTINEL";
			}
		};

		await expect(tenantFields.encryptFieldsInPlace(root)).rejects.toMatchObject({
			code: "FIELD_POLICY",
		});
		expect(root.child.taxId).toBe("PLAINTEXT_SENTINEL");
	});

	it("resolves through a real Nest dynamic module", async () => {
		const crypto = CryptoModule.forRoot({
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
		});
		const module = await Test.createTestingModule({
			imports: [
				TenantCryptoModule.forRoot({
					namespace: "module-test",
					imports: [TestTenantContextModule, crypto],
				}),
			],
		}).compile();
		modules.push(module);
		expect(module.get(TenantCipherService)).toBeInstanceOf(TenantCipherService);
		expect(module.get(TenantFieldCipherService)).toBeInstanceOf(TenantFieldCipherService);
	});

	it("supports asynchronous tenant-module configuration", async () => {
		const crypto = CryptoModule.forRoot({
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
		});
		const module = await Test.createTestingModule({
			imports: [
				TenantCryptoModule.forRootAsync({
					imports: [TestTenantContextModule, crypto],
					useFactory: () => ({ namespace: "async-module-test" }),
				}),
			],
		}).compile();
		modules.push(module);
		expect(module.get(TenantCipherService)).toBeInstanceOf(TenantCipherService);
	});

	it("integrates with real tenant scopes and rejects missing, unscoped, and detached authority", async () => {
		const provider = new CountingProvider("real-tenant-key");
		const audit = vi.fn();
		const store = new InMemoryTenantRegistryStore([
			{ id: "alpha", settings: { enabled: true } },
			{ id: "beta", settings: { enabled: true } },
		]);
		const module = await Test.createTestingModule({
			imports: [
				TenantCryptoModule.forRoot({
					namespace: "real-tenant-test",
					imports: [
						TenantModule.forRoot({
							store,
							http: false,
							disableAutomaticGuard: true,
							bypass: { auditor: { audit } },
						}),
						CryptoModule.forRoot({
							providers: [{ name: "local", provider }],
							defaultProvider: "local",
						}),
					],
				}),
			],
		}).compile();
		modules.push(module);
		const tenantService = module.get(TenantService);
		const tenantCipher = module.get(TenantCipherService);

		await expect(
			tenantCipher.encryptText("missing", { purpose: "context.test" }),
		).rejects.toMatchObject({ code: "TENANT_POLICY" });
		expect(provider.generateCalls).toBe(0);

		await tenantService.runWithBypass({ reason: "unscoped maintenance" }, async () => {
			await expect(
				tenantCipher.encryptText("unscoped", { purpose: "context.test" }),
			).rejects.toMatchObject({ code: "TENANT_POLICY" });
		});
		expect(provider.generateCalls).toBe(0);

		await tenantService.run({ tenantId: "alpha" }, async () => {
			const envelope = await tenantCipher.encryptText("tenant", { purpose: "context.test" });
			await expect(tenantCipher.decryptText(envelope, { purpose: "context.test" })).resolves.toBe(
				"tenant",
			);
		});

		await tenantService.runWithTargetedBypass(
			{ tenantId: "alpha", reason: "key rotation" },
			async () => {
				const envelope = await tenantCipher.encryptText("targeted", {
					purpose: "context.test",
				});
				await expect(tenantCipher.decryptText(envelope, { purpose: "context.test" })).resolves.toBe(
					"targeted",
				);
			},
		);
		expect(audit).toHaveBeenCalled();

		const callsBeforeDetached = provider.generateCalls;
		let detached: Promise<string> | undefined;
		await tenantService.runWithTargetedBypass(
			{ tenantId: "alpha", reason: "detached rotation" },
			() => {
				detached = tenantCipher.encryptText("detached", { purpose: "context.test" });
			},
		);
		expect(detached).toBeDefined();
		await expect(detached).rejects.toMatchObject({ code: "TENANT_POLICY" });
		expect(provider.generateCalls).toBe(callsBeforeDetached);
	});
});
