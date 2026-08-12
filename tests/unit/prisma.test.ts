import { randomBytes } from "node:crypto";
import type { TenantContextReader, TenantTarget } from "@nestm/tenant/context";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CipherService } from "../../src/cipher.service.js";
import {
	AesKeyRingProvider,
	CipherEngine,
	type DataKeyContext,
	type DataKeyProvider,
	type GeneratedDataKey,
	type WrappedDataKey,
} from "../../src/core/index.js";
import {
	createTenantPrismaFieldEncryption,
	TENANT_PRISMA_WRITE_OPERATIONS,
	type TenantPrismaFieldEncryptionOptions,
	type TenantPrismaWriteInput,
} from "../../src/prisma/index.js";
import { TenantCipherService } from "../../src/tenant/index.js";
import { TenantCryptoScopeService } from "../../src/tenant/tenant-cipher.service.js";

function target(id: string): TenantTarget {
	return Object.freeze({
		tenant: Object.freeze({ id, settings: Object.freeze({}), source: "test" }),
		authority: "tenant",
	});
}

class StaticTenantContext implements TenantContextReader {
	readonly target = target("alpha");

	current(): ReturnType<TenantContextReader["current"]> {
		return { mode: "tenant", tenant: this.target.tenant };
	}

	require(): ReturnType<TenantContextReader["require"]> {
		return { mode: "tenant", tenant: this.target.tenant };
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

class CountingProvider implements DataKeyProvider {
	generateCalls = 0;
	unwrapCalls = 0;
	readonly #delegate = new AesKeyRingProvider({
		activeKeyId: "active",
		keys: { active: randomBytes(32) },
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

const defaultOptions: TenantPrismaFieldEncryptionOptions = {
	registry: {
		User: {
			email: { purpose: "user.email" },
			secondaryEmail: { purpose: "user.secondary-email" },
		},
		Post: {
			title: { purpose: "post.title" },
		},
	},
	relations: {
		User: { posts: "Post" },
	},
};

const engines: CipherEngine[] = [];

function services(options: TenantPrismaFieldEncryptionOptions = defaultOptions) {
	const provider = new CountingProvider();
	const engine = new CipherEngine({
		defaultProvider: "local",
		providers: [{ name: "local", provider }],
	});
	engines.push(engine);
	const cipher = new CipherService(engine);
	const scope = new TenantCryptoScopeService(new StaticTenantContext(), cipher, null, {
		namespace: "prisma-tests",
	});
	const tenant = new TenantCipherService(cipher, scope);
	return {
		provider,
		tenant,
		processor: createTenantPrismaFieldEncryption(tenant, options),
	};
}

function expectEnvelope(value: unknown): asserts value is string {
	expect(typeof value).toBe("string");
	expect(value).toMatch(/^nmc1\./u);
}

afterEach(async () => {
	await Promise.all(engines.splice(0).map((engine) => engine.close()));
});

describe("Tenant Prisma field encryption", () => {
	it("exports an immutable complete top-level write-operation allowlist", () => {
		expect(Object.isFrozen(TENANT_PRISMA_WRITE_OPERATIONS)).toBe(true);
		expect(TENANT_PRISMA_WRITE_OPERATIONS).toEqual([
			"create",
			"update",
			"upsert",
			"createMany",
			"createManyAndReturn",
			"updateMany",
			"updateManyAndReturn",
		]);
	});

	it("encrypts every supported direct write operation and set slot", async () => {
		const { processor, tenant } = services();
		const create = {
			model: "User",
			operation: "create",
			args: { data: { email: "create@example.test" } },
		} satisfies TenantPrismaWriteInput;
		const update = {
			model: "User",
			operation: "update",
			args: { data: { email: { set: "update@example.test" } } },
		} satisfies TenantPrismaWriteInput;
		const upsert = {
			model: "User",
			operation: "upsert",
			args: {
				where: { id: "1" },
				create: { email: "upsert-create@example.test" },
				update: { email: { set: "upsert-update@example.test" } },
			},
		} satisfies TenantPrismaWriteInput;
		const createMany = {
			model: "User",
			operation: "createMany",
			args: {
				data: [{ email: "many-a@example.test" }, { email: "many-b@example.test" }],
			},
		} satisfies TenantPrismaWriteInput;
		const createManyAndReturn = {
			model: "User",
			operation: "createManyAndReturn",
			args: {
				data: [{ email: "many-return-a@example.test" }, { email: "many-return-b@example.test" }],
			},
		} satisfies TenantPrismaWriteInput;
		const updateMany = {
			model: "User",
			operation: "updateMany",
			args: { where: {}, data: { email: { set: "update-many@example.test" } } },
		} satisfies TenantPrismaWriteInput;
		const updateManyAndReturn = {
			model: "User",
			operation: "updateManyAndReturn",
			args: { where: {}, data: { email: { set: "update-many-return@example.test" } } },
		} satisfies TenantPrismaWriteInput;

		for (const input of [
			create,
			update,
			upsert,
			createMany,
			createManyAndReturn,
			updateMany,
			updateManyAndReturn,
		]) {
			await processor.encryptWriteArgs(input);
		}

		const encrypted = [
			[create.args.data.email, "create@example.test"],
			[update.args.data.email.set, "update@example.test"],
			[upsert.args.create.email, "upsert-create@example.test"],
			[upsert.args.update.email.set, "upsert-update@example.test"],
			[createMany.args.data[0]!.email, "many-a@example.test"],
			[createMany.args.data[1]!.email, "many-b@example.test"],
			[createManyAndReturn.args.data[0]!.email, "many-return-a@example.test"],
			[createManyAndReturn.args.data[1]!.email, "many-return-b@example.test"],
			[updateMany.args.data.email.set, "update-many@example.test"],
			[updateManyAndReturn.args.data.email.set, "update-many-return@example.test"],
		] as const;
		for (const [envelope, plaintext] of encrypted) {
			expectEnvelope(envelope);
			await expect(tenant.decryptText(envelope, { purpose: "user.email" })).resolves.toBe(
				plaintext,
			);
		}
	});

	it("traverses nested create, createMany, upsert, update, and updateMany writes", async () => {
		const { processor, tenant } = services();
		const input = {
			model: "User",
			operation: "update",
			args: {
				where: { id: "1" },
				data: {
					posts: {
						create: { title: "nested-create" },
						createMany: {
							data: [{ title: "nested-many-a" }, { title: "nested-many-b" }],
						},
						upsert: {
							where: { id: "2" },
							create: { title: "nested-upsert-create" },
							update: { title: { set: "nested-upsert-update" } },
						},
						update: [
							{
								where: { id: "3" },
								data: { title: { set: "nested-update" } },
							},
						],
						updateMany: {
							where: { published: false },
							data: { title: { set: "nested-update-many" } },
						},
					},
				},
			},
		} satisfies TenantPrismaWriteInput;

		await processor.encryptWriteArgs(input);

		const posts = input.args.data.posts;
		const encrypted = [
			[posts.create.title, "nested-create"],
			[posts.createMany.data[0]!.title, "nested-many-a"],
			[posts.createMany.data[1]!.title, "nested-many-b"],
			[posts.upsert.create.title, "nested-upsert-create"],
			[posts.upsert.update.title.set, "nested-upsert-update"],
			[posts.update[0]!.data.title.set, "nested-update"],
			[posts.updateMany.data.title.set, "nested-update-many"],
		] as const;
		for (const [envelope, plaintext] of encrypted) {
			expectEnvelope(envelope);
			await expect(tenant.decryptText(envelope, { purpose: "post.title" })).resolves.toBe(
				plaintext,
			);
		}
	});

	it("uses one protection batch, authenticates existing envelopes, and preserves order", async () => {
		const { processor, tenant, provider } = services();
		const existing = await tenant.encryptText("already-protected", {
			purpose: "user.secondary-email",
		});
		provider.generateCalls = 0;
		provider.unwrapCalls = 0;
		const protect = vi.spyOn(tenant, "protectTextBatch");
		const input = {
			model: "User",
			operation: "create",
			args: {
				data: {
					email: "plain@example.test",
					secondaryEmail: existing,
				},
			},
		} satisfies TenantPrismaWriteInput;

		await processor.encryptWriteArgs(input);

		expect(protect).toHaveBeenCalledTimes(1);
		expect(protect).toHaveBeenCalledWith([
			{ value: "plain@example.test", purpose: "user.email" },
			{ value: existing, purpose: "user.secondary-email" },
		]);
		expect(provider.generateCalls).toBe(1);
		expect(provider.unwrapCalls).toBe(1);
		expect(input.args.data.secondaryEmail).toBe(existing);
		expectEnvelope(input.args.data.email);
	});

	it("asserts authenticated envelopes without mutating and still rejects mixed plaintext", async () => {
		const { processor, tenant } = services();
		const input = {
			model: "User",
			operation: "create",
			args: {
				data: {
					email: "one@example.test",
					secondaryEmail: "two@example.test",
				},
			},
		} satisfies TenantPrismaWriteInput;
		await processor.encryptWriteArgs(input);
		const email = input.args.data.email;
		const secondaryEmail = input.args.data.secondaryEmail;
		const protect = vi.spyOn(tenant, "protectTextBatch");

		await processor.assertWriteArgsEncrypted(input);
		expect(protect).toHaveBeenCalledTimes(1);
		expect(input.args.data).toEqual({ email, secondaryEmail });

		input.args.data.secondaryEmail = "legacy@example.test";
		await expect(processor.assertWriteArgsEncrypted(input)).rejects.toMatchObject({
			code: "FIELD_POLICY",
		});
		expect(input.args.data).toEqual({ email, secondaryEmail: "legacy@example.test" });
		expect(protect).toHaveBeenCalledTimes(2);
	});

	it("preserves nullish fields and rejects unsupported registered field operations before crypto", async () => {
		const { processor, tenant } = services();
		const protect = vi.spyOn(tenant, "protectTextBatch");
		const nullish = {
			model: "User",
			operation: "update",
			args: {
				data: {
					email: null,
					secondaryEmail: { set: undefined },
				},
			},
		} satisfies TenantPrismaWriteInput;
		await processor.encryptWriteArgs(nullish);
		expect(nullish.args.data).toEqual({ email: null, secondaryEmail: { set: undefined } });
		expect(protect).not.toHaveBeenCalled();

		const invalid = {
			model: "User",
			operation: "update",
			args: {
				data: {
					email: "must-remain-plain",
					secondaryEmail: { increment: "unsupported" },
				},
			},
		} satisfies TenantPrismaWriteInput;
		await expect(processor.encryptWriteArgs(invalid)).rejects.toMatchObject({
			code: "FIELD_POLICY",
		});
		expect(invalid.args.data.email).toBe("must-remain-plain");
		expect(protect).not.toHaveBeenCalled();
	});

	it("does not commit any field when authentication or assignment fails", async () => {
		const { processor, tenant } = services();
		const wrongPurpose = await tenant.encryptText("wrong-purpose", { purpose: "other" });
		const input = {
			model: "User",
			operation: "create",
			args: {
				data: {
					email: "first@example.test",
					secondaryEmail: wrongPurpose,
				},
			},
		} satisfies TenantPrismaWriteInput;
		await expect(processor.encryptWriteArgs(input)).rejects.toMatchObject({
			code: "AUTHENTICATION_FAILED",
		});
		expect(input.args.data).toEqual({
			email: "first@example.test",
			secondaryEmail: wrongPurpose,
		});

		input.args.data.secondaryEmail = "second@example.test";
		const originalSet = Reflect.set;
		vi.spyOn(Reflect, "set").mockImplementation((owner, key, value, receiver) => {
			if (key === "secondaryEmail") return false;
			return receiver === undefined
				? originalSet(owner, key, value)
				: originalSet(owner, key, value, receiver);
		});
		await expect(processor.encryptWriteArgs(input)).rejects.toMatchObject({ code: "FIELD_POLICY" });
		expect(input.args.data).toEqual({
			email: "first@example.test",
			secondaryEmail: "second@example.test",
		});
	});

	it("detects argument mutation during asynchronous crypto before committing", async () => {
		const { processor, tenant } = services();
		let resolveBatch: ((values: readonly string[]) => void) | undefined;
		const pendingBatch = new Promise<readonly string[]>((resolve) => {
			resolveBatch = resolve;
		});
		const protect = vi.spyOn(tenant, "protectTextBatch").mockReturnValue(pendingBatch);
		const input = {
			model: "User",
			operation: "create",
			args: { data: { email: "original@example.test" } },
		} satisfies TenantPrismaWriteInput;

		const pending = processor.encryptWriteArgs(input);
		await vi.waitFor(() => expect(protect).toHaveBeenCalledOnce());
		input.args.data.email = "changed@example.test";
		resolveBatch?.(["nmc1.protected"]);

		await expect(pending).rejects.toMatchObject({ code: "FIELD_POLICY" });
		expect(input.args.data.email).toBe("changed@example.test");
	});

	it("rejects malformed crypto results without committing caller arguments", async () => {
		const { processor, tenant } = services();
		const input = {
			model: "User",
			operation: "create",
			args: { data: { email: "unchanged@example.test" } },
		} satisfies TenantPrismaWriteInput;
		const protect = vi.spyOn(tenant, "protectTextBatch").mockResolvedValue([]);

		await expect(processor.encryptWriteArgs(input)).rejects.toMatchObject({
			code: "FIELD_POLICY",
		});
		expect(input.args.data.email).toBe("unchanged@example.test");

		protect.mockRestore();
		const envelope = await tenant.encryptText("already-encrypted", { purpose: "user.email" });
		input.args.data.email = envelope;
		vi.spyOn(tenant, "protectTextBatch").mockResolvedValue(["nmc1.unexpected-replacement"]);

		await expect(processor.assertWriteArgsEncrypted(input)).rejects.toMatchObject({
			code: "FIELD_POLICY",
		});
		expect(input.args.data.email).toBe(envelope);
	});

	it("fails closed for accessors, proxies, cycles, unsupported nested writes, and depth overflow", async () => {
		const accessorServices = services();
		let getterCalls = 0;
		const accessorData: object = {};
		Object.defineProperty(accessorData, "email", {
			configurable: true,
			enumerable: true,
			get: () => {
				getterCalls += 1;
				return "leak@example.test";
			},
		});
		await expect(
			accessorServices.processor.encryptWriteArgs({
				model: "User",
				operation: "create",
				args: { data: accessorData },
			}),
		).rejects.toMatchObject({ code: "FIELD_POLICY" });
		expect(getterCalls).toBe(0);

		await expect(
			accessorServices.processor.encryptWriteArgs({
				model: "User",
				operation: "create",
				args: { data: { posts: new Proxy({}, {}) } },
			}),
		).rejects.toMatchObject({ code: "FIELD_POLICY" });

		await expect(
			accessorServices.processor.encryptWriteArgs({
				model: "User",
				operation: "create",
				args: {
					data: {
						posts: {
							connectOrCreate: {
								where: { id: "1" },
								create: { title: "must-not-leak" },
							},
						},
					},
				},
			}),
		).rejects.toMatchObject({ code: "FIELD_POLICY" });

		const recursiveOptions: TenantPrismaFieldEncryptionOptions = {
			registry: { Node: { secret: { purpose: "node.secret" } } },
			relations: { Node: { children: "Node" } },
			maxDepth: 1,
		};
		const recursive = services(recursiveOptions).processor;
		const cycle: { secret: string; children?: unknown } = { secret: "cycle" };
		cycle.children = { create: cycle };
		await expect(
			recursive.encryptWriteArgs({
				model: "Node",
				operation: "create",
				args: { data: cycle },
			}),
		).rejects.toMatchObject({ code: "FIELD_POLICY" });

		await expect(
			recursive.encryptWriteArgs({
				model: "Node",
				operation: "create",
				args: {
					data: {
						secret: "root",
						children: {
							create: {
								secret: "child",
								children: { create: { secret: "too-deep" } },
							},
						},
					},
				},
			}),
		).rejects.toMatchObject({ code: "FIELD_POLICY" });
	});

	it("snapshots configuration and rejects ambiguous registry definitions", async () => {
		const mutableRegistry = {
			User: { email: { purpose: "stable-purpose" } },
		};
		const { processor, tenant } = services({ registry: mutableRegistry });
		mutableRegistry.User.email.purpose = "mutated-purpose";
		const input = {
			model: "User",
			operation: "create",
			args: { data: { email: "snapshot@example.test" } },
		} satisfies TenantPrismaWriteInput;
		await processor.encryptWriteArgs(input);
		expectEnvelope(input.args.data.email);
		await expect(
			tenant.decryptText(input.args.data.email, { purpose: "stable-purpose" }),
		).resolves.toBe("snapshot@example.test");

		expect(() =>
			createTenantPrismaFieldEncryption(tenant, {
				registry: { User: { profile: { purpose: "user.profile" } } },
				relations: { User: { profile: "Profile" } },
			}),
		).toThrow(expect.objectContaining({ code: "CONFIGURATION" }));

		const misspelledOptions: TenantPrismaFieldEncryptionOptions = {
			registry: { User: {}, Post: { title: { purpose: "post.title" } } },
			// @ts-expect-error Exercises runtime rejection of an unknown configuration property.
			relation: { User: { posts: "Post" } },
		};
		expect(() => createTenantPrismaFieldEncryption(tenant, misspelledOptions)).toThrow(
			expect.objectContaining({ code: "CONFIGURATION" }),
		);

		expect(() =>
			createTenantPrismaFieldEncryption(tenant, {
				registry: { User: {}, Post: { title: { purpose: "post.title" } } },
				relations: { User: { posts: "Pots" } },
			}),
		).toThrow(expect.objectContaining({ code: "CONFIGURATION" }));
	});
});
