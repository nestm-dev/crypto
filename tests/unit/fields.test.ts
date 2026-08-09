import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { CipherService } from "../../src/cipher.service.js";
import {
	AesKeyRingProvider,
	CipherEngine,
	frame,
	utf8,
	type DataKeyContext,
	type DataKeyProvider,
	type WrappedDataKey,
} from "../../src/core/index.js";
import { EncryptedField, FieldCipherService } from "../../src/fields/index.js";

function fields(): FieldCipherService {
	const engine = new CipherEngine({
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
	return new FieldCipherService(new CipherService(engine));
}

function fieldAad(purpose: string): Uint8Array {
	return frame(utf8("@nestm/crypto/field"), utf8(purpose), new Uint8Array());
}

class AddressDto {
	@EncryptedField("customer.address.line1")
	line1 = "Main Street";
}

class CustomerDto {
	@EncryptedField("customer.taxId")
	taxId: string | null = "123";

	@EncryptedField("customer.optional")
	optional: string | undefined = undefined;

	addresses: AddressDto[] = [new AddressDto(), new AddressDto()];
}

describe("FieldCipherService", () => {
	it("round trips tagged strings across nested arrays and preserves nullish values", async () => {
		const service = fields();
		const customer = new CustomerDto();
		const originalOptional = customer.optional;
		await service.encryptFieldsInPlace(customer);
		expect(customer.taxId).toMatch(/^nmc1\./u);
		expect(customer.optional).toBe(originalOptional);
		expect(customer.addresses.every(({ line1 }) => line1.startsWith("nmc1."))).toBe(true);
		await service.decryptFieldsInPlace(customer);
		expect(customer.taxId).toBe("123");
		expect(customer.addresses.map(({ line1 }) => line1)).toEqual(["Main Street", "Main Street"]);

		customer.taxId = null;
		await service.encryptFieldsInPlace(customer);
		expect(customer.taxId).toBeNull();
	});

	it("uses one wrapped data key and unique nonces per traversal", async () => {
		const service = fields();
		const customer = new CustomerDto();
		await service.encryptFieldsInPlace(customer);
		const envelopes = [customer.taxId, ...customer.addresses.map(({ line1 }) => line1)] as string[];
		expect(new Set(envelopes.map((value) => value.split(".")[2])).size).toBe(1);
		expect(new Set(envelopes.map((value) => value.split(".")[3])).size).toBe(envelopes.length);
	});

	it("authenticates existing envelopes before treating encryption as idempotent", async () => {
		const service = fields();
		const customer = new CustomerDto();
		await service.encryptFieldsInPlace(customer);
		const first = customer.taxId;
		await service.encryptFieldsInPlace(customer);
		expect(customer.taxId).toBe(first);

		const envelope = customer.taxId as string;
		const segments = envelope.split(".");
		const ciphertext = segments[4];
		if (!ciphertext) throw new Error("Missing ciphertext test segment.");
		segments[4] = `${ciphertext.startsWith("A") ? "B" : "A"}${ciphertext.slice(1)}`;
		customer.taxId = segments.join(".");
		await expect(service.encryptFieldsInPlace(customer)).rejects.toMatchObject({
			code: "AUTHENTICATION_FAILED",
		});
	});

	it("requires explicit legacy plaintext passthrough", async () => {
		const service = fields();
		const customer = new CustomerDto();
		await expect(service.decryptFieldsInPlace(customer)).rejects.toMatchObject({
			code: "FIELD_POLICY",
		});
		await expect(
			service.decryptFieldsInPlace(customer, { legacyPlaintext: "allow" }),
		).resolves.toBe(customer);
	});

	it("never treats future or malformed envelope namespaces as legacy plaintext", async () => {
		const service = fields();
		for (const reserved of ["nmc2.a.b.c.d.e", "nmc1garbage", "nmc2garbage", "nmc"]) {
			const decrypting = new CustomerDto();
			decrypting.taxId = reserved;
			await expect(
				service.decryptFieldsInPlace(decrypting, { legacyPlaintext: "allow" }),
			).rejects.toMatchObject({
				code: reserved.startsWith("nmc2.") ? "UNSUPPORTED_VERSION" : "MALFORMED_ENVELOPE",
			});
		}

		const encrypting = new CustomerDto();
		encrypting.taxId = "nmc2.a.b.c.d.e";
		await expect(service.encryptFieldsInPlace(encrypting)).rejects.toMatchObject({
			code: "UNSUPPORTED_VERSION",
		});
	});

	it("fails closed for plain nested objects", async () => {
		const service = fields();
		const customer = new CustomerDto();
		customer.addresses = [{ line1: "leak" }] as AddressDto[];
		await expect(service.encryptFieldsInPlace(customer)).rejects.toMatchObject({
			code: "FIELD_POLICY",
		});
	});

	it.each(["Map", "Set"] as const)(
		"fails closed instead of skipping decorated instances inside %s",
		async (container) => {
			class ContainerDto {
				children: Map<string, AddressDto> | Set<AddressDto> =
					container === "Map" ? new Map([["home", new AddressDto()]]) : new Set([new AddressDto()]);
			}
			await expect(fields().encryptFieldsInPlace(new ContainerDto())).rejects.toMatchObject({
				code: "FIELD_POLICY",
			});
		},
	);

	it("rejects intrinsic leaves and arrays that hide attached decorated descendants", async () => {
		class ContainerDto {
			leaf: object = new Date();
		}
		const dated = new ContainerDto();
		Object.defineProperty(dated.leaf, "child", {
			value: new AddressDto(),
			enumerable: true,
		});
		await expect(fields().encryptFieldsInPlace(dated)).rejects.toMatchObject({
			code: "FIELD_POLICY",
		});

		const array = new ContainerDto();
		array.leaf = [new AddressDto()];
		Object.defineProperty(array.leaf, "hiddenChild", {
			value: new AddressDto(),
			enumerable: true,
		});
		await expect(fields().encryptFieldsInPlace(array)).rejects.toMatchObject({
			code: "FIELD_POLICY",
		});
	});

	it("traverses non-enumerable data properties so decorated children cannot be hidden", async () => {
		class ContainerDto {
			marker = "container";
		}
		const container = new ContainerDto();
		const child = new AddressDto();
		Object.defineProperty(container, "child", {
			value: child,
			writable: true,
			configurable: true,
		});

		await fields().encryptFieldsInPlace(container);
		expect(child.line1).toMatch(/^nmc1\./u);
	});

	it("rejects proxies before committing any transformed field", async () => {
		class PairDto {
			@EncryptedField("pair.first")
			first = "first";

			@EncryptedField("pair.second")
			second = "second";
		}
		const target = new PairDto();
		const value = new Proxy(target, {
			set(object, property, next) {
				if (property === "second") return false;
				return Reflect.set(object, property, next);
			},
		});

		await expect(fields().encryptFieldsInPlace(value)).rejects.toMatchObject({
			code: "FIELD_POLICY",
		});
		expect(target.first).toBe("first");
		expect(target.second).toBe("second");
	});

	it("rejects decorated values inherited from a prototype", async () => {
		class PrototypeDto {
			@EncryptedField("prototype.secret")
			declare secret: string;
		}
		Object.defineProperty(PrototypeDto.prototype, "secret", {
			value: "PLAINTEXT_SENTINEL",
			writable: true,
			configurable: true,
		});
		const value = new PrototypeDto();

		await expect(fields().encryptFieldsInPlace(value)).rejects.toMatchObject({
			code: "FIELD_POLICY",
		});
		expect(Object.prototype.hasOwnProperty.call(value, "secret")).toBe(false);
		expect(value.secret).toBe("PLAINTEXT_SENTINEL");
	});

	it("fails without committing when the object graph changes during provider work", async () => {
		class RootDto {
			child = new AddressDto();
		}
		let release: (() => void) | undefined;
		let started: (() => void) | undefined;
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		const providerStarted = new Promise<void>((resolve) => {
			started = resolve;
		});
		const delegate = new AesKeyRingProvider({
			activeKeyId: "k1",
			keys: { k1: new Uint8Array(randomBytes(32)) },
		});
		const provider: DataKeyProvider = {
			generateDataKey: async (context: DataKeyContext) => {
				started?.();
				await gate;
				return delegate.generateDataKey(context);
			},
			unwrapDataKey: (dataKey: WrappedDataKey, context: DataKeyContext) =>
				delegate.unwrapDataKey(dataKey, context),
		};
		const service = new FieldCipherService(
			new CipherService(
				new CipherEngine({
					providers: [{ name: "delayed", provider }],
					defaultProvider: "delayed",
				}),
			),
		);
		const root = new RootDto();
		const pending = service.encryptFieldsInPlace(root);
		await providerStarted;
		root.child = new AddressDto();
		root.child.line1 = "LEAK";
		release?.();

		await expect(pending).rejects.toMatchObject({ code: "FIELD_POLICY" });
		expect(root.child.line1).toBe("LEAK");
	});

	it("validates all decrypted strings before mutating any field", async () => {
		class PairDto {
			@EncryptedField("pair.first")
			first = "first";

			@EncryptedField("pair.second")
			second = "second";
		}
		const engine = new CipherEngine({
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
		const cipher = new CipherService(engine);
		const service = new FieldCipherService(cipher);
		const value = new PairDto();
		value.first = await cipher.encryptText("first", { aad: fieldAad("pair.first") });
		value.second = await cipher.encryptBytes(new Uint8Array([0xff]), {
			aad: fieldAad("pair.second"),
		});
		const firstEnvelope = value.first;

		await expect(service.decryptFieldsInPlace(value)).rejects.toMatchObject({
			code: "CIPHER_FAILURE",
		});
		expect(value.first).toBe(firstEnvelope);
		expect(value.second).toMatch(/^nmc1\./u);
	});

	it("fails closed for cycles and depth overflow", async () => {
		class NodeDto {
			@EncryptedField("node.secret")
			secret = "value";

			next?: NodeDto;
		}
		const service = fields();
		const cyclic = new NodeDto();
		cyclic.next = cyclic;
		await expect(service.encryptFieldsInPlace(cyclic)).rejects.toMatchObject({
			code: "FIELD_POLICY",
		});

		const root = new NodeDto();
		root.next = new NodeDto();
		await expect(service.encryptFieldsInPlace(root, { maxDepth: 0 })).rejects.toMatchObject({
			code: "FIELD_POLICY",
		});
	});

	it("rejects non-string tagged values", async () => {
		const service = fields();
		const customer = new CustomerDto();
		customer.taxId = 42 as unknown as string;
		await expect(service.encryptFieldsInPlace(customer)).rejects.toMatchObject({
			code: "FIELD_POLICY",
		});
	});
});
