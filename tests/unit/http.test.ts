import "reflect-metadata";
import type {
	ArgumentMetadata,
	CallHandler,
	ExecutionContext,
	Type as NestType,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { ExecutionContextHost } from "@nestjs/core/helpers/execution-context-host.js";
import {
	type TenantContextReader,
	type TenantContextState,
	type TenantTarget,
} from "@nestm/tenant/context";
import { Type } from "class-transformer";
import { randomBytes } from "node:crypto";
import { firstValueFrom, of } from "rxjs";
import { describe, expect, it } from "vitest";
import { CipherService } from "../../src/cipher.service.js";
import { AesKeyRingProvider, CipherEngine, CryptoError } from "../../src/core/index.js";
import { EncryptedField, FieldCipherService } from "../../src/fields/index.js";
import {
	DecryptTenantFieldsAs,
	TENANT_DECRYPT_FIELDS_METADATA,
	TenantDecryptFieldsInterceptor,
	TenantEncryptFieldsPipe,
	type TenantDecryptFieldsMetadata,
} from "../../src/http/index.js";
import { TenantFieldCipherService } from "../../src/tenant/index.js";
import { TenantCryptoScopeService } from "../../src/tenant/tenant-cipher.service.js";

const ALPHA_TARGET: TenantTarget = Object.freeze({
	tenant: Object.freeze({ id: "alpha", settings: Object.freeze({}), source: "test" }),
	authority: "tenant",
});

class MutableTenantContext implements TenantContextReader {
	available = true;

	current(): TenantContextState | undefined {
		return this.available
			? Object.freeze({ mode: "tenant", tenant: ALPHA_TARGET.tenant })
			: undefined;
	}

	require(): TenantContextState {
		const state = this.current();
		if (state === undefined) throw new Error("Tenant context is unavailable.");
		return state;
	}

	requireTenant(): TenantTarget["tenant"] {
		const state = this.require();
		if (state.mode !== "tenant") throw new Error("Tenant authority is unavailable.");
		return state.tenant;
	}

	requireTenantId(): string {
		return this.requireTenant().id;
	}

	requireTenantTarget(): TenantTarget {
		this.require();
		return ALPHA_TARGET;
	}
}

function services(): {
	readonly context: MutableTenantContext;
	readonly fields: TenantFieldCipherService;
} {
	const context = new MutableTenantContext();
	const cipher = new CipherService(
		new CipherEngine({
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
		}),
	);
	const scope = new TenantCryptoScopeService(context, cipher, null, { namespace: "http-test" });
	return {
		context,
		fields: new TenantFieldCipherService(new FieldCipherService(cipher), scope),
	};
}

function argumentMetadata(
	metatype?: NestType<unknown>,
	type: ArgumentMetadata["type"] = "body",
): ArgumentMetadata {
	return {
		type,
		...(metatype === undefined ? {} : { metatype }),
	};
}

function executionContext(handler: () => unknown): ExecutionContext {
	return new ExecutionContextHost([], null, handler);
}

async function intercept(
	interceptor: TenantDecryptFieldsInterceptor,
	handler: () => unknown,
	value: unknown,
): Promise<unknown> {
	const next: CallHandler<unknown> = { handle: () => of(value) };
	return await firstValueFrom(interceptor.intercept(executionContext(handler), next));
}

class RequestDto {
	@EncryptedField("request.secret")
	secret = "request-value";
}

class OtherRequestDto {
	secret = "must-not-pass";
}

class NestedResponseDto {
	@EncryptedField("response.nested-secret")
	secret = "";
}

class ResponseDto {
	@EncryptedField("response.secret")
	secret = "";

	@Type(() => NestedResponseDto)
	nested = new NestedResponseDto();
}

class InvalidTransformResponseDto {
	readonly marker = true;

	constructor() {
		throw new TypeError("Invalid response constructor.");
	}
}

const RESPONSE_CRYPTO_ERROR = new CryptoError("FIELD_POLICY", "Preserved response failure.");

class CryptoErrorResponseDto {
	readonly marker = true;

	constructor() {
		throw RESPONSE_CRYPTO_ERROR;
	}
}

function responseDto(value: string): ResponseDto {
	const result = new ResponseDto();
	result.secret = `${value}-root`;
	result.nested.secret = `${value}-nested`;
	return result;
}

function plainResponse(value: ResponseDto): object {
	return {
		secret: value.secret,
		nested: { secret: value.nested.secret },
	};
}

const UNDECORATED_HANDLER = (): void => undefined;
const INVALID_RESPONSE_TYPE = (): never => {
	throw new TypeError("Invalid test DTO type.");
};

describe("TenantEncryptFieldsPipe", () => {
	it("passes non-body values through without resolving tenant context", async () => {
		const { context, fields } = services();
		context.available = false;
		const pipe = new TenantEncryptFieldsPipe(fields);

		await expect(pipe.transform("customer-1", argumentMetadata(String, "param"))).resolves.toBe(
			"customer-1",
		);
	});

	it("encrypts transformed DTO instances with a defensive option snapshot", async () => {
		const { fields } = services();
		const configuredAad = new Uint8Array([1, 2, 3]);
		const expectedAad = new Uint8Array(configuredAad);
		const pipe = new TenantEncryptFieldsPipe(fields, { aad: configuredAad });
		configuredAad.fill(9);
		const value = new RequestDto();

		await expect(pipe.transform(value, argumentMetadata(RequestDto))).resolves.toBe(value);
		expect(value.secret).toMatch(/^nmc1\./u);
		await fields.decryptFieldsInPlace(value, { aad: expectedAad });
		expect(value.secret).toBe("request-value");
	});

	it("fails closed when body metadata is absent or validation produced the wrong class", async () => {
		const { fields } = services();
		const pipe = new TenantEncryptFieldsPipe(fields);

		await expect(pipe.transform({ secret: "plaintext" }, argumentMetadata())).rejects.toMatchObject(
			{ code: "FIELD_POLICY" },
		);
		await expect(
			pipe.transform({ secret: "plaintext" }, argumentMetadata(RequestDto)),
		).rejects.toMatchObject({ code: "FIELD_POLICY" });
		await expect(
			pipe.transform(new OtherRequestDto(), argumentMetadata(RequestDto)),
		).rejects.toMatchObject({ code: "FIELD_POLICY" });
	});

	it("rejects misspelled adapter options instead of silently weakening the boundary", () => {
		const { fields } = services();
		expect(
			() =>
				new TenantEncryptFieldsPipe(fields, {
					// @ts-expect-error Exercises runtime rejection of an unknown option.
					maxDepht: 1,
				}),
		).toThrow(expect.objectContaining({ code: "INVALID_ARGUMENT" }));
	});
});

describe("TenantDecryptFieldsInterceptor", () => {
	it("only decrypts routes that opt in", async () => {
		const { context, fields } = services();
		context.available = false;
		const interceptor = new TenantDecryptFieldsInterceptor(fields, new Reflector());
		const value = { secret: "nmc1.not-inspected" };

		await expect(intercept(interceptor, UNDECORATED_HANDLER, value)).resolves.toBe(value);
	});

	it("maps arrays and nested plain values to DTO instances before decryption", async () => {
		const { fields } = services();
		const values = [responseDto("one"), responseDto("two")];
		await fields.encryptFieldsInPlace(values);
		class Controller {
			@DecryptTenantFieldsAs(() => ResponseDto)
			response(this: void): void {}
		}
		const interceptor = new TenantDecryptFieldsInterceptor(fields, new Reflector());
		const result = await intercept(
			interceptor,
			Controller.prototype.response,
			values.map(plainResponse),
		);

		expect(result).toBeInstanceOf(Array);
		if (!Array.isArray(result)) throw new Error("Expected an array response.");
		expect(result).toHaveLength(2);
		const first: unknown = result[0];
		expect(first).toBeInstanceOf(ResponseDto);
		if (!(first instanceof ResponseDto)) throw new Error("Expected a response DTO instance.");
		expect(first.nested).toBeInstanceOf(NestedResponseDto);
		expect(result).toMatchObject([
			{ secret: "one-root", nested: { secret: "one-nested" } },
			{ secret: "two-root", nested: { secret: "two-nested" } },
		]);
	});

	it("captures decorator options without exposing mutable AAD", async () => {
		const { fields } = services();
		const configuredAad = new Uint8Array([4, 5, 6]);
		const expectedAad = new Uint8Array(configuredAad);
		const value = responseDto("safe-options");
		await fields.encryptFieldsInPlace(value, { aad: expectedAad });
		class Controller {
			@DecryptTenantFieldsAs(() => ResponseDto, { aad: configuredAad })
			response(this: void): void {}
		}
		configuredAad.fill(9);
		const reflector = new Reflector();
		const metadata = reflector.get<TenantDecryptFieldsMetadata>(
			TENANT_DECRYPT_FIELDS_METADATA,
			Controller.prototype.response,
		);
		const exposedAad = metadata.options.aad;
		if (!(exposedAad instanceof Uint8Array)) throw new Error("Expected byte AAD metadata.");
		exposedAad.fill(8);
		const freshAad = metadata.options.aad;
		expect(freshAad).toEqual(expectedAad);

		const result = await intercept(
			new TenantDecryptFieldsInterceptor(fields, reflector),
			Controller.prototype.response,
			plainResponse(value),
		);
		expect(result).toMatchObject({
			secret: "safe-options-root",
			nested: { secret: "safe-options-nested" },
		});
	});

	it("preserves null without requiring tenant context", async () => {
		const { context, fields } = services();
		context.available = false;
		class Controller {
			@DecryptTenantFieldsAs(() => ResponseDto)
			response(this: void): void {}
		}

		await expect(
			intercept(
				new TenantDecryptFieldsInterceptor(fields, new Reflector()),
				Controller.prototype.response,
				null,
			),
		).resolves.toBeNull();
	});

	it("rejects non-null primitive responses on decorated routes", async () => {
		const { fields } = services();
		class Controller {
			@DecryptTenantFieldsAs(() => ResponseDto)
			response(this: void): void {}
		}

		await expect(
			intercept(
				new TenantDecryptFieldsInterceptor(fields, new Reflector()),
				Controller.prototype.response,
				"plaintext",
			),
		).rejects.toMatchObject({ code: "FIELD_POLICY" });
	});

	it("normalizes invalid response type factories to a field-policy error", async () => {
		const { fields } = services();
		class Controller {
			@DecryptTenantFieldsAs(INVALID_RESPONSE_TYPE)
			response(this: void): void {}
		}

		await expect(
			intercept(
				new TenantDecryptFieldsInterceptor(fields, new Reflector()),
				Controller.prototype.response,
				{},
			),
		).rejects.toMatchObject({ code: "FIELD_POLICY", message: "The response DTO type is invalid." });
	});

	it("normalizes class-transformer failures to a field-policy error", async () => {
		const { fields } = services();
		class Controller {
			@DecryptTenantFieldsAs(() => InvalidTransformResponseDto)
			response(this: void): void {}
		}

		await expect(
			intercept(
				new TenantDecryptFieldsInterceptor(fields, new Reflector()),
				Controller.prototype.response,
				{},
			),
		).rejects.toMatchObject({
			code: "FIELD_POLICY",
			message: "The response could not be mapped to its DTO type.",
		});
	});

	it("preserves crypto errors raised during response transformation", async () => {
		const { fields } = services();
		class Controller {
			@DecryptTenantFieldsAs(() => CryptoErrorResponseDto)
			response(this: void): void {}
		}

		await expect(
			intercept(
				new TenantDecryptFieldsInterceptor(fields, new Reflector()),
				Controller.prototype.response,
				{},
			),
		).rejects.toBe(RESPONSE_CRYPTO_ERROR);
	});

	it("propagates missing tenant context on decorated object responses", async () => {
		const { context, fields } = services();
		context.available = false;
		class Controller {
			@DecryptTenantFieldsAs(() => ResponseDto)
			response(this: void): void {}
		}

		await expect(
			intercept(
				new TenantDecryptFieldsInterceptor(fields, new Reflector()),
				Controller.prototype.response,
				{ secret: "ciphertext", nested: { secret: "ciphertext" } },
			),
		).rejects.toMatchObject({ code: "TENANT_POLICY" });
	});
});
