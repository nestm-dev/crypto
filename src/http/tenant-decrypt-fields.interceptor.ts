import { Injectable } from "@nestjs/common";
import type { CallHandler, ExecutionContext, NestInterceptor, Type } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { plainToInstance } from "class-transformer";
import type { Observable } from "rxjs";
import { mergeMap } from "rxjs";
import { CryptoError, isCryptoError } from "../core/index.js";
import { TenantFieldCipherService } from "../tenant/index.js";
import {
	TENANT_DECRYPT_FIELDS_METADATA,
	type TenantDecryptFieldsMetadata,
} from "./decrypt-tenant-fields.decorator.js";

function transformResponse<Value extends object>(
	type: Type<Value>,
	value: object,
): Value | Value[] {
	try {
		return plainToInstance(type, value);
	} catch (error: unknown) {
		if (isCryptoError(error)) throw error;
		throw new CryptoError("FIELD_POLICY", "The response could not be mapped to its DTO type.", {
			cause: error,
		});
	}
}

function isDtoType(value: unknown): value is Type<object> {
	if (typeof value !== "function") return false;
	try {
		Reflect.construct(String, [], value);
		return true;
	} catch {
		return false;
	}
}

function resolveResponseType(metadata: TenantDecryptFieldsMetadata): Type<object> {
	try {
		const type: unknown = metadata.type();
		if (!isDtoType(type)) {
			throw new TypeError("The response DTO type factory returned an invalid value.");
		}
		return type;
	} catch (error: unknown) {
		if (isCryptoError(error)) throw error;
		throw new CryptoError("FIELD_POLICY", "The response DTO type is invalid.", { cause: error });
	}
}

@Injectable()
export class TenantDecryptFieldsInterceptor implements NestInterceptor<unknown, unknown> {
	readonly #fields: TenantFieldCipherService;
	readonly #reflector: Reflector;

	constructor(fields: TenantFieldCipherService, reflector: Reflector) {
		this.#fields = fields;
		this.#reflector = reflector;
	}

	intercept(context: ExecutionContext, next: CallHandler<unknown>): Observable<unknown> {
		const metadata = this.#reflector.get<TenantDecryptFieldsMetadata | undefined>(
			TENANT_DECRYPT_FIELDS_METADATA,
			context.getHandler(),
		);
		if (metadata === undefined) return next.handle();

		return next.handle().pipe(
			mergeMap(async (value: unknown) => {
				if (value === null) return null;
				if (typeof value !== "object") {
					throw new CryptoError(
						"FIELD_POLICY",
						"A decorated response must be an object, an array, or null.",
					);
				}
				const transformed = transformResponse(resolveResponseType(metadata), value);
				return await this.#fields.decryptFieldsInPlace(transformed, metadata.options);
			}),
		);
	}
}
