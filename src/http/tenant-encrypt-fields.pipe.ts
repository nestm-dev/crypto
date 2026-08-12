import { Inject, Injectable, Optional } from "@nestjs/common";
import type { ArgumentMetadata, PipeTransform } from "@nestjs/common";
import { CryptoError } from "../core/index.js";
import { TenantFieldCipherService, type TenantFieldCipherOptions } from "../tenant/index.js";
import { captureTenantFieldCipherOptions } from "./http-options.js";
import { TENANT_ENCRYPT_FIELDS_PIPE_OPTIONS } from "./http.tokens.js";

export type TenantEncryptFieldsPipeOptions = TenantFieldCipherOptions;

@Injectable()
export class TenantEncryptFieldsPipe implements PipeTransform<unknown, Promise<unknown>> {
	readonly #fields: TenantFieldCipherService;
	readonly #options: Readonly<TenantEncryptFieldsPipeOptions>;

	constructor(
		fields: TenantFieldCipherService,
		@Optional()
		@Inject(TENANT_ENCRYPT_FIELDS_PIPE_OPTIONS)
		options?: TenantEncryptFieldsPipeOptions,
	) {
		this.#fields = fields;
		this.#options = captureTenantFieldCipherOptions(options);
	}

	async transform(value: unknown, metadata: ArgumentMetadata): Promise<unknown> {
		if (metadata.type !== "body") return value;
		if (
			metadata.metatype === undefined ||
			typeof value !== "object" ||
			value === null ||
			!this.#matchesMetatype(value, metadata.metatype)
		) {
			throw new CryptoError("FIELD_POLICY", "A class instance is required for field encryption.");
		}
		return await this.#fields.encryptFieldsInPlace(value, this.#options);
	}

	#matchesMetatype(value: object, metatype: NonNullable<ArgumentMetadata["metatype"]>): boolean {
		try {
			return value instanceof metatype;
		} catch {
			return false;
		}
	}
}
