import { Injectable } from "@nestjs/common";
import { aadBytes, frame } from "../core/index.js";
import { FieldCipherService } from "../fields/index.js";
import { FIELD_CIPHER_COMMIT_GUARD } from "../fields/field-cipher.service.js";
import {
	normalizeTenantAuthentication,
	TenantCryptoScopeService,
} from "./tenant-cipher.service.js";
import type { TenantFieldCipherOptions, TenantFieldDecryptOptions } from "./tenant-crypto.types.js";

@Injectable()
export class TenantFieldCipherService {
	readonly #fields: FieldCipherService;
	readonly #scope: TenantCryptoScopeService;

	constructor(fields: FieldCipherService, scope: TenantCryptoScopeService) {
		this.#fields = fields;
		this.#scope = scope;
	}

	async encryptFieldsInPlace<Value extends object>(
		value: Value,
		options: TenantFieldCipherOptions = {},
	): Promise<Value> {
		const callerAad = aadBytes(options.aad);
		const signal = options.signal;
		const maxDepth = options.maxDepth;
		try {
			const context = await this.#scope.resolve(signal);
			this.#scope.assertActive(context);
			const fieldOptions = {
				aad: frame(context.tenantScope, callerAad),
				keyContext: context.keyContext,
				provider: context.writeProvider,
				allowedProviders: context.readProviders,
				...(signal === undefined ? {} : { signal }),
				...(maxDepth === undefined ? {} : { maxDepth }),
				[FIELD_CIPHER_COMMIT_GUARD]: () => this.#scope.assertActive(context),
			};
			const result = await normalizeTenantAuthentication(() =>
				this.#fields.encryptFieldsInPlace(value, fieldOptions),
			);
			this.#scope.assertActive(context);
			return result;
		} finally {
			callerAad.fill(0);
		}
	}

	async decryptFieldsInPlace<Value extends object>(
		value: Value,
		options: TenantFieldDecryptOptions = {},
	): Promise<Value> {
		const callerAad = aadBytes(options.aad);
		const signal = options.signal;
		const maxDepth = options.maxDepth;
		const legacyPlaintext = options.legacyPlaintext;
		try {
			const context = await this.#scope.resolve(signal);
			this.#scope.assertActive(context);
			const fieldOptions = {
				aad: frame(context.tenantScope, callerAad),
				keyContext: context.keyContext,
				allowedProviders: context.readProviders,
				...(signal === undefined ? {} : { signal }),
				...(maxDepth === undefined ? {} : { maxDepth }),
				...(legacyPlaintext === undefined ? {} : { legacyPlaintext }),
				[FIELD_CIPHER_COMMIT_GUARD]: () => this.#scope.assertActive(context),
			};
			const result = await normalizeTenantAuthentication(() =>
				this.#fields.decryptFieldsInPlace(value, fieldOptions),
			);
			this.#scope.assertActive(context);
			return result;
		} finally {
			callerAad.fill(0);
		}
	}
}
