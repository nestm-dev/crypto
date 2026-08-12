import { SetMetadata, type Type } from "@nestjs/common";
import { CryptoError } from "../core/index.js";
import type { TenantFieldDecryptOptions } from "../tenant/index.js";
import { captureTenantFieldDecryptOptions } from "./http-options.js";

export const TENANT_DECRYPT_FIELDS_METADATA: unique symbol = Symbol(
	"@nestm/crypto/http/tenant-decrypt-fields",
);

export interface TenantDecryptFieldsMetadata<Value extends object = object> {
	readonly type: () => Type<Value>;
	readonly options: Readonly<TenantFieldDecryptOptions>;
}

export function DecryptTenantFieldsAs<Value extends object>(
	type: () => Type<Value>,
	options?: TenantFieldDecryptOptions,
): MethodDecorator {
	if (typeof type !== "function") {
		throw new CryptoError("INVALID_ARGUMENT", "A response DTO type factory is required.");
	}
	const metadata: TenantDecryptFieldsMetadata<Value> = Object.freeze({
		type,
		options: captureTenantFieldDecryptOptions(options),
	});
	return SetMetadata(TENANT_DECRYPT_FIELDS_METADATA, metadata);
}
