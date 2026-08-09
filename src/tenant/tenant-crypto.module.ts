import { Module, type DynamicModule, type Provider } from "@nestjs/common";
import { tenantCryptoPolicyProvider } from "./tenant-crypto.providers.js";
import { TenantCipherService, TenantCryptoScopeService } from "./tenant-cipher.service.js";
import { TENANT_CRYPTO_OPTIONS } from "./tenant-crypto.tokens.js";
import type {
	TenantCryptoForRootAsyncOptions,
	TenantCryptoForRootOptions,
} from "./tenant-crypto.types.js";
import { TenantFieldCipherService } from "./tenant-field-cipher.service.js";

const services: readonly Provider[] = [
	tenantCryptoPolicyProvider,
	TenantCryptoScopeService,
	TenantCipherService,
	TenantFieldCipherService,
];

@Module({})
export class TenantCryptoModule {
	static forRoot(options: TenantCryptoForRootOptions): DynamicModule {
		const { imports, isGlobal, ...moduleOptions } = options;
		return {
			module: TenantCryptoModule,
			global: isGlobal === true,
			imports: imports ?? [],
			providers: [
				{ provide: TENANT_CRYPTO_OPTIONS, useValue: Object.freeze(moduleOptions) },
				...services,
			],
			exports: [TenantCipherService, TenantFieldCipherService],
		};
	}

	static forRootAsync(options: TenantCryptoForRootAsyncOptions): DynamicModule {
		return {
			module: TenantCryptoModule,
			global: options.isGlobal === true,
			imports: options.imports ?? [],
			providers: [
				...(options.providers ?? []),
				{
					provide: TENANT_CRYPTO_OPTIONS,
					inject: options.inject ?? [],
					useFactory: options.useFactory,
				},
				...services,
			],
			exports: [TenantCipherService, TenantFieldCipherService],
		};
	}
}
