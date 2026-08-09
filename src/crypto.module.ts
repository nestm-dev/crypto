import { Module, type DynamicModule, type FactoryProvider } from "@nestjs/common";
import { CipherService } from "./cipher.service.js";
import { CipherEngine } from "./core/index.js";
import {
	ASYNC_OPTIONS_TYPE,
	ConfigurableModuleClass,
	MODULE_OPTIONS_TOKEN,
	OPTIONS_TYPE,
} from "./crypto.module-definition.js";
import { CIPHER_ENGINE } from "./crypto.tokens.js";
import type { CryptoModuleOptions } from "./crypto.types.js";
import { FieldCipherService } from "./fields/field-cipher.service.js";

const engineProvider: FactoryProvider<CipherEngine> = {
	provide: CIPHER_ENGINE,
	inject: [MODULE_OPTIONS_TOKEN],
	useFactory: (options: CryptoModuleOptions) => new CipherEngine(options),
};

@Module({
	providers: [engineProvider, CipherService, FieldCipherService],
	exports: [CIPHER_ENGINE, CipherService, FieldCipherService],
})
export class CryptoModule extends ConfigurableModuleClass {
	static forRoot(options: typeof OPTIONS_TYPE): DynamicModule {
		return super.forRoot(options);
	}

	static forRootAsync(options: typeof ASYNC_OPTIONS_TYPE): DynamicModule {
		return super.forRootAsync(options);
	}
}
