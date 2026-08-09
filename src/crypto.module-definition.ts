import { ConfigurableModuleBuilder } from "@nestjs/common";
import type { CryptoModuleExtras, CryptoModuleOptions } from "./crypto.types.js";

export const { ConfigurableModuleClass, MODULE_OPTIONS_TOKEN, OPTIONS_TYPE, ASYNC_OPTIONS_TYPE } =
	new ConfigurableModuleBuilder<CryptoModuleOptions>()
		.setClassMethodName("forRoot")
		.setFactoryMethodName("createCryptoOptions")
		.setExtras<CryptoModuleExtras>({ isGlobal: false }, (definition, extras) => ({
			...definition,
			global: extras.isGlobal === true,
		}))
		.build();

export type CryptoForRootOptions = typeof OPTIONS_TYPE;
export type CryptoForRootAsyncOptions = typeof ASYNC_OPTIONS_TYPE;
