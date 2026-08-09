import type { CipherEngineOptions } from "./core/index.js";

export interface CryptoModuleOptions extends Omit<CipherEngineOptions, "nonceSource"> {}

export interface CryptoModuleExtras {
	readonly isGlobal?: boolean;
}
