import type { FactoryProvider, InjectionToken, ModuleMetadata, Type } from "@nestjs/common";
import type { TenantSettings, TenantSnapshot, TenantTargetAuthority } from "@nestm/tenant/context";
import type { CipherAad, CipherEnvelopeInfo } from "../core/index.js";

export interface TenantCryptoProfile {
	readonly writeProvider: string;
	readonly readProviders?: readonly string[];
}

export interface TenantCryptoPolicyContext<Settings = TenantSettings> {
	readonly tenant: TenantSnapshot<Settings>;
	readonly authority: TenantTargetAuthority;
}

export interface TenantCryptoPolicy<Settings = TenantSettings> {
	resolve(
		context: TenantCryptoPolicyContext<Settings>,
	): TenantCryptoProfile | Promise<TenantCryptoProfile>;
}

export type TenantCryptoProviderDefinition<Value> =
	| Value
	| Type<Value>
	| Readonly<{ useValue: Value }>
	| Readonly<{ useClass: Type<Value> }>
	| Readonly<{ useExisting: InjectionToken<Value> }>
	| Readonly<{
			useFactory: FactoryProvider<Value>["useFactory"];
			inject?: FactoryProvider<Value>["inject"];
	  }>;

export interface TenantCryptoModuleOptions {
	readonly namespace: string;
	readonly policy?: TenantCryptoProviderDefinition<TenantCryptoPolicy>;
}

export interface TenantCryptoForRootOptions extends TenantCryptoModuleOptions {
	readonly imports?: ModuleMetadata["imports"];
	readonly isGlobal?: boolean;
}

export interface TenantCryptoForRootAsyncOptions extends Pick<
	ModuleMetadata,
	"imports" | "providers"
> {
	readonly inject?: FactoryProvider<TenantCryptoModuleOptions>["inject"];
	readonly useFactory: FactoryProvider<TenantCryptoModuleOptions>["useFactory"];
	readonly isGlobal?: boolean;
}

export interface TenantCipherOperationOptions {
	readonly purpose: string;
	readonly aad?: CipherAad;
	readonly signal?: AbortSignal;
}

export interface TenantBatchOptions {
	readonly signal?: AbortSignal;
}

export interface TenantBatchEncryptTextItem {
	readonly plaintext: string;
	readonly purpose: string;
	readonly aad?: CipherAad;
}

export interface TenantBatchDecryptTextItem {
	readonly envelope: string;
	readonly purpose: string;
	readonly aad?: CipherAad;
}

export interface TenantProtectTextItem {
	readonly value: string;
	readonly purpose: string;
	readonly aad?: CipherAad;
}

export interface TenantFieldCipherOptions {
	readonly aad?: CipherAad;
	readonly signal?: AbortSignal;
	readonly maxDepth?: number;
}

export interface TenantFieldDecryptOptions extends TenantFieldCipherOptions {
	readonly legacyPlaintext?: "reject" | "allow";
}

export type TenantCipherEnvelopeInfo = CipherEnvelopeInfo;
