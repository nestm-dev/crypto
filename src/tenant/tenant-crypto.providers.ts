import { ModuleRef } from "@nestjs/core";
import type { FactoryProvider, Type } from "@nestjs/common";
import { CryptoError } from "../core/index.js";
import { TENANT_CRYPTO_OPTIONS, TENANT_CRYPTO_POLICY } from "./tenant-crypto.tokens.js";
import type {
	TenantCryptoModuleOptions,
	TenantCryptoPolicy,
	TenantCryptoProviderDefinition,
} from "./tenant-crypto.types.js";

type RuntimeToken = string | symbol | Type<unknown> | Function;

function record(value: unknown): Record<PropertyKey, unknown> | undefined {
	return typeof value === "object" && value !== null
		? (value as Record<PropertyKey, unknown>)
		: undefined;
}

function own(value: Record<PropertyKey, unknown>, key: PropertyKey): boolean {
	return Object.prototype.hasOwnProperty.call(value, key);
}

function token(value: unknown): RuntimeToken {
	if (typeof value === "string" || typeof value === "symbol" || typeof value === "function") {
		return value;
	}
	throw new CryptoError("CONFIGURATION", "A tenant crypto injection token is invalid.");
}

async function dependency(moduleRef: ModuleRef, value: unknown): Promise<unknown> {
	const descriptor = record(value);
	const optional = descriptor?.optional === true;
	const runtimeToken = token(descriptor && own(descriptor, "token") ? descriptor.token : value);
	try {
		return moduleRef.get<unknown>(runtimeToken, { strict: false });
	} catch (error: unknown) {
		if (optional) return undefined;
		throw error;
	}
}

async function resolveDefinition<Value>(
	definition: TenantCryptoProviderDefinition<Value>,
	moduleRef: ModuleRef,
): Promise<Value> {
	if (typeof definition === "function") return moduleRef.create(definition as Type<Value>);
	const descriptor = record(definition);
	if (!descriptor) return definition as Value;
	if (own(descriptor, "useValue")) return descriptor.useValue as Value;
	if (own(descriptor, "useExisting")) {
		return moduleRef.get<Value>(token(descriptor.useExisting), { strict: false });
	}
	if (own(descriptor, "useClass")) {
		if (typeof descriptor.useClass !== "function") {
			throw new CryptoError("CONFIGURATION", "Tenant crypto useClass must reference a class.");
		}
		return moduleRef.create(descriptor.useClass as Type<Value>);
	}
	if (own(descriptor, "useFactory")) {
		if (typeof descriptor.useFactory !== "function") {
			throw new CryptoError("CONFIGURATION", "Tenant crypto useFactory must be a function.");
		}
		const dependencies = await Promise.all(
			(Array.isArray(descriptor.inject) ? descriptor.inject : []).map((item) =>
				dependency(moduleRef, item),
			),
		);
		return (await Reflect.apply(descriptor.useFactory, undefined, dependencies)) as Value;
	}
	return definition as Value;
}

export const tenantCryptoPolicyProvider: FactoryProvider<TenantCryptoPolicy | null> = {
	provide: TENANT_CRYPTO_POLICY,
	inject: [TENANT_CRYPTO_OPTIONS, ModuleRef],
	useFactory: async (
		options: TenantCryptoModuleOptions,
		moduleRef: ModuleRef,
	): Promise<TenantCryptoPolicy | null> => {
		if (!options.policy) return null;
		const policy = await resolveDefinition(options.policy, moduleRef);
		if (
			typeof policy !== "object" ||
			policy === null ||
			typeof (policy as { resolve?: unknown }).resolve !== "function"
		) {
			throw new CryptoError("CONFIGURATION", "The tenant crypto policy is invalid.");
		}
		return policy;
	},
};
