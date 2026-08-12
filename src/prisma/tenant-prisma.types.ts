export const TENANT_PRISMA_WRITE_OPERATIONS = Object.freeze([
	"create",
	"update",
	"upsert",
	"createMany",
	"createManyAndReturn",
	"updateMany",
	"updateManyAndReturn",
] as const);

export type TenantPrismaWriteOperation = (typeof TENANT_PRISMA_WRITE_OPERATIONS)[number];

export interface TenantPrismaEncryptedField {
	readonly purpose: string;
}

export type TenantPrismaFieldRegistry = Readonly<
	Record<string, Readonly<Record<string, TenantPrismaEncryptedField>>>
>;

export type TenantPrismaRelationMap = Readonly<Record<string, Readonly<Record<string, string>>>>;

export interface TenantPrismaFieldEncryptionOptions {
	readonly registry: TenantPrismaFieldRegistry;
	readonly relations?: TenantPrismaRelationMap;
	readonly maxDepth?: number;
}

export interface TenantPrismaWriteInput {
	readonly model: string;
	readonly operation: TenantPrismaWriteOperation;
	readonly args: unknown;
}

export interface TenantPrismaWriteProcessor {
	encryptWriteArgs(input: TenantPrismaWriteInput): Promise<void>;
	assertWriteArgsEncrypted(input: TenantPrismaWriteInput): Promise<void>;
}
