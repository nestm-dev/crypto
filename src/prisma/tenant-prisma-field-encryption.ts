import { types as nodeTypes } from "node:util";
import { CryptoError } from "../core/index.js";
import type { TenantCipherService } from "../tenant/index.js";
import {
	type TenantPrismaEncryptedField,
	type TenantPrismaFieldEncryptionOptions,
	type TenantPrismaWriteInput,
	type TenantPrismaWriteOperation,
	type TenantPrismaWriteProcessor,
} from "./tenant-prisma.types.js";

const DEFAULT_MAX_DEPTH = 5;
const MAX_MAX_DEPTH = 100;
const SAFE_RELATION_OPERATIONS = new Set(["connect", "disconnect", "set", "delete", "deleteMany"]);

interface DataDescriptor {
	readonly configurable?: boolean;
	readonly enumerable?: boolean;
	readonly value?: unknown;
	readonly writable?: boolean;
}

interface CapturedOptions {
	readonly registry: ReadonlyMap<string, ReadonlyMap<string, TenantPrismaEncryptedField>>;
	readonly relations: ReadonlyMap<string, ReadonlyMap<string, string>>;
	readonly maxDepth: number;
}

interface CapturedInput {
	readonly source: object;
	readonly model: string;
	readonly operation: TenantPrismaWriteOperation;
	readonly args: object;
}

interface FieldReference {
	readonly owner: object;
	readonly key: string;
	readonly purpose: string;
	readonly value: string | null | undefined;
}

interface TraversalSnapshot {
	readonly source: object;
	readonly model: string;
	readonly operation: TenantPrismaWriteOperation;
	readonly args: object;
	readonly fields: readonly FieldReference[];
}

function configurationError(message: string, cause?: unknown): CryptoError {
	return new CryptoError("CONFIGURATION", message, cause === undefined ? undefined : { cause });
}

function fieldPolicyError(message: string, cause?: unknown): CryptoError {
	return new CryptoError("FIELD_POLICY", message, cause === undefined ? undefined : { cause });
}

function dataDescriptor(value: object, key: PropertyKey): DataDescriptor | undefined {
	return Object.getOwnPropertyDescriptor(value, key);
}

function assertPlainRecord(
	value: unknown,
	error: (message: string, cause?: unknown) => CryptoError,
	message: string,
): asserts value is object {
	try {
		if (
			typeof value !== "object" ||
			value === null ||
			Array.isArray(value) ||
			nodeTypes.isProxy(value)
		) {
			throw new TypeError("A plain record is required.");
		}
		const prototype = Reflect.getPrototypeOf(value);
		if (prototype !== Object.prototype && prototype !== null) {
			throw new TypeError("A plain record is required.");
		}
		for (const key of Reflect.ownKeys(value)) {
			if (typeof key !== "string") throw new TypeError("Symbol properties are unsupported.");
			const descriptor = dataDescriptor(value, key);
			if (descriptor === undefined || !("value" in descriptor)) {
				throw new TypeError("Accessor properties are unsupported.");
			}
		}
	} catch (cause: unknown) {
		if (cause instanceof CryptoError) throw cause;
		throw error(message, cause);
	}
}

function assertDenseArray(value: unknown, message: string): asserts value is readonly unknown[] {
	try {
		if (!Array.isArray(value) || nodeTypes.isProxy(value)) {
			throw new TypeError("An array is required.");
		}
		if (Object.getPrototypeOf(value) !== Array.prototype) {
			throw new TypeError("Array subclasses are unsupported.");
		}
		for (const key of Reflect.ownKeys(value)) {
			if (key === "length") continue;
			if (typeof key !== "string" || !/^(?:0|[1-9]\d*)$/u.test(key)) {
				throw new TypeError("Arrays with attached properties are unsupported.");
			}
			const index = Number(key);
			if (!Number.isSafeInteger(index) || index < 0 || index >= value.length) {
				throw new TypeError("An array index is invalid.");
			}
			const descriptor = dataDescriptor(value, key);
			if (descriptor === undefined || !("value" in descriptor)) {
				throw new TypeError("Array accessors are unsupported.");
			}
		}
		for (let index = 0; index < value.length; index += 1) {
			if (!Object.prototype.hasOwnProperty.call(value, index)) {
				throw new TypeError("Sparse arrays are unsupported.");
			}
		}
	} catch (cause: unknown) {
		if (cause instanceof CryptoError) throw cause;
		throw fieldPolicyError(message, cause);
	}
}

function ownValue(value: object, key: string): unknown {
	const descriptor = dataDescriptor(value, key);
	return descriptor === undefined ? undefined : descriptor.value;
}

function requiredOwnValue(value: object, key: string, message: string): unknown {
	const descriptor = dataDescriptor(value, key);
	if (descriptor === undefined) throw fieldPolicyError(message);
	return descriptor.value;
}

function ownKeys(value: object): readonly string[] {
	return Reflect.ownKeys(value).map((key) => {
		if (typeof key !== "string") throw fieldPolicyError("Prisma write arguments are ambiguous.");
		return key;
	});
}

function assertOnlyKeys(value: object, allowed: ReadonlySet<string>, message: string): void {
	if (ownKeys(value).some((key) => !allowed.has(key))) throw fieldPolicyError(message);
}

function assertIdentifier(value: unknown, label: string): asserts value is string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		Buffer.byteLength(value, "utf8") > 255 ||
		value.trim() !== value ||
		/\p{Cc}/u.test(value)
	) {
		throw configurationError(`A Prisma ${label} identifier is invalid.`);
	}
}

function assertPurpose(value: unknown): asserts value is string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		Buffer.byteLength(value, "utf8") > 255 ||
		value.trim() !== value ||
		/\p{Cc}/u.test(value)
	) {
		throw configurationError("A Prisma encrypted-field purpose is invalid.");
	}
}

function captureMaxDepth(value: unknown): number {
	const maxDepth = value ?? DEFAULT_MAX_DEPTH;
	if (
		!Number.isSafeInteger(maxDepth) ||
		typeof maxDepth !== "number" ||
		maxDepth < 0 ||
		maxDepth > MAX_MAX_DEPTH
	) {
		throw configurationError("The Prisma relation traversal depth is invalid.");
	}
	return maxDepth;
}

function captureRegistry(
	value: unknown,
): ReadonlyMap<string, ReadonlyMap<string, TenantPrismaEncryptedField>> {
	assertPlainRecord(value, configurationError, "The Prisma encrypted-field registry is invalid.");
	const registry = new Map<string, ReadonlyMap<string, TenantPrismaEncryptedField>>();
	for (const model of ownKeys(value)) {
		assertIdentifier(model, "model");
		const unresolvedFields = ownValue(value, model);
		assertPlainRecord(
			unresolvedFields,
			configurationError,
			"A Prisma model field registry is invalid.",
		);
		const fields = new Map<string, TenantPrismaEncryptedField>();
		for (const field of ownKeys(unresolvedFields)) {
			assertIdentifier(field, "field");
			const unresolvedDefinition = ownValue(unresolvedFields, field);
			assertPlainRecord(
				unresolvedDefinition,
				configurationError,
				"A Prisma encrypted-field definition is invalid.",
			);
			if (
				ownKeys(unresolvedDefinition).length !== 1 ||
				dataDescriptor(unresolvedDefinition, "purpose") === undefined
			) {
				throw configurationError("A Prisma encrypted-field definition is invalid.");
			}
			const purpose = ownValue(unresolvedDefinition, "purpose");
			assertPurpose(purpose);
			fields.set(field, Object.freeze({ purpose }));
		}
		registry.set(model, fields);
	}
	return registry;
}

function captureRelations(value: unknown): ReadonlyMap<string, ReadonlyMap<string, string>> {
	if (value === undefined) return new Map();
	assertPlainRecord(value, configurationError, "The Prisma relation map is invalid.");
	const relations = new Map<string, ReadonlyMap<string, string>>();
	for (const model of ownKeys(value)) {
		assertIdentifier(model, "model");
		const unresolvedModelRelations = ownValue(value, model);
		assertPlainRecord(
			unresolvedModelRelations,
			configurationError,
			"A Prisma model relation map is invalid.",
		);
		const modelRelations = new Map<string, string>();
		for (const relation of ownKeys(unresolvedModelRelations)) {
			assertIdentifier(relation, "relation");
			const childModel = ownValue(unresolvedModelRelations, relation);
			assertIdentifier(childModel, "model");
			modelRelations.set(relation, childModel);
		}
		relations.set(model, modelRelations);
	}
	return relations;
}

function captureOptions(options: TenantPrismaFieldEncryptionOptions): CapturedOptions {
	assertPlainRecord(options, configurationError, "Prisma field-encryption options are invalid.");
	if (
		ownKeys(options).some((key) => key !== "registry" && key !== "relations" && key !== "maxDepth")
	) {
		throw configurationError("Prisma field-encryption options contain an unknown property.");
	}
	const registry = captureRegistry(ownValue(options, "registry"));
	const relations = captureRelations(ownValue(options, "relations"));
	const maxDepth = captureMaxDepth(ownValue(options, "maxDepth"));
	for (const [model, fields] of registry) {
		const modelRelations = relations.get(model);
		if (modelRelations === undefined) continue;
		for (const field of fields.keys()) {
			if (modelRelations.has(field)) {
				throw configurationError("A Prisma property cannot be both encrypted and relational.");
			}
		}
	}
	for (const modelRelations of relations.values()) {
		for (const childModel of modelRelations.values()) {
			if (!registry.has(childModel) && !relations.has(childModel)) {
				throw configurationError("A Prisma relation target model is not registered.");
			}
		}
	}
	return Object.freeze({ registry, relations, maxDepth });
}

function isWriteOperation(value: unknown): value is TenantPrismaWriteOperation {
	return (
		value === "create" ||
		value === "update" ||
		value === "upsert" ||
		value === "createMany" ||
		value === "createManyAndReturn" ||
		value === "updateMany" ||
		value === "updateManyAndReturn"
	);
}

type TenantPrismaNestedWriteOperation = Exclude<
	TenantPrismaWriteOperation,
	"createManyAndReturn" | "updateManyAndReturn"
>;

function isNestedWriteOperation(value: unknown): value is TenantPrismaNestedWriteOperation {
	return (
		value === "create" ||
		value === "update" ||
		value === "upsert" ||
		value === "createMany" ||
		value === "updateMany"
	);
}

function captureInput(input: TenantPrismaWriteInput): CapturedInput {
	assertPlainRecord(input, fieldPolicyError, "Prisma write input is invalid.");
	const model = requiredOwnValue(input, "model", "A Prisma write model is required.");
	const operation = requiredOwnValue(input, "operation", "A Prisma write operation is required.");
	const args = requiredOwnValue(input, "args", "Prisma write arguments are required.");
	if (typeof model !== "string" || model.length === 0) {
		throw fieldPolicyError("A Prisma write model is required.");
	}
	if (!isWriteOperation(operation)) {
		throw fieldPolicyError("The Prisma write operation is unsupported.");
	}
	assertPlainRecord(args, fieldPolicyError, "Prisma write arguments are invalid.");
	return Object.freeze({ source: input, model, operation, args });
}

class WriteCollector {
	readonly #options: CapturedOptions;
	readonly #seen = new WeakSet<object>();
	readonly #fields: FieldReference[] = [];

	constructor(options: CapturedOptions) {
		this.#options = options;
	}

	collect(input: TenantPrismaWriteInput): TraversalSnapshot {
		const captured = captureInput(input);
		if (!this.#hasModelWork(captured.model)) {
			return Object.freeze({ ...captured, fields: Object.freeze([]) });
		}
		this.#claim(captured.args);
		switch (captured.operation) {
			case "create":
			case "update":
			case "updateMany":
			case "updateManyAndReturn":
				this.#visitModelData(
					captured.model,
					requiredOwnValue(captured.args, "data", "Prisma write data is required."),
					0,
					false,
				);
				break;
			case "createMany":
			case "createManyAndReturn":
				this.#visitModelData(
					captured.model,
					requiredOwnValue(captured.args, "data", "Prisma createMany data is required."),
					0,
					true,
				);
				break;
			case "upsert":
				this.#visitModelData(
					captured.model,
					requiredOwnValue(captured.args, "create", "Prisma upsert create data is required."),
					0,
					false,
				);
				this.#visitModelData(
					captured.model,
					requiredOwnValue(captured.args, "update", "Prisma upsert update data is required."),
					0,
					false,
				);
				break;
		}
		return Object.freeze({ ...captured, fields: Object.freeze(this.#fields) });
	}

	#hasModelWork(model: string): boolean {
		return this.#options.registry.has(model) || this.#options.relations.has(model);
	}

	#claim(value: object): void {
		if (this.#seen.has(value)) {
			throw fieldPolicyError("Prisma write traversal encountered a cycle or shared container.");
		}
		this.#seen.add(value);
	}

	#visitModelData(model: string, value: unknown, depth: number, allowArray: boolean): void {
		if (depth > this.#options.maxDepth) {
			throw fieldPolicyError("Prisma relation traversal exceeded its depth limit.");
		}
		if (Array.isArray(value)) {
			if (!allowArray) throw fieldPolicyError("Prisma write data has an unsupported array shape.");
			assertDenseArray(value, "Prisma write data has an invalid array shape.");
			this.#claim(value);
			for (const item of value) this.#visitModelData(model, item, depth, false);
			return;
		}
		assertPlainRecord(value, fieldPolicyError, "Prisma model write data is invalid.");
		this.#claim(value);
		this.#collectFields(model, value);
		this.#visitRelations(model, value, depth);
	}

	#collectFields(model: string, data: object): void {
		const definitions = this.#options.registry.get(model);
		if (definitions === undefined) return;
		for (const [field, definition] of definitions) {
			const descriptor = dataDescriptor(data, field);
			if (descriptor === undefined) continue;
			this.#collectFieldValue(data, field, descriptor, definition.purpose);
		}
	}

	#collectFieldValue(
		owner: object,
		key: string,
		descriptor: DataDescriptor,
		purpose: string,
	): void {
		const value = descriptor.value;
		if (value === null || value === undefined) {
			this.#fields.push(Object.freeze({ owner, key, purpose, value }));
			return;
		}
		if (typeof value === "string") {
			if (descriptor.writable !== true || Object.isFrozen(owner)) {
				throw fieldPolicyError("A registered Prisma encrypted field is not writable.");
			}
			this.#fields.push(Object.freeze({ owner, key, purpose, value }));
			return;
		}
		assertPlainRecord(
			value,
			fieldPolicyError,
			"A registered Prisma encrypted field has an invalid shape.",
		);
		this.#claim(value);
		const setDescriptor = dataDescriptor(value, "set");
		if (ownKeys(value).length !== 1 || setDescriptor === undefined) {
			throw fieldPolicyError(
				"A registered Prisma encrypted field has an unsupported operation shape.",
			);
		}
		const setValue = setDescriptor.value;
		if (setValue !== null && setValue !== undefined && typeof setValue !== "string") {
			throw fieldPolicyError("A registered Prisma encrypted field contains an unsupported value.");
		}
		if (
			typeof setValue === "string" &&
			(setDescriptor.writable !== true || Object.isFrozen(value))
		) {
			throw fieldPolicyError("A registered Prisma encrypted field operation is not writable.");
		}
		this.#fields.push(Object.freeze({ owner: value, key: "set", purpose, value: setValue }));
	}

	#visitRelations(model: string, data: object, depth: number): void {
		const relations = this.#options.relations.get(model);
		if (relations === undefined) return;
		for (const [relation, childModel] of relations) {
			const descriptor = dataDescriptor(data, relation);
			if (descriptor === undefined || descriptor.value === null || descriptor.value === undefined)
				continue;
			this.#visitRelationEnvelope(childModel, descriptor.value, depth + 1);
		}
	}

	#visitRelationEnvelope(childModel: string, value: unknown, depth: number): void {
		if (depth > this.#options.maxDepth) {
			throw fieldPolicyError("Prisma relation traversal exceeded its depth limit.");
		}
		assertPlainRecord(value, fieldPolicyError, "A Prisma nested relation write is invalid.");
		this.#claim(value);
		for (const operation of ownKeys(value)) {
			const payload = ownValue(value, operation);
			if (payload === null || payload === undefined || SAFE_RELATION_OPERATIONS.has(operation))
				continue;
			if (!isNestedWriteOperation(operation)) {
				throw fieldPolicyError("A Prisma nested relation operation is unsupported.");
			}
			switch (operation) {
				case "create":
					this.#visitModelData(childModel, payload, depth, true);
					break;
				case "createMany":
					this.#visitCreateMany(childModel, payload, depth);
					break;
				case "upsert":
					this.#visitEnvelopeList(payload, "Prisma nested upsert data is invalid.", (entry) => {
						assertOnlyKeys(
							entry,
							new Set(["where", "create", "update"]),
							"Prisma nested upsert data is ambiguous.",
						);
						this.#visitModelData(
							childModel,
							requiredOwnValue(entry, "create", "Prisma nested upsert create data is required."),
							depth,
							false,
						);
						this.#visitModelData(
							childModel,
							requiredOwnValue(entry, "update", "Prisma nested upsert update data is required."),
							depth,
							false,
						);
					});
					break;
				case "update":
					this.#visitNestedUpdate(childModel, payload, depth);
					break;
				case "updateMany":
					this.#visitEnvelopeList(payload, "Prisma nested updateMany data is invalid.", (entry) => {
						assertOnlyKeys(
							entry,
							new Set(["where", "data"]),
							"Prisma nested updateMany data is ambiguous.",
						);
						this.#visitModelData(
							childModel,
							requiredOwnValue(entry, "data", "Prisma nested updateMany data is required."),
							depth,
							false,
						);
					});
					break;
			}
		}
	}

	#visitCreateMany(childModel: string, value: unknown, depth: number): void {
		assertPlainRecord(value, fieldPolicyError, "Prisma nested createMany data is invalid.");
		this.#claim(value);
		assertOnlyKeys(
			value,
			new Set(["data", "skipDuplicates"]),
			"Prisma nested createMany data is ambiguous.",
		);
		const skipDuplicates = ownValue(value, "skipDuplicates");
		if (skipDuplicates !== undefined && typeof skipDuplicates !== "boolean") {
			throw fieldPolicyError("Prisma nested createMany data is invalid.");
		}
		this.#visitModelData(
			childModel,
			requiredOwnValue(value, "data", "Prisma nested createMany data is required."),
			depth,
			true,
		);
	}

	#visitNestedUpdate(childModel: string, value: unknown, depth: number): void {
		if (Array.isArray(value)) {
			assertDenseArray(value, "Prisma nested update data has an invalid array shape.");
			this.#claim(value);
			for (const entry of value) this.#visitUpdateEnvelope(childModel, entry, depth, true);
			return;
		}
		this.#visitUpdateEnvelope(childModel, value, depth, false);
	}

	#visitUpdateEnvelope(
		childModel: string,
		value: unknown,
		depth: number,
		requireEnvelope: boolean,
	): void {
		assertPlainRecord(value, fieldPolicyError, "Prisma nested update data is invalid.");
		const keys = ownKeys(value);
		const hasWhere = dataDescriptor(value, "where") !== undefined;
		const hasData = dataDescriptor(value, "data") !== undefined;
		const configuredDataProperty =
			this.#options.registry.get(childModel)?.has("data") === true ||
			this.#options.relations.get(childModel)?.has("data") === true;
		const dataValue = ownValue(value, "data");
		const implicitEnvelope =
			hasData &&
			keys.length === 1 &&
			!configuredDataProperty &&
			typeof dataValue === "object" &&
			dataValue !== null;
		if (requireEnvelope || hasWhere || implicitEnvelope) {
			this.#claim(value);
			assertOnlyKeys(value, new Set(["where", "data"]), "Prisma nested update data is ambiguous.");
			this.#visitModelData(
				childModel,
				requiredOwnValue(value, "data", "Prisma nested update data is required."),
				depth,
				false,
			);
			return;
		}
		this.#visitModelData(childModel, value, depth, false);
	}

	#visitEnvelopeList(value: unknown, message: string, visit: (entry: object) => void): void {
		if (Array.isArray(value)) {
			assertDenseArray(value, message);
			this.#claim(value);
			for (const item of value) {
				assertPlainRecord(item, fieldPolicyError, message);
				this.#claim(item);
				visit(item);
			}
			return;
		}
		assertPlainRecord(value, fieldPolicyError, message);
		this.#claim(value);
		visit(value);
	}
}

function collectSnapshot(
	options: CapturedOptions,
	input: TenantPrismaWriteInput,
): TraversalSnapshot {
	return new WriteCollector(options).collect(input);
}

function assertTraversalUnchanged(
	options: CapturedOptions,
	input: TenantPrismaWriteInput,
	expected: TraversalSnapshot,
): void {
	const current = collectSnapshot(options, input);
	if (
		current.source !== expected.source ||
		current.model !== expected.model ||
		current.operation !== expected.operation ||
		current.args !== expected.args ||
		current.fields.length !== expected.fields.length ||
		current.fields.some((field, index) => {
			const original = expected.fields[index];
			return (
				original === undefined ||
				field.owner !== original.owner ||
				field.key !== original.key ||
				field.purpose !== original.purpose ||
				field.value !== original.value
			);
		})
	) {
		throw fieldPolicyError("Prisma write arguments changed during field encryption.");
	}
}

function captureTextResults(
	value: readonly string[],
	expectedLength: number,
	message: string,
): readonly string[] {
	assertDenseArray(value, message);
	if (value.length !== expectedLength || value.some((item) => typeof item !== "string")) {
		throw fieldPolicyError(message);
	}
	return Object.freeze([...value]);
}

function commitFields(fields: readonly FieldReference[], values: readonly string[]): void {
	if (fields.length !== values.length) {
		throw fieldPolicyError("Prisma field encryption returned invalid output.");
	}
	const committed: FieldReference[] = [];
	try {
		for (const [index, field] of fields.entries()) {
			const transformed = values[index];
			if (transformed === undefined || !Reflect.set(field.owner, field.key, transformed)) {
				throw new Error("Prisma field assignment was rejected.");
			}
			committed.push(field);
		}
	} catch (cause: unknown) {
		for (const field of committed.toReversed()) {
			try {
				Reflect.set(field.owner, field.key, field.value);
			} catch {
				// Preflight rejects accessors, proxies, and immutable slots. This is a final
				// best-effort rollback for a concurrently changed descriptor.
			}
		}
		throw fieldPolicyError("A Prisma encrypted field could not be updated.", cause);
	}
}

class TenantPrismaWriteProcessorImpl implements TenantPrismaWriteProcessor {
	readonly #cipher: TenantCipherService;
	readonly #options: CapturedOptions;

	constructor(cipher: TenantCipherService, options: CapturedOptions) {
		this.#cipher = cipher;
		this.#options = options;
	}

	async encryptWriteArgs(input: TenantPrismaWriteInput): Promise<void> {
		const snapshot = collectSnapshot(this.#options, input);
		const fields = snapshot.fields.filter(
			(field): field is FieldReference & { readonly value: string } =>
				typeof field.value === "string",
		);
		if (fields.length === 0) return;
		const unresolved = await this.#cipher.protectTextBatch(
			fields.map(({ value, purpose }) => ({ value, purpose })),
		);
		const encrypted = captureTextResults(
			unresolved,
			fields.length,
			"Prisma field encryption returned invalid output.",
		);
		assertTraversalUnchanged(this.#options, input, snapshot);
		commitFields(fields, encrypted);
	}

	async assertWriteArgsEncrypted(input: TenantPrismaWriteInput): Promise<void> {
		const snapshot = collectSnapshot(this.#options, input);
		const fields = snapshot.fields.filter(
			(field): field is FieldReference & { readonly value: string } =>
				typeof field.value === "string",
		);
		const encrypted = fields.filter(({ value }) => value.startsWith("nmc"));
		if (encrypted.length > 0) {
			const unresolved = await this.#cipher.protectTextBatch(
				encrypted.map(({ value, purpose }) => ({ value, purpose })),
			);
			const authenticated = captureTextResults(
				unresolved,
				encrypted.length,
				"Prisma field authentication returned invalid output.",
			);
			if (authenticated.some((value, index) => value !== encrypted[index]?.value)) {
				throw fieldPolicyError("Prisma field authentication returned invalid output.");
			}
			assertTraversalUnchanged(this.#options, input, snapshot);
		}
		if (fields.length !== encrypted.length) {
			throw fieldPolicyError("A registered Prisma encrypted field contains plaintext.");
		}
	}
}

export function createTenantPrismaFieldEncryption(
	cipher: TenantCipherService,
	options: TenantPrismaFieldEncryptionOptions,
): TenantPrismaWriteProcessor {
	return new TenantPrismaWriteProcessorImpl(cipher, captureOptions(options));
}
