import { Injectable } from "@nestjs/common";
import { types as nodeTypes } from "node:util";
import { CipherService } from "../cipher.service.js";
import { aadBytes, CryptoError, decodeUtf8, frame, utf8, type CipherAad } from "../core/index.js";
import { getEncryptedFieldMetadata } from "./encrypted-field.decorator.js";

const FIELD_DOMAIN = utf8("@nestm/crypto/field");
export const FIELD_CIPHER_COMMIT_GUARD: unique symbol = Symbol("@nestm/crypto/field-commit-guard");

export interface FieldCipherOptions {
	readonly aad?: CipherAad;
	readonly keyContext?: CipherAad;
	readonly provider?: string;
	readonly cipher?: string;
	readonly allowedProviders?: readonly string[];
	readonly signal?: AbortSignal;
	readonly maxDepth?: number;
}

export interface FieldDecryptOptions extends FieldCipherOptions {
	readonly legacyPlaintext?: "reject" | "allow";
}

interface FieldReference {
	readonly owner: Record<PropertyKey, unknown>;
	readonly key: string | symbol;
	readonly purpose: string;
	readonly value: string;
}

interface InternalFieldCipherOptions {
	readonly [FIELD_CIPHER_COMMIT_GUARD]?: () => void;
}

interface CapturedFieldCipherOptions {
	readonly aad: Uint8Array;
	readonly keyContext: Uint8Array;
	readonly provider?: string;
	readonly cipher?: string;
	readonly allowedProviders?: readonly string[];
	readonly signal?: AbortSignal;
	readonly maxDepth: number;
	readonly commitGuard?: () => void;
}

function isEnvelopeCandidate(value: string): boolean {
	return value.startsWith("nmc");
}

function assertMaxDepth(value: number | undefined): number {
	const maxDepth = value ?? 5;
	if (!Number.isSafeInteger(maxDepth) || maxDepth < 0 || maxDepth > 100) {
		throw new CryptoError("FIELD_POLICY", "The field traversal depth is invalid.");
	}
	return maxDepth;
}

function isArrayIndex(key: PropertyKey, length: number): boolean {
	if (typeof key !== "string" || !/^(?:0|[1-9]\d*)$/u.test(key)) return false;
	const index = Number(key);
	return Number.isSafeInteger(index) && index >= 0 && index < length;
}

function assertArrayShape(value: readonly unknown[]): void {
	if (Object.getPrototypeOf(value) !== Array.prototype) {
		throw new CryptoError("FIELD_POLICY", "Array subclasses are not supported by field traversal.");
	}
	for (const key of Reflect.ownKeys(value)) {
		if (key !== "length" && !isArrayIndex(key, value.length)) {
			throw new CryptoError(
				"FIELD_POLICY",
				"Arrays with attached properties are not supported by field traversal.",
			);
		}
	}
}

function isIgnoredLeaf(value: object): boolean {
	if (value instanceof Date) {
		if (Object.getPrototypeOf(value) !== Date.prototype || Reflect.ownKeys(value).length !== 0) {
			throw new CryptoError("FIELD_POLICY", "Extended Date values are not supported.");
		}
		return true;
	}
	if (value instanceof RegExp) {
		const keys = Reflect.ownKeys(value);
		if (
			Object.getPrototypeOf(value) !== RegExp.prototype ||
			keys.length !== 1 ||
			keys[0] !== "lastIndex"
		) {
			throw new CryptoError("FIELD_POLICY", "Extended RegExp values are not supported.");
		}
		return true;
	}
	if (value instanceof Uint8Array) {
		const prototype = Object.getPrototypeOf(value) as object | null;
		if (prototype !== Uint8Array.prototype && prototype !== Buffer.prototype) {
			throw new CryptoError("FIELD_POLICY", "Typed-array subclasses are not supported.");
		}
		for (const key of Reflect.ownKeys(value)) {
			if (!isArrayIndex(key, value.length)) {
				throw new CryptoError(
					"FIELD_POLICY",
					"Typed arrays with attached properties are not supported.",
				);
			}
		}
		return true;
	}
	return false;
}

function assertSupportedObject(value: object): void {
	if (Object.prototype.toString.call(value) !== "[object Object]") {
		throw new CryptoError(
			"FIELD_POLICY",
			"Encrypted field traversal encountered an unsupported object container.",
		);
	}
}

function captureOptions(options: FieldCipherOptions): CapturedFieldCipherOptions {
	if (options.allowedProviders !== undefined && !Array.isArray(options.allowedProviders)) {
		throw new CryptoError("FIELD_POLICY", "Allowed field providers must be an array.");
	}
	const aad = aadBytes(options.aad);
	let keyContext: Uint8Array | undefined;
	try {
		keyContext = aadBytes(options.keyContext);
		return Object.freeze({
			aad,
			keyContext,
			...(options.provider === undefined ? {} : { provider: options.provider }),
			...(options.cipher === undefined ? {} : { cipher: options.cipher }),
			...(options.allowedProviders === undefined
				? {}
				: { allowedProviders: Object.freeze([...options.allowedProviders]) }),
			...(options.signal === undefined ? {} : { signal: options.signal }),
			maxDepth: assertMaxDepth(options.maxDepth),
			...((options as FieldCipherOptions & InternalFieldCipherOptions)[
				FIELD_CIPHER_COMMIT_GUARD
			] === undefined
				? {}
				: {
						commitGuard: (options as FieldCipherOptions & InternalFieldCipherOptions)[
							FIELD_CIPHER_COMMIT_GUARD
						],
					}),
		});
	} catch (error: unknown) {
		aad.fill(0);
		keyContext?.fill(0);
		throw error;
	}
}

function releaseOptions(options: CapturedFieldCipherOptions): void {
	options.aad.fill(0);
	options.keyContext.fill(0);
}

function commitFields(fields: readonly FieldReference[], values: readonly string[]): void {
	if (fields.length !== values.length) {
		throw new CryptoError(
			"FIELD_POLICY",
			"Encrypted field transformation returned invalid output.",
		);
	}
	const committed: FieldReference[] = [];
	try {
		for (const [index, field] of fields.entries()) {
			const transformed = values[index];
			if (transformed === undefined || !Reflect.set(field.owner, field.key, transformed)) {
				throw new Error("Field assignment was rejected.");
			}
			committed.push(field);
		}
	} catch (error: unknown) {
		for (const field of committed.toReversed()) {
			try {
				Reflect.set(field.owner, field.key, field.value);
			} catch {
				// The traversal preflight rejects accessors and immutable fields. This is a
				// final best-effort rollback for proxies that change behavior during commit.
			}
		}
		throw new CryptoError("FIELD_POLICY", "An encrypted field could not be updated.", {
			cause: error,
		});
	}
}

function fieldAad(purpose: string, aad?: CipherAad): Uint8Array {
	const callerAad = aadBytes(aad);
	try {
		return frame(FIELD_DOMAIN, utf8(purpose), callerAad);
	} finally {
		callerAad.fill(0);
	}
}

function collectFields(root: object, maxDepth: number): readonly FieldReference[] {
	const references: FieldReference[] = [];
	const visiting = new WeakSet<object>();
	const visited = new WeakSet<object>();

	const visit = (value: object, depth: number): void => {
		if (depth > maxDepth) {
			throw new CryptoError("FIELD_POLICY", "Encrypted field traversal exceeded its depth limit.");
		}
		if (nodeTypes.isProxy(value)) {
			throw new CryptoError("FIELD_POLICY", "Proxy objects are not supported by field traversal.");
		}
		if (visiting.has(value)) {
			throw new CryptoError("FIELD_POLICY", "Encrypted field traversal encountered a cycle.");
		}
		if (visited.has(value) || isIgnoredLeaf(value)) return;
		if (Array.isArray(value)) {
			assertArrayShape(value);
			visiting.add(value);
			for (const item of value) {
				if (typeof item === "object" && item !== null) visit(item, depth + 1);
			}
			visiting.delete(value);
			visited.add(value);
			return;
		}
		assertSupportedObject(value);
		const prototype = Object.getPrototypeOf(value) as object | null;
		if (prototype === Object.prototype || prototype === null) {
			throw new CryptoError(
				"FIELD_POLICY",
				"Plain nested objects are not supported; use class instances so field metadata cannot be skipped.",
			);
		}

		visiting.add(value);
		const owner = value as Record<PropertyKey, unknown>;
		const metadata = getEncryptedFieldMetadata(value);
		const encryptedKeys = new Set(metadata.map(({ propertyKey }) => propertyKey));
		for (const field of metadata) {
			const descriptor = Object.getOwnPropertyDescriptor(value, field.propertyKey);
			if (descriptor === undefined) {
				throw new CryptoError(
					"FIELD_POLICY",
					"An encrypted field must be an own data property, including when undefined.",
				);
			}
			if (!("value" in descriptor) || descriptor.writable === false || Object.isFrozen(value)) {
				throw new CryptoError(
					"FIELD_POLICY",
					"An encrypted field is not a writable data property.",
				);
			}
			const fieldValue = descriptor.value;
			if (fieldValue === null || fieldValue === undefined) continue;
			if (typeof fieldValue !== "string") {
				throw new CryptoError("FIELD_POLICY", "An encrypted field contains an unsupported value.");
			}
			references.push({
				owner,
				key: field.propertyKey,
				purpose: field.purpose,
				value: fieldValue,
			});
		}
		for (const key of Reflect.ownKeys(value)) {
			if (encryptedKeys.has(key)) continue;
			const descriptor = Object.getOwnPropertyDescriptor(value, key);
			if (descriptor === undefined) continue;
			if (!("value" in descriptor)) {
				throw new CryptoError(
					"FIELD_POLICY",
					"Accessor properties are not supported by field traversal.",
				);
			}
			const nested = descriptor.value;
			if (typeof nested === "object" && nested !== null) visit(nested, depth + 1);
		}
		visiting.delete(value);
		visited.add(value);
	};

	visit(root, 0);
	return Object.freeze(references);
}

function assertTraversalUnchanged(
	root: object,
	maxDepth: number,
	expected: readonly FieldReference[],
): void {
	const current = collectFields(root, maxDepth);
	if (
		current.length !== expected.length ||
		current.some((field, index) => {
			const original = expected[index];
			return (
				original === undefined ||
				field.owner !== original.owner ||
				field.key !== original.key ||
				field.purpose !== original.purpose ||
				field.value !== original.value
			);
		})
	) {
		throw new CryptoError(
			"FIELD_POLICY",
			"The object graph changed during encrypted field traversal.",
		);
	}
}

@Injectable()
export class FieldCipherService {
	readonly #cipher: CipherService;

	constructor(cipher: CipherService) {
		this.#cipher = cipher;
	}

	async encryptFieldsInPlace<Value extends object>(
		value: Value,
		options: FieldCipherOptions = {},
	): Promise<Value> {
		const captured = captureOptions(options);
		try {
			return await this.#encryptFieldsInPlace(value, captured);
		} finally {
			releaseOptions(captured);
		}
	}

	async decryptFieldsInPlace<Value extends object>(
		value: Value,
		options: FieldDecryptOptions = {},
	): Promise<Value> {
		const captured = captureOptions(options);
		const legacyPlaintext = options.legacyPlaintext;
		try {
			return await this.#decryptFieldsInPlace(value, captured, legacyPlaintext);
		} finally {
			releaseOptions(captured);
		}
	}

	async #encryptFieldsInPlace<Value extends object>(
		value: Value,
		options: CapturedFieldCipherOptions,
	): Promise<Value> {
		if (typeof value !== "object" || value === null) {
			throw new CryptoError("FIELD_POLICY", "A class instance is required for field encryption.");
		}
		const maxDepth = options.maxDepth;
		const fields = collectFields(value, maxDepth);
		const existing = fields.filter(({ value: fieldValue }) => isEnvelopeCandidate(fieldValue));
		if (existing.length > 0) {
			const batch = existing.map((field) => ({
				envelope: field.value,
				aad: fieldAad(field.purpose, options.aad),
			}));
			let decrypted: readonly Uint8Array[];
			try {
				decrypted = await this.#cipher.decryptBatch(batch, {
					keyContext: options.keyContext,
					...(options.allowedProviders === undefined
						? {}
						: { allowedProviders: options.allowedProviders }),
					...(options.signal === undefined ? {} : { signal: options.signal }),
				});
			} finally {
				for (const item of batch) item.aad.fill(0);
			}
			try {
				for (const plaintext of decrypted) decodeUtf8(plaintext);
			} finally {
				for (const plaintext of decrypted) plaintext.fill(0);
			}
			assertTraversalUnchanged(value, maxDepth, fields);
		}
		const plaintext = fields.filter(({ value: fieldValue }) => !isEnvelopeCandidate(fieldValue));
		if (plaintext.length === 0) {
			options.commitGuard?.();
			assertTraversalUnchanged(value, maxDepth, fields);
			return value;
		}
		const batch = plaintext.map((field) => ({
			plaintext: utf8(field.value),
			aad: fieldAad(field.purpose, options.aad),
		}));
		let encrypted: readonly string[];
		try {
			encrypted = await this.#cipher.encryptBatch(batch, {
				keyContext: options.keyContext,
				...(options.provider === undefined ? {} : { provider: options.provider }),
				...(options.cipher === undefined ? {} : { cipher: options.cipher }),
				...(options.signal === undefined ? {} : { signal: options.signal }),
			});
		} finally {
			for (const item of batch) {
				item.plaintext.fill(0);
				item.aad.fill(0);
			}
		}
		options.commitGuard?.();
		assertTraversalUnchanged(value, maxDepth, fields);
		commitFields(plaintext, encrypted);
		return value;
	}

	async #decryptFieldsInPlace<Value extends object>(
		value: Value,
		options: CapturedFieldCipherOptions,
		legacyPlaintext: FieldDecryptOptions["legacyPlaintext"],
	): Promise<Value> {
		if (typeof value !== "object" || value === null) {
			throw new CryptoError("FIELD_POLICY", "A class instance is required for field decryption.");
		}
		const maxDepth = options.maxDepth;
		const fields = collectFields(value, maxDepth);
		const encrypted = fields.filter(({ value: fieldValue }) => isEnvelopeCandidate(fieldValue));
		const plaintext = fields.filter(({ value: fieldValue }) => !isEnvelopeCandidate(fieldValue));
		if (plaintext.length > 0 && legacyPlaintext !== "allow") {
			throw new CryptoError("FIELD_POLICY", "An encrypted field contains legacy plaintext.");
		}
		if (encrypted.length === 0) {
			options.commitGuard?.();
			assertTraversalUnchanged(value, maxDepth, fields);
			return value;
		}
		const batch = encrypted.map((field) => ({
			envelope: field.value,
			aad: fieldAad(field.purpose, options.aad),
		}));
		let decrypted: readonly Uint8Array[];
		try {
			decrypted = await this.#cipher.decryptBatch(batch, {
				keyContext: options.keyContext,
				...(options.allowedProviders === undefined
					? {}
					: { allowedProviders: options.allowedProviders }),
				...(options.signal === undefined ? {} : { signal: options.signal }),
			});
		} finally {
			for (const item of batch) item.aad.fill(0);
		}
		let transformed: readonly string[];
		try {
			transformed = decrypted.map((bytes) => decodeUtf8(bytes));
		} finally {
			for (const bytes of decrypted) bytes.fill(0);
		}
		options.commitGuard?.();
		assertTraversalUnchanged(value, maxDepth, fields);
		commitFields(encrypted, transformed);
		return value;
	}
}
