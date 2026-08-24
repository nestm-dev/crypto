import { randomUUID } from "node:crypto";

import {
	StorageError,
	StorageErrorCode,
	isStorageError,
	type StorageErrorCode as StorageErrorCodeValue,
	type StorageOperationOptions,
} from "@nestm/storage/core";
import type {
	StorageWorkspace,
	StorageWorkspaceBody,
	StorageWorkspaceCopyOptions,
	StorageWorkspaceDeleteOptions,
	StorageWorkspaceEntry,
	StorageWorkspaceFile,
	StorageWorkspaceLimits,
	StorageWorkspaceListOptions,
	StorageWorkspaceMountOptions,
	StorageWorkspaceMutationOptions,
	StorageWorkspacePage,
	StorageWorkspacePermission,
	StorageWorkspaceReadOptions,
	StorageWorkspaceSearchOptions,
	StorageWorkspaceTextFile,
	StorageWorkspaceWriteOptions,
} from "@nestm/storage/workspace";

import type {
	AuthenticatedWorkspaceCipher,
	AuthenticatedWorkspaceCipherContext,
	ProtectedStorageWorkspace,
	ProtectedStorageWorkspaceByteFile,
	ProtectedStorageWorkspacePathSearch,
	ProtectedStorageWorkspaceProtection,
	ProtectStorageWorkspaceOptions,
} from "./types.js";

const OUTER_VERSION = 1 as const;
const OUTER_CONTENT_TYPE = "application/octet-stream";
const CIPHER_ENVELOPE_PREFIX = "nmc1.";
const CONTEXT_DOMAIN = "nestm:crypto:protected-storage-workspace:v1";
const MAX_SCOPE_CONTEXT_BYTES = 4096;
const MAX_POLICY_REVISION_BYTES = 256;
const MAX_CONTENT_TYPE_BYTES = 255;
const MAX_OPERATION_TIMEOUT_MS = 2_147_483_647;
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const textEncoder = new TextEncoder();
const strictTextDecoder = new TextDecoder("utf-8", { fatal: true });
const FORBIDDEN_PERMISSIONS = new Set<StorageWorkspacePermission>(["copy", "move"]);

type ProtectedPurpose = "metadata" | "body";

interface ProtectedOuterObject {
	readonly v: typeof OUTER_VERSION;
	readonly record: string;
	readonly version: string;
	readonly metadata: string;
	readonly content: string;
}

interface ProtectedMetadata {
	readonly contentType: string;
	readonly path: string;
	readonly size: number;
}

interface AuthenticatedMetadata {
	readonly contentType: string;
	readonly outer: ProtectedOuterObject;
	readonly size: number;
}

interface OperationRuntime {
	readonly signal: AbortSignal | undefined;
	readonly timedOut: () => boolean;
	readonly close: () => void;
}

interface CapturedOptions {
	readonly storage: StorageWorkspace;
	readonly cipher: AuthenticatedWorkspaceCipher;
	readonly scopeContext: Uint8Array;
	readonly policyRevision: string;
	readonly limits: Readonly<StorageWorkspaceLimits>;
	readonly maxCiphertextBytes: number;
	readonly maxPlaintextBytes: number;
	readonly signal?: AbortSignal;
	readonly pathSearch: ProtectedStorageWorkspacePathSearch;
}

/**
 * Build a strict encrypted-only view over an existing StorageWorkspace.
 *
 * The backing workspace remains the authority for paths, CAS, cursors, and
 * provider access. This wrapper owns only authenticated serialization and
 * logical plaintext projection.
 */
export function protectStorageWorkspace(
	options: ProtectStorageWorkspaceOptions,
): ProtectedStorageWorkspace {
	const captured = captureOptions(options);
	try {
		captured.signal?.throwIfAborted();
	} catch {
		captured.scopeContext.fill(0);
		throw protectedError(StorageErrorCode.ABORTED, "protect", undefined, {
			aborted: true,
		});
	}
	try {
		return new ProtectedStorageWorkspaceImplementation(captured, "");
	} finally {
		captured.scopeContext.fill(0);
	}
}

class ProtectedStorageWorkspaceImplementation implements ProtectedStorageWorkspace {
	readonly #storage: StorageWorkspace;
	readonly #cipher: AuthenticatedWorkspaceCipher;
	readonly #scopeContext: Uint8Array;
	readonly #policyRevision: string;
	readonly #directory: string;
	readonly #maxCiphertextBytes: number;
	readonly #maxPlaintextBytes: number;
	readonly #lifetimeSignal: AbortSignal | undefined;
	readonly #pathSearch: ProtectedStorageWorkspacePathSearch;
	readonly limits: Readonly<StorageWorkspaceLimits>;
	readonly protection: Readonly<ProtectedStorageWorkspaceProtection>;

	constructor(options: CapturedOptions, directory: string) {
		this.#storage = options.storage;
		this.#cipher = options.cipher;
		this.#scopeContext = new Uint8Array(options.scopeContext);
		this.#policyRevision = options.policyRevision;
		this.#directory = directory;
		this.#maxCiphertextBytes = options.maxCiphertextBytes;
		this.#maxPlaintextBytes = options.maxPlaintextBytes;
		this.#lifetimeSignal = options.signal;
		this.#pathSearch = options.pathSearch;
		this.limits = Object.freeze({ ...options.limits });
		this.protection = Object.freeze({
			body: "encrypted",
			cipherEnvelope: "nmc1",
			kind: "authenticated-encryption",
			metadata: "encrypted",
			outerFormat: "nestm-protected-storage-workspace",
			outerVersion: OUTER_VERSION,
			pathBinding: "scope-policy-path-record-version-purpose",
			pathSearch: options.pathSearch,
			policyRevision: options.policyRevision,
		});
		Object.freeze(this);
	}

	get permissions(): ReadonlySet<StorageWorkspacePermission> {
		return new Set(
			[...this.#storage.permissions].filter((permission) => this.#permissionAllowed(permission)),
		);
	}

	allows(permission: StorageWorkspacePermission): boolean {
		return this.#permissionAllowed(permission);
	}

	async stat(path: string, options?: StorageOperationOptions): Promise<StorageWorkspaceFile> {
		return await this.#operate("stat", path, options, async (runtime) => {
			this.#require("read", "stat", path);
			const stored = await this.#readStored(path, options, runtime.signal);
			const metadata = await this.#decryptMetadata(path, stored.text, runtime.signal);
			return logicalFile(path, metadata, stored);
		});
	}

	async readText(
		path: string,
		options?: StorageWorkspaceReadOptions,
	): Promise<StorageWorkspaceTextFile> {
		return await this.#operate("read", path, options, async (runtime) => {
			this.#require("read", "read", path);
			const file = await this.#readBytes(path, options, runtime.signal);
			try {
				return { ...withoutBytes(file), text: strictTextDecoder.decode(file.bytes) };
			} catch {
				throw protectedError(StorageErrorCode.INVALID_ARGUMENT, "read", path, { permanent: true });
			} finally {
				file.bytes.fill(0);
			}
		});
	}

	async readBytes(
		path: string,
		options?: StorageWorkspaceReadOptions,
	): Promise<ProtectedStorageWorkspaceByteFile> {
		return await this.#operate("read", path, options, async (runtime) => {
			this.#require("read", "read", path);
			return await this.#readBytes(path, options, runtime.signal);
		});
	}

	async list(options?: StorageWorkspaceListOptions): Promise<StorageWorkspacePage> {
		return await this.#operate("list", options?.directory, options, async (runtime) => {
			this.#require("list", "list", options?.directory);
			const page = await this.#storage.list(listOptions(options, runtime.signal));
			return await this.#authenticatePage(page, operationOptions(options, runtime.signal));
		});
	}

	async search(
		query: string,
		options?: StorageWorkspaceSearchOptions,
	): Promise<StorageWorkspacePage> {
		return await this.#operate("search", options?.directory, options, async (runtime) => {
			if (this.#pathSearch !== "provider-visible") {
				throw protectedError(StorageErrorCode.NOT_SUPPORTED, "search", options?.directory, {
					permanent: true,
				});
			}
			this.#require("search", "search", options?.directory);
			const page = await this.#storage.search(query, searchOptions(options, runtime.signal));
			return await this.#authenticatePage(page, operationOptions(options, runtime.signal));
		});
	}

	async writeFile(
		path: string,
		body: StorageWorkspaceBody,
		options: StorageWorkspaceWriteOptions,
	): Promise<StorageWorkspaceFile> {
		return await this.#operate("write", path, options, async (runtime) => {
			const mode = captureWriteMode(options, path);
			this.#require(writePermission(mode), "write", path);
			assertLogicalWritePath(path, this.limits.maxPathBytes);
			if (Object.hasOwn(options, "metadata")) {
				throw protectedError(StorageErrorCode.INVALID_ARGUMENT, "write", path, {
					permanent: true,
				});
			}
			const plaintext = captureBody(body, path, this.limits.maxWriteBytes);
			const clearPlaintext = (): void => {
				plaintext.fill(0);
			};
			runtime.signal?.addEventListener("abort", clearPlaintext, { once: true });
			try {
				if (plaintext.byteLength > this.limits.maxWriteBytes) {
					throw protectedError(StorageErrorCode.LIMIT_EXCEEDED, "write", path, {
						permanent: true,
					});
				}
				const contentType = captureContentType(options.contentType ?? OUTER_CONTENT_TYPE, path);
				let record: string = randomUUID();
				if (mode === "replace") {
					const current = await this.#readStored(path, options, runtime.signal);
					const authenticated = await this.#decryptMetadata(path, current.text, runtime.signal);
					record = authenticated.outer.record;
				}
				const outer = await this.#encryptObject(
					path,
					plaintext,
					contentType,
					record,
					randomUUID(),
					runtime.signal,
				);
				if (textEncoder.encode(outer).byteLength > this.#maxCiphertextBytes) {
					throw protectedError(StorageErrorCode.LIMIT_EXCEEDED, "write", path, {
						permanent: true,
					});
				}
				const stored = await this.#storage.writeFile(
					path,
					outer,
					storageWriteOptions(options, mode, runtime.signal),
				);
				return logicalFile(path, { contentType, size: plaintext.byteLength }, stored);
			} finally {
				runtime.signal?.removeEventListener("abort", clearPlaintext);
				clearPlaintext();
			}
		});
	}

	async copyFile(
		_source: string,
		destination: string,
		options: StorageWorkspaceCopyOptions,
	): Promise<StorageWorkspaceFile> {
		return await this.#operate("copy", destination, options, async () => {
			throw protectedError(StorageErrorCode.NOT_SUPPORTED, "copy", destination, {
				permanent: true,
			});
		});
	}

	async moveFile(
		_source: string,
		destination: string,
		options: StorageWorkspaceMutationOptions,
	): Promise<StorageWorkspaceFile> {
		return await this.#operate("move", destination, options, async () => {
			throw protectedError(StorageErrorCode.NOT_SUPPORTED, "move", destination, {
				permanent: true,
			});
		});
	}

	async deleteFile(path: string, options: StorageWorkspaceDeleteOptions): Promise<void> {
		await this.#operate("delete", path, options, async (runtime) => {
			this.#require("delete", "delete", path);
			await this.#storage.deleteFile(path, storageDeleteOptions(options, runtime.signal));
		});
	}

	mount(directory: string, options?: StorageWorkspaceMountOptions): ProtectedStorageWorkspace {
		this.#throwIfLifetimeAborted("mount", directory);
		try {
			const limits = restrictLimits(this.limits, options?.limits);
			const permissions = restrictPermissions(this.permissions, options?.permissions);
			const storage = this.#storage.mount(directory, {
				permissions,
				limits: {
					...limits,
					maxReadBytes: this.#storage.limits.maxReadBytes,
					maxWriteBytes: this.#storage.limits.maxWriteBytes,
				},
			});
			return new ProtectedStorageWorkspaceImplementation(
				{
					cipher: this.#cipher,
					limits,
					maxCiphertextBytes: this.#maxCiphertextBytes,
					maxPlaintextBytes: this.#maxPlaintextBytes,
					pathSearch: this.#pathSearch,
					policyRevision: this.#policyRevision,
					scopeContext: this.#scopeContext,
					...(this.#lifetimeSignal === undefined ? {} : { signal: this.#lifetimeSignal }),
					storage,
				},
				joinPath(this.#directory, directory),
			);
		} catch (error: unknown) {
			throw sanitizeError(error, "mount", directory, false, this.#lifetimeSignal?.aborted === true);
		}
	}

	#permissionAllowed(permission: StorageWorkspacePermission): boolean {
		if (FORBIDDEN_PERMISSIONS.has(permission) || !this.#storage.allows(permission)) {
			return false;
		}
		if (permission === "search") {
			return this.#pathSearch === "provider-visible" && this.#storage.allows("read");
		}
		if (permission === "list" || permission === "replace") {
			return this.#storage.allows("read");
		}
		return true;
	}

	#require(
		permission: StorageWorkspacePermission,
		operation: string,
		path: string | undefined,
	): void {
		if (!this.#permissionAllowed(permission)) {
			throw protectedError(StorageErrorCode.UNAUTHORIZED, operation, path, {
				permanent: true,
			});
		}
	}

	async #readBytes(
		path: string,
		options: StorageWorkspaceReadOptions | undefined,
		signal: AbortSignal | undefined,
	): Promise<ProtectedStorageWorkspaceByteFile> {
		const maxBytes = options?.maxBytes ?? this.limits.maxReadBytes;
		assertReadLimit(maxBytes, this.limits.maxReadBytes, path);
		const stored = await this.#readStored(path, options, signal);
		const metadata = await this.#decryptMetadata(path, stored.text, signal);
		if (metadata.size > maxBytes) {
			throw protectedError(StorageErrorCode.LIMIT_EXCEEDED, "read", path, {
				permanent: true,
			});
		}
		let plaintext: Uint8Array | undefined;
		try {
			plaintext = await this.#decryptValue(
				metadata.outer.content,
				path,
				metadata.outer.record,
				metadata.outer.version,
				"body",
				signal,
			);
			if (!isStableBytes(plaintext)) {
				throw new TypeError("The workspace cipher returned invalid plaintext.");
			}
			const bytes = new Uint8Array(plaintext);
			if (bytes.byteLength !== metadata.size || bytes.byteLength > this.#maxPlaintextBytes) {
				bytes.fill(0);
				throw new TypeError("Protected body size is invalid.");
			}
			return { ...logicalFile(path, metadata, stored), bytes };
		} catch (error: unknown) {
			throw authenticationError("read", path, error);
		} finally {
			plaintext?.fill(0);
		}
	}

	async #readStored(
		path: string,
		options: StorageOperationOptions | undefined,
		signal: AbortSignal | undefined,
	): Promise<StorageWorkspaceTextFile> {
		return await this.#storage.readText(path, {
			...operationOptions(options, signal),
			maxBytes: this.#maxCiphertextBytes,
		});
	}

	async #authenticatePage(
		page: StorageWorkspacePage,
		options: StorageOperationOptions | undefined,
	): Promise<StorageWorkspacePage> {
		const entries: StorageWorkspaceEntry[] = [];
		for (const entry of page.entries) {
			if (entry.kind === "directory") {
				entries.push(entry);
				continue;
			}
			const stored = await this.#readStored(entry.path, options, options?.signal);
			const metadata = await this.#decryptMetadata(entry.path, stored.text, options?.signal);
			entries.push(logicalFile(entry.path, metadata, stored));
		}
		return {
			entries,
			...(page.cursor === undefined ? {} : { cursor: page.cursor }),
		};
	}

	async #encryptObject(
		path: string,
		body: Uint8Array,
		contentType: string,
		record: string,
		version: string,
		signal: AbortSignal | undefined,
	): Promise<string> {
		const fullPath = joinPath(this.#directory, path);
		const metadataBytes = textEncoder.encode(
			JSON.stringify({
				contentType,
				path: fullPath,
				size: body.byteLength,
			} satisfies ProtectedMetadata),
		);
		try {
			const metadata = await this.#encryptValue(
				metadataBytes,
				path,
				record,
				version,
				"metadata",
				signal,
			);
			const encryptedBody = await this.#encryptValue(body, path, record, version, "body", signal);
			assertCipherEnvelope(metadata);
			assertCipherEnvelope(encryptedBody);
			return JSON.stringify({
				v: OUTER_VERSION,
				record,
				version,
				metadata,
				content: encryptedBody,
			} satisfies ProtectedOuterObject);
		} catch (error: unknown) {
			throw authenticationError("write", path, error);
		} finally {
			metadataBytes.fill(0);
		}
	}

	async #decryptMetadata(
		path: string,
		stored: string,
		signal: AbortSignal | undefined,
	): Promise<AuthenticatedMetadata> {
		let plaintext: Uint8Array | undefined;
		try {
			const outer = parseOuter(stored, this.#maxCiphertextBytes);
			plaintext = await this.#decryptValue(
				outer.metadata,
				path,
				outer.record,
				outer.version,
				"metadata",
				signal,
			);
			if (!isStableBytes(plaintext)) {
				throw new TypeError("The workspace cipher returned invalid metadata.");
			}
			const metadata = parseMetadata(
				plaintext,
				joinPath(this.#directory, path),
				this.#maxPlaintextBytes,
			);
			return { contentType: metadata.contentType, outer, size: metadata.size };
		} catch (error: unknown) {
			throw authenticationError("read", path, error);
		} finally {
			plaintext?.fill(0);
		}
	}

	#cipherContext(
		path: string,
		record: string,
		version: string,
		purpose: ProtectedPurpose,
		signal: AbortSignal | undefined,
	): AuthenticatedWorkspaceCipherContext {
		const shared = [
			this.#scopeContext,
			textEncoder.encode(this.#policyRevision),
			textEncoder.encode(joinPath(this.#directory, path)),
			textEncoder.encode(record),
			textEncoder.encode(version),
			textEncoder.encode(purpose),
		];
		return {
			authenticatedData: frameContext("aad", shared),
			keyContext: frameContext("key-context", shared),
			...(signal === undefined ? {} : { signal }),
		};
	}

	async #encryptValue(
		plaintext: Uint8Array,
		path: string,
		record: string,
		version: string,
		purpose: ProtectedPurpose,
		signal: AbortSignal | undefined,
	): Promise<string> {
		const context = this.#cipherContext(path, record, version, purpose, signal);
		const clearContext = (): void => {
			context.authenticatedData.fill(0);
			context.keyContext.fill(0);
		};
		signal?.addEventListener("abort", clearContext, { once: true });
		try {
			const encrypted = await this.#cipher.encryptBytes(plaintext, context);
			if (signal?.aborted) throw signal.reason;
			return encrypted;
		} finally {
			signal?.removeEventListener("abort", clearContext);
			clearContext();
		}
	}

	async #decryptValue(
		envelope: string,
		path: string,
		record: string,
		version: string,
		purpose: ProtectedPurpose,
		signal: AbortSignal | undefined,
	): Promise<Uint8Array> {
		const context = this.#cipherContext(path, record, version, purpose, signal);
		const clearContext = (): void => {
			context.authenticatedData.fill(0);
			context.keyContext.fill(0);
		};
		signal?.addEventListener("abort", clearContext, { once: true });
		try {
			const plaintext = await this.#cipher.decryptBytes(envelope, context);
			if (signal?.aborted) {
				if (isStableBytes(plaintext)) plaintext.fill(0);
				throw signal.reason;
			}
			return plaintext;
		} finally {
			signal?.removeEventListener("abort", clearContext);
			clearContext();
		}
	}

	async #operate<Result>(
		operation: string,
		path: string | undefined,
		options: StorageOperationOptions | undefined,
		work: (runtime: OperationRuntime) => Promise<Result>,
	): Promise<Result> {
		const runtime = operationRuntime(this.#lifetimeSignal, options, operation, path);
		try {
			return await raceWithAbort(async () => await work(runtime), runtime.signal);
		} catch (error: unknown) {
			throw sanitizeError(
				error,
				operation,
				path,
				runtime.timedOut(),
				runtime.signal?.aborted === true,
			);
		} finally {
			runtime.close();
		}
	}

	#throwIfLifetimeAborted(operation: string, path?: string): void {
		if (this.#lifetimeSignal?.aborted) {
			throw protectedError(StorageErrorCode.ABORTED, operation, path, {
				aborted: true,
			});
		}
	}
}

function captureOptions(options: ProtectStorageWorkspaceOptions): CapturedOptions {
	if (typeof options !== "object" || options === null) {
		throw new TypeError("Protected storage-workspace options are required.");
	}
	const storage = options.storage;
	if (
		typeof storage !== "object" ||
		storage === null ||
		typeof storage.readText !== "function" ||
		typeof storage.writeFile !== "function" ||
		typeof storage.mount !== "function"
	) {
		throw new TypeError("A StorageWorkspace is required.");
	}
	const cipher = options.cipher;
	if (
		typeof cipher !== "object" ||
		cipher === null ||
		typeof cipher.encryptBytes !== "function" ||
		typeof cipher.decryptBytes !== "function"
	) {
		throw new TypeError("An authenticated workspace cipher is required.");
	}
	const signal = options.signal;
	assertOptionalSignal(signal);
	const policyRevision = capturePolicyRevision(options.policyRevision);
	const scopeContext = captureScopeContext(options.scopeContext);
	const limits = captureLimits(options.limits, storage.limits);
	const maxCiphertextBytes = positiveInteger(
		options.maxCiphertextBytes,
		"The protected workspace ciphertext limit",
	);
	const maxPlaintextBytes = Math.max(limits.maxReadBytes, limits.maxWriteBytes);
	if (
		maxCiphertextBytes < maxPlaintextBytes ||
		maxCiphertextBytes > storage.limits.maxReadBytes ||
		maxCiphertextBytes > storage.limits.maxWriteBytes
	) {
		scopeContext.fill(0);
		throw new TypeError(
			"The ciphertext limit must cover logical plaintext and fit the backing workspace read/write limits.",
		);
	}
	const pathSearch = options.pathSearch ?? "disabled";
	if (pathSearch !== "disabled" && pathSearch !== "provider-visible") {
		scopeContext.fill(0);
		throw new TypeError("Protected workspace path search is invalid.");
	}
	return {
		cipher,
		limits,
		maxCiphertextBytes,
		maxPlaintextBytes,
		pathSearch,
		policyRevision,
		scopeContext,
		...(signal === undefined ? {} : { signal }),
		storage,
	};
}

function captureLimits(
	value: Readonly<StorageWorkspaceLimits>,
	backing: Readonly<StorageWorkspaceLimits>,
): Readonly<StorageWorkspaceLimits> {
	if (typeof value !== "object" || value === null) {
		throw new TypeError("Protected workspace logical limits are required.");
	}
	const result = {
		cursorTtlMs: captureInitialLimit("cursorTtlMs", value, backing, false),
		maxCursorBytes: captureInitialLimit("maxCursorBytes", value, backing, false),
		maxPageSize: captureInitialLimit("maxPageSize", value, backing, false),
		maxPathBytes: captureInitialLimit("maxPathBytes", value, backing, false),
		maxReadBytes: captureInitialLimit("maxReadBytes", value, backing, true),
		maxSearchResults: captureInitialLimit("maxSearchResults", value, backing, false),
		maxSearchScan: captureInitialLimit("maxSearchScan", value, backing, false),
		maxWriteBytes: captureInitialLimit("maxWriteBytes", value, backing, true),
	} satisfies StorageWorkspaceLimits;
	return Object.freeze(result);
}

function captureInitialLimit(
	key: keyof StorageWorkspaceLimits,
	value: Readonly<StorageWorkspaceLimits>,
	backing: Readonly<StorageWorkspaceLimits>,
	allowNarrowing: boolean,
): number {
	const limit = positiveInteger(value[key], `The logical ${key} limit`);
	if (limit > backing[key]) {
		throw new TypeError(`The logical ${key} limit cannot exceed its backing workspace limit.`);
	}
	if (!allowNarrowing && limit !== backing[key]) {
		throw new TypeError(`The initial logical ${key} limit must match its backing workspace limit.`);
	}
	return limit;
}

function captureScopeContext(value: string | Uint8Array): Uint8Array {
	let bytes: Uint8Array;
	if (typeof value === "string") {
		bytes = boundedUtf8(value, MAX_SCOPE_CONTEXT_BYTES, "Protected workspace scope context");
	} else if (isStableBytes(value)) {
		if (value.byteLength === 0 || value.byteLength > MAX_SCOPE_CONTEXT_BYTES) {
			throw new TypeError("Protected workspace scope context has an invalid size.");
		}
		bytes = new Uint8Array(value);
	} else {
		throw new TypeError("Protected workspace scope context must be text or bytes.");
	}
	if (bytes.byteLength === 0 || bytes.byteLength > MAX_SCOPE_CONTEXT_BYTES) {
		bytes.fill(0);
		throw new TypeError("Protected workspace scope context has an invalid size.");
	}
	return bytes;
}

function capturePolicyRevision(value: string): string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > MAX_POLICY_REVISION_BYTES ||
		value.trim() !== value ||
		/\p{C}/u.test(value)
	) {
		throw new TypeError("Protected workspace policy revision is invalid.");
	}
	const bytes = boundedUtf8(
		value,
		MAX_POLICY_REVISION_BYTES,
		"Protected workspace policy revision",
	);
	bytes.fill(0);
	return value;
}

function captureWriteMode(
	options: StorageWorkspaceWriteOptions,
	path: string,
): StorageWorkspaceWriteOptions["mode"] {
	if (typeof options !== "object" || options === null) {
		throw protectedError(StorageErrorCode.INVALID_ARGUMENT, "write", path, {
			permanent: true,
		});
	}
	if (options.mode !== "create" && options.mode !== "replace" && options.mode !== "overwrite") {
		throw protectedError(StorageErrorCode.INVALID_ARGUMENT, "write", path, {
			permanent: true,
		});
	}
	if (
		options.mode === "replace" &&
		(typeof options.etag !== "string" || options.etag.length === 0)
	) {
		throw protectedError(StorageErrorCode.INVALID_ARGUMENT, "write", path, {
			permanent: true,
		});
	}
	if (options.mode !== "replace" && Object.hasOwn(options, "etag")) {
		throw protectedError(StorageErrorCode.INVALID_ARGUMENT, "write", path, {
			permanent: true,
		});
	}
	return options.mode;
}

function writePermission(mode: StorageWorkspaceWriteOptions["mode"]): StorageWorkspacePermission {
	if (mode === "overwrite") return "write";
	return mode;
}

function storageWriteOptions(
	options: StorageWorkspaceWriteOptions,
	mode: StorageWorkspaceWriteOptions["mode"],
	signal: AbortSignal | undefined,
): StorageWorkspaceWriteOptions {
	const operation = operationOptions(options, signal);
	if (mode === "create") {
		return { ...operation, contentType: OUTER_CONTENT_TYPE, mode: "create" };
	}
	if (mode === "overwrite") {
		return { ...operation, contentType: OUTER_CONTENT_TYPE, mode: "overwrite" };
	}
	if (options.mode !== "replace") {
		throw new TypeError("Protected workspace replace options are invalid.");
	}
	return {
		...operation,
		contentType: OUTER_CONTENT_TYPE,
		etag: options.etag,
		mode: "replace",
	};
}

function captureBody(body: StorageWorkspaceBody, path: string, maxBytes: number): Uint8Array {
	if (typeof body === "string") {
		try {
			return boundedUtf8(body, maxBytes, "Protected workspace body");
		} catch {
			throw protectedError(StorageErrorCode.LIMIT_EXCEEDED, "write", path, {
				permanent: true,
			});
		}
	}
	if (!isStableBytes(body)) {
		throw protectedError(StorageErrorCode.INVALID_ARGUMENT, "write", path, {
			permanent: true,
		});
	}
	if (body.byteLength > maxBytes) {
		throw protectedError(StorageErrorCode.LIMIT_EXCEEDED, "write", path, {
			permanent: true,
		});
	}
	return new Uint8Array(body);
}

function assertLogicalWritePath(path: string, maxBytes: number): void {
	if (typeof path !== "string" || path.length === 0 || path.length > maxBytes) {
		throw protectedError(StorageErrorCode.INVALID_ARGUMENT, "write", undefined, {
			permanent: true,
		});
	}
	try {
		const bytes = boundedUtf8(path, maxBytes, "Protected workspace path");
		bytes.fill(0);
	} catch {
		throw protectedError(StorageErrorCode.INVALID_ARGUMENT, "write", undefined, {
			permanent: true,
		});
	}
}

function captureContentType(value: string, path: string): string {
	if (!isCanonicalContentType(value)) {
		throw protectedError(StorageErrorCode.INVALID_ARGUMENT, "write", path, {
			permanent: true,
		});
	}
	return value;
}

function isCanonicalContentType(value: unknown): value is string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > MAX_CONTENT_TYPE_BYTES ||
		value.trim() !== value ||
		/\p{C}/u.test(value)
	) {
		return false;
	}
	try {
		const bytes = boundedUtf8(value, MAX_CONTENT_TYPE_BYTES, "Protected content type");
		bytes.fill(0);
	} catch {
		return false;
	}
	return true;
}

function parseOuter(stored: string, maxCiphertextBytes: number): ProtectedOuterObject {
	if (typeof stored !== "string" || textEncoder.encode(stored).byteLength > maxCiphertextBytes) {
		throw new TypeError("Protected outer object exceeds its physical limit.");
	}
	const parsed: unknown = JSON.parse(stored);
	if (!isRecord(parsed) || Object.keys(parsed).join(",") !== "v,record,version,metadata,content") {
		throw new TypeError("Protected outer object is malformed.");
	}
	if (
		parsed.v !== OUTER_VERSION ||
		typeof parsed.record !== "string" ||
		!UUID_V4_PATTERN.test(parsed.record) ||
		typeof parsed.version !== "string" ||
		!UUID_V4_PATTERN.test(parsed.version) ||
		typeof parsed.metadata !== "string" ||
		typeof parsed.content !== "string"
	) {
		throw new TypeError("Protected outer object is malformed.");
	}
	assertCipherEnvelope(parsed.metadata);
	assertCipherEnvelope(parsed.content);
	return {
		content: parsed.content,
		metadata: parsed.metadata,
		record: parsed.record,
		v: OUTER_VERSION,
		version: parsed.version,
	};
}

function parseMetadata(
	bytes: Uint8Array,
	expectedPath: string,
	maxPlaintextBytes: number,
): ProtectedMetadata {
	const parsed: unknown = JSON.parse(strictTextDecoder.decode(bytes));
	if (!isRecord(parsed) || Object.keys(parsed).join(",") !== "contentType,path,size") {
		throw new TypeError("Protected metadata is malformed.");
	}
	const size = parsed.size;
	if (
		!isCanonicalContentType(parsed.contentType) ||
		parsed.path !== expectedPath ||
		typeof size !== "number" ||
		!Number.isSafeInteger(size) ||
		size < 0 ||
		size > maxPlaintextBytes
	) {
		throw new TypeError("Protected metadata is malformed.");
	}
	return { contentType: parsed.contentType, path: expectedPath, size };
}

function assertCipherEnvelope(value: string): void {
	if (typeof value !== "string" || !value.startsWith(CIPHER_ENVELOPE_PREFIX)) {
		throw new TypeError("The workspace cipher must return an nmc1 envelope.");
	}
}

function logicalFile(
	path: string,
	logical: Pick<ProtectedMetadata, "contentType" | "size">,
	stored: Pick<StorageWorkspaceFile, "etag" | "lastModified">,
): StorageWorkspaceFile {
	const name = path.slice(path.lastIndexOf("/") + 1);
	return {
		contentType: logical.contentType,
		...(stored.etag === undefined ? {} : { etag: stored.etag }),
		kind: "file",
		...(stored.lastModified === undefined ? {} : { lastModified: new Date(stored.lastModified) }),
		name,
		path,
		size: logical.size,
	};
}

function withoutBytes(file: ProtectedStorageWorkspaceByteFile): StorageWorkspaceFile {
	return {
		contentType: file.contentType,
		...(file.etag === undefined ? {} : { etag: file.etag }),
		kind: "file",
		...(file.lastModified === undefined ? {} : { lastModified: file.lastModified }),
		name: file.name,
		path: file.path,
		size: file.size,
	};
}

function assertReadLimit(value: number, maximum: number, path: string): void {
	if (!Number.isSafeInteger(value) || value <= 0) {
		throw protectedError(StorageErrorCode.INVALID_ARGUMENT, "read", path, {
			permanent: true,
		});
	}
	if (value > maximum) {
		throw protectedError(StorageErrorCode.LIMIT_EXCEEDED, "read", path, {
			permanent: true,
		});
	}
}

function restrictLimits(
	parent: Readonly<StorageWorkspaceLimits>,
	requested: Partial<StorageWorkspaceLimits> | undefined,
): Readonly<StorageWorkspaceLimits> {
	const result = {
		cursorTtlMs: childLimit(requested?.cursorTtlMs, parent.cursorTtlMs),
		maxCursorBytes: childLimit(requested?.maxCursorBytes, parent.maxCursorBytes),
		maxPageSize: childLimit(requested?.maxPageSize, parent.maxPageSize),
		maxPathBytes: childLimit(requested?.maxPathBytes, parent.maxPathBytes),
		maxReadBytes: childLimit(requested?.maxReadBytes, parent.maxReadBytes),
		maxSearchResults: childLimit(requested?.maxSearchResults, parent.maxSearchResults),
		maxSearchScan: childLimit(requested?.maxSearchScan, parent.maxSearchScan),
		maxWriteBytes: childLimit(requested?.maxWriteBytes, parent.maxWriteBytes),
	} satisfies StorageWorkspaceLimits;
	return Object.freeze(result);
}

function childLimit(value: number | undefined, parent: number): number {
	if (value === undefined) return parent;
	if (!Number.isSafeInteger(value) || value <= 0 || value > parent) {
		throw protectedError(StorageErrorCode.INVALID_ARGUMENT, "mount", undefined, {
			permanent: true,
		});
	}
	return value;
}

function restrictPermissions(
	parent: ReadonlySet<StorageWorkspacePermission>,
	requested: Iterable<StorageWorkspacePermission> | undefined,
): readonly StorageWorkspacePermission[] {
	if (requested === undefined) return Object.freeze([...parent]);
	const result: StorageWorkspacePermission[] = [];
	for (const permission of requested) {
		if (!parent.has(permission)) {
			throw protectedError(StorageErrorCode.UNAUTHORIZED, "mount", undefined, {
				permanent: true,
			});
		}
		result.push(permission);
	}
	return Object.freeze(result);
}

function operationOptions(
	options: StorageOperationOptions | undefined,
	signal: AbortSignal | undefined,
): StorageOperationOptions | undefined {
	if (options === undefined && signal === undefined) return undefined;
	return {
		...(options?.retries === undefined ? {} : { retries: options.retries }),
		...(signal === undefined ? {} : { signal }),
	};
}

function listOptions(
	options: StorageWorkspaceListOptions | undefined,
	signal: AbortSignal | undefined,
): StorageWorkspaceListOptions {
	return {
		...(options?.cursor === undefined ? {} : { cursor: options.cursor }),
		...(options?.directory === undefined ? {} : { directory: options.directory }),
		...(options?.limit === undefined ? {} : { limit: options.limit }),
		...(options?.recursive === undefined ? {} : { recursive: options.recursive }),
		...operationOptions(options, signal),
	};
}

function searchOptions(
	options: StorageWorkspaceSearchOptions | undefined,
	signal: AbortSignal | undefined,
): StorageWorkspaceSearchOptions {
	return {
		...(options?.caseInsensitive === undefined ? {} : { caseInsensitive: options.caseInsensitive }),
		...(options?.cursor === undefined ? {} : { cursor: options.cursor }),
		...(options?.directory === undefined ? {} : { directory: options.directory }),
		...(options?.limit === undefined ? {} : { limit: options.limit }),
		...(options?.match === undefined ? {} : { match: options.match }),
		...operationOptions(options, signal),
	};
}

function storageDeleteOptions(
	options: StorageWorkspaceDeleteOptions,
	signal: AbortSignal | undefined,
): StorageWorkspaceDeleteOptions {
	const operation = operationOptions(options, signal);
	if ("mode" in options && options.mode === "unconditional") {
		return { ...operation, mode: "unconditional" };
	}
	if (!("etag" in options)) {
		throw new TypeError("Protected workspace delete options are invalid.");
	}
	return { ...operation, etag: options.etag };
}

function operationRuntime(
	lifetimeSignal: AbortSignal | undefined,
	options: StorageOperationOptions | undefined,
	operation: string,
	path: string | undefined,
): OperationRuntime {
	if (options !== undefined && (typeof options !== "object" || options === null)) {
		throw protectedError(StorageErrorCode.INVALID_ARGUMENT, operation, path, {
			permanent: true,
		});
	}
	const callerSignal = options?.signal;
	if (callerSignal !== undefined && !isAbortSignal(callerSignal)) {
		throw protectedError(StorageErrorCode.INVALID_ARGUMENT, operation, path, {
			permanent: true,
		});
	}
	const timeout = options?.timeout;
	if (
		timeout !== undefined &&
		(!Number.isSafeInteger(timeout) || timeout <= 0 || timeout > MAX_OPERATION_TIMEOUT_MS)
	) {
		throw protectedError(StorageErrorCode.INVALID_ARGUMENT, operation, path, {
			permanent: true,
		});
	}
	const sources = [
		...new Set(
			[lifetimeSignal, callerSignal].filter(
				(signal): signal is AbortSignal => signal !== undefined,
			),
		),
	];
	if (sources.length === 0 && timeout === undefined) {
		return { close: () => undefined, signal: undefined, timedOut: () => false };
	}
	const controller = new AbortController();
	let timeoutReached = false;
	const listeners = new Map<AbortSignal, () => void>();
	for (const source of sources) {
		const listener = (): void => controller.abort(source.reason);
		listeners.set(source, listener);
		source.addEventListener("abort", listener, { once: true });
		if (source.aborted) listener();
	}
	const timer =
		timeout === undefined
			? undefined
			: setTimeout(() => {
					timeoutReached = true;
					controller.abort(new DOMException("The operation timed out.", "TimeoutError"));
				}, timeout);
	timer?.unref();
	return {
		close: () => {
			if (timer !== undefined) clearTimeout(timer);
			for (const [source, listener] of listeners) {
				source.removeEventListener("abort", listener);
			}
		},
		signal: controller.signal,
		timedOut: () => timeoutReached,
	};
}

async function raceWithAbort<Result>(
	work: () => Promise<Result>,
	signal: AbortSignal | undefined,
): Promise<Result> {
	if (signal === undefined) return await work();
	if (signal.aborted) throw signal.reason;
	return await new Promise<Result>((resolve, reject) => {
		let settled = false;
		const finish = (callback: () => void): void => {
			if (settled) return;
			settled = true;
			signal.removeEventListener("abort", onAbort);
			callback();
		};
		const onAbort = (): void => finish(() => reject(signal.reason));
		signal.addEventListener("abort", onAbort, { once: true });
		if (signal.aborted) onAbort();
		const pending = Promise.resolve().then(async () => {
			if (signal.aborted) throw signal.reason;
			return await work();
		});
		void pending.then(
			(value) => finish(() => resolve(value)),
			(error: unknown) => finish(() => reject(error)),
		);
	});
}

function frameContext(kind: "aad" | "key-context", values: readonly Uint8Array[]): Uint8Array {
	const fields = [textEncoder.encode(CONTEXT_DOMAIN), textEncoder.encode(kind), ...values];
	let size = 0;
	for (const field of fields) {
		if (field.byteLength > 0xffff_ffff || size > Number.MAX_SAFE_INTEGER - 4 - field.byteLength) {
			throw new TypeError("Protected workspace context is too large.");
		}
		size += 4 + field.byteLength;
	}
	const framed = new Uint8Array(size);
	const view = new DataView(framed.buffer);
	let offset = 0;
	for (const field of fields) {
		view.setUint32(offset, field.byteLength, false);
		offset += 4;
		framed.set(field, offset);
		offset += field.byteLength;
	}
	return framed;
}

function sanitizeError(
	error: unknown,
	operation: string,
	path: string | undefined,
	timedOut: boolean,
	aborted: boolean,
): StorageError {
	if (timedOut) {
		return protectedError(StorageErrorCode.TIMEOUT, operation, path, {
			aborted: true,
			timedOut: true,
		});
	}
	if (aborted) {
		return protectedError(StorageErrorCode.ABORTED, operation, path, {
			aborted: true,
		});
	}
	if (isStorageError(error)) {
		return protectedError(error.code, operation, path, {
			aborted: error.aborted,
			permanent: error.permanent,
			timedOut: error.timedOut,
		});
	}
	if (isAbortLike(error)) {
		return protectedError(StorageErrorCode.ABORTED, operation, path, {
			aborted: true,
		});
	}
	return protectedError(StorageErrorCode.PROVIDER, operation, path, {
		permanent: true,
	});
}

function authenticationError(operation: string, path: string, error: unknown): StorageError {
	if (isStorageError(error)) {
		return protectedError(error.code, operation, path, {
			aborted: error.aborted,
			permanent: error.permanent,
			timedOut: error.timedOut,
		});
	}
	if (isAbortLike(error)) {
		return protectedError(StorageErrorCode.ABORTED, operation, path, { aborted: true });
	}
	return protectedError(StorageErrorCode.PROVIDER, operation, path, { permanent: true });
}

function protectedError(
	code: StorageErrorCodeValue,
	operation: string,
	path: string | undefined,
	flags: {
		readonly aborted?: boolean;
		readonly permanent?: boolean;
		readonly timedOut?: boolean;
	} = {},
): StorageError {
	return new StorageError(`Protected workspace ${operation} failed.`, {
		aborted: flags.aborted === true,
		code,
		...(path === undefined ? {} : { key: path }),
		operation,
		permanent: flags.permanent === true,
		timedOut: flags.timedOut === true,
	});
}

function isAbortLike(error: unknown): boolean {
	if (typeof error !== "object" || error === null) return false;
	try {
		return "name" in error && error.name === "AbortError";
	} catch {
		return false;
	}
}

function assertOptionalSignal(signal: AbortSignal | undefined): void {
	if (signal !== undefined && !isAbortSignal(signal)) {
		throw new TypeError("Protected workspace lifetime signal is invalid.");
	}
}

function isAbortSignal(value: unknown): value is AbortSignal {
	if (typeof value !== "object" || value === null) return false;
	try {
		return (
			typeof Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get?.call(value) ===
			"boolean"
		);
	} catch {
		return false;
	}
}

function isStableBytes(value: unknown): value is Uint8Array {
	try {
		if (!(value instanceof Uint8Array) || !ArrayBuffer.isView(value)) return false;
		const prototype: unknown = Object.getPrototypeOf(value);
		if (prototype !== Uint8Array.prototype && prototype !== Buffer.prototype) return false;
		return !(value.buffer instanceof SharedArrayBuffer) && Number.isSafeInteger(value.byteLength);
	} catch {
		return false;
	}
}

function positiveInteger(value: number, label: string): number {
	if (!Number.isSafeInteger(value) || value <= 0) {
		throw new TypeError(`${label} must be a positive safe integer.`);
	}
	return value;
}

function boundedUtf8(value: string, maxBytes: number, label: string): Uint8Array {
	if (typeof value !== "string" || value.length > maxBytes) {
		throw new TypeError(`${label} exceeds its UTF-8 byte limit.`);
	}
	const encodedUpperBound = value.length * 3;
	const detectionBound = maxBytes === Number.MAX_SAFE_INTEGER ? maxBytes : maxBytes + 1;
	const target = new Uint8Array(Math.min(encodedUpperBound, detectionBound));
	const result = textEncoder.encodeInto(value, target);
	if (result.read !== value.length || result.written > maxBytes) {
		target.fill(0);
		throw new TypeError(`${label} exceeds its UTF-8 byte limit.`);
	}
	const bytes = target.slice(0, result.written);
	target.fill(0);
	return bytes;
}

function joinPath(directory: string, path: string): string {
	return directory.length === 0 ? path : `${directory}/${path}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
