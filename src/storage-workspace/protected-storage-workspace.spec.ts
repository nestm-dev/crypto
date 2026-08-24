import { randomUUID } from "node:crypto";
import { getEventListeners } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { StorageClient, StorageError, StorageErrorCode } from "@nestm/storage/core";
import { createFsStorageDriver } from "@nestm/storage/files-sdk/fs";
import {
	Aes256GcmStorageWorkspaceCursorCodec,
	mountStorageWorkspace,
	type StorageWorkspace,
	type StorageWorkspaceLimits,
	type StorageWorkspacePermission,
} from "@nestm/storage/workspace";

import { AesKeyRingProvider, CipherEngine } from "../core/index.js";
import { createCipherEngineWorkspaceCipher } from "./cipher-engine-adapter.js";
import { protectStorageWorkspace } from "./protected-storage-workspace.js";
import type {
	AuthenticatedWorkspaceCipher,
	ProtectedStorageWorkspace,
	ProtectStorageWorkspaceOptions,
} from "./types.js";

const PREFIX = "protected-workspace-fixture";
const MAX_CIPHERTEXT_BYTES = 32 * 1024;
const BACKING_LIMITS: Readonly<StorageWorkspaceLimits> = Object.freeze({
	cursorTtlMs: 60_000,
	maxCursorBytes: 4096,
	maxPageSize: 20,
	maxPathBytes: 512,
	maxReadBytes: 64 * 1024,
	maxSearchResults: 20,
	maxSearchScan: 100,
	maxWriteBytes: 64 * 1024,
});
const LOGICAL_LIMITS: Readonly<StorageWorkspaceLimits> = Object.freeze({
	...BACKING_LIMITS,
	maxReadBytes: 4096,
	maxWriteBytes: 4096,
});
const ALL_PERMISSIONS = Object.freeze([
	"list",
	"read",
	"search",
	"write",
	"create",
	"replace",
	"copy",
	"move",
	"delete",
] satisfies readonly StorageWorkspacePermission[]);
const KEY = new Uint8Array(32).fill(0x41);
const temporaryRoots: string[] = [];

afterEach(() => {
	for (const root of temporaryRoots.splice(0)) {
		rmSync(root, { force: true, recursive: true });
	}
});

interface RawOuter {
	readonly v: 1;
	readonly record: string;
	readonly version: string;
	readonly metadata: string;
	readonly content: string;
}

interface Fixture {
	readonly client: StorageClient;
	readonly engine: CipherEngine;
	readonly cipher: AuthenticatedWorkspaceCipher;
	readonly storage: StorageWorkspace;
	readonly workspace: ProtectedStorageWorkspace;
}

function engine(): CipherEngine {
	return new CipherEngine({
		defaultProvider: "local",
		maxPayloadBytes: LOGICAL_LIMITS.maxWriteBytes,
		providers: [
			{
				name: "local",
				provider: new AesKeyRingProvider({
					activeKeyId: "test-key-v1",
					keys: { "test-key-v1": KEY },
				}),
			},
		],
	});
}

function backing(
	client: StorageClient,
	prefix = PREFIX,
	permissions: readonly StorageWorkspacePermission[] = ALL_PERMISSIONS,
): StorageWorkspace {
	return mountStorageWorkspace(client, {
		cursor: {
			codec: new Aes256GcmStorageWorkspaceCursorCodec({
				activeKeyId: "cursor-v1",
				keys: { "cursor-v1": new Uint8Array(32).fill(0x43) },
			}),
			mountId: `test/${prefix}`,
			scope: "protected-workspace-tests",
		},
		limits: BACKING_LIMITS,
		permissions,
		prefix,
	});
}

function protectedView(
	storage: StorageWorkspace,
	cipher: AuthenticatedWorkspaceCipher,
	overrides: Partial<
		Pick<
			ProtectStorageWorkspaceOptions,
			"limits" | "maxCiphertextBytes" | "pathSearch" | "policyRevision" | "scopeContext" | "signal"
		>
	> = {},
): ProtectedStorageWorkspace {
	return protectStorageWorkspace({
		cipher,
		limits: overrides.limits ?? LOGICAL_LIMITS,
		maxCiphertextBytes: overrides.maxCiphertextBytes ?? MAX_CIPHERTEXT_BYTES,
		pathSearch: overrides.pathSearch ?? "disabled",
		policyRevision: overrides.policyRevision ?? "policy-v1",
		scopeContext: overrides.scopeContext ?? "tenant/acme/workspace/primary",
		...(overrides.signal === undefined ? {} : { signal: overrides.signal }),
		storage,
	});
}

function fixture(): Fixture {
	const root = mkdtempSync(join(tmpdir(), "nestm-protected-workspace-"));
	temporaryRoots.push(root);
	const client = new StorageClient(
		"protected-workspace-test",
		createFsStorageDriver({ adapter: { root } }),
	);
	const testEngine = engine();
	const cipher = createCipherEngineWorkspaceCipher(testEngine);
	const storage = backing(client);
	return {
		cipher,
		client,
		engine: testEngine,
		storage,
		workspace: protectedView(storage, cipher),
	};
}

async function rawText(client: StorageClient, path: string, prefix = PREFIX): Promise<string> {
	return await client.downloadText(`${prefix}/${path}`, {
		maxBytes: BACKING_LIMITS.maxReadBytes,
	});
}

async function putRaw(
	client: StorageClient,
	path: string,
	body: string,
	prefix = PREFIX,
): Promise<void> {
	await client.upload(`${prefix}/${path}`, body, {
		contentType: "application/octet-stream",
	});
}

function parseRaw(value: string): RawOuter {
	const parsed: unknown = JSON.parse(value);
	if (
		typeof parsed !== "object" ||
		parsed === null ||
		!("v" in parsed) ||
		parsed.v !== 1 ||
		!("record" in parsed) ||
		typeof parsed.record !== "string" ||
		!("version" in parsed) ||
		typeof parsed.version !== "string" ||
		!("metadata" in parsed) ||
		typeof parsed.metadata !== "string" ||
		!("content" in parsed) ||
		typeof parsed.content !== "string"
	) {
		throw new TypeError("The raw test object is malformed.");
	}
	return {
		v: 1,
		record: parsed.record,
		version: parsed.version,
		metadata: parsed.metadata,
		content: parsed.content,
	};
}

function mutateEnvelope(value: string): string {
	const last = value.at(-1);
	if (last === undefined) throw new Error("Missing envelope value.");
	return `${value.slice(0, -1)}${last === "A" ? "B" : "A"}`;
}

describe("protected StorageWorkspace", () => {
	it("round-trips text and bytes while exposing only a frozen protected view", async () => {
		const { client, workspace } = fixture();
		const path = "reports/private.md";
		const plaintext = "classified workspace artifact";

		const created = await workspace.writeFile(path, plaintext, {
			contentType: "text/markdown; charset=utf-8",
			mode: "create",
		});

		expect(created).toMatchObject({
			contentType: "text/markdown; charset=utf-8",
			kind: "file",
			name: "private.md",
			path,
			size: new TextEncoder().encode(plaintext).byteLength,
		});
		await expect(workspace.readText(path)).resolves.toMatchObject({ text: plaintext });
		await expect(workspace.readBytes(path)).resolves.toMatchObject({
			bytes: new TextEncoder().encode(plaintext),
		});

		const binary = new Uint8Array([0, 1, 2, 254, 255]);
		await workspace.writeFile("payload.bin", binary, {
			contentType: "application/x-fixture",
			mode: "create",
		});
		await expect(workspace.readBytes("payload.bin")).resolves.toMatchObject({ bytes: binary });
		await expect(workspace.readText("payload.bin")).rejects.toMatchObject({
			code: StorageErrorCode.INVALID_ARGUMENT,
		});

		const raw = await rawText(client, path);
		const outer = parseRaw(raw);
		expect(Object.keys(outer)).toEqual(["v", "record", "version", "metadata", "content"]);
		expect(outer).toMatchObject({ v: 1 });
		expect(outer.metadata).toMatch(/^nmc1\./u);
		expect(outer.content).toMatch(/^nmc1\./u);
		expect(raw).not.toContain(plaintext);
		expect(raw).not.toContain(path);
		expect(raw).not.toContain("text/markdown");
		await expect(client.head(`${PREFIX}/${path}`)).resolves.toMatchObject({
			contentType: "application/octet-stream",
		});

		expect(workspace.protection).toEqual({
			body: "encrypted",
			cipherEnvelope: "nmc1",
			kind: "authenticated-encryption",
			metadata: "encrypted",
			outerFormat: "nestm-protected-storage-workspace",
			outerVersion: 1,
			pathBinding: "scope-policy-path-record-version-purpose",
			pathSearch: "disabled",
			policyRevision: "policy-v1",
		});
		expect(Object.isFrozen(workspace)).toBe(true);
		expect(Object.isFrozen(workspace.limits)).toBe(true);
		expect(Object.isFrozen(workspace.protection)).toBe(true);
		expect(Reflect.ownKeys(workspace)).toEqual(["limits", "protection"]);
		expect(workspace.allows("copy")).toBe(false);
		expect(workspace.allows("move")).toBe(false);
		expect(workspace.allows("search")).toBe(false);
		expect(workspace.permissions.has("copy")).toBe(false);
		expect(Reflect.get(workspace, "storage")).toBeUndefined();
		expect(Reflect.get(workspace, "cipher")).toBeUndefined();
	});

	it("rejects plaintext, noncanonical outer records, and malformed nmc1-only writes", async () => {
		const { cipher, client, storage, workspace } = fixture();
		await putRaw(client, "plaintext.txt", "provider plaintext");
		await expect(workspace.readText("plaintext.txt")).rejects.toMatchObject({
			cause: undefined,
			code: StorageErrorCode.PROVIDER,
			key: "plaintext.txt",
			message: "Protected workspace read failed.",
		});

		await workspace.writeFile("canonical.txt", "protected", { mode: "create" });
		const outer = parseRaw(await rawText(client, "canonical.txt"));
		await putRaw(
			client,
			"reordered.txt",
			JSON.stringify({
				record: outer.record,
				v: outer.v,
				version: outer.version,
				metadata: outer.metadata,
				content: outer.content,
			}),
		);
		await expect(workspace.stat("reordered.txt")).rejects.toMatchObject({
			code: StorageErrorCode.PROVIDER,
		});

		const invalidCipher: AuthenticatedWorkspaceCipher = Object.freeze({
			decryptBytes: async () => new Uint8Array(),
			encryptBytes: async () => "not-an-nmc1-envelope",
		});
		const invalid = protectedView(storage, invalidCipher, { scopeContext: "invalid-cipher" });
		await expect(
			invalid.writeFile("invalid.txt", "secret", { mode: "create" }),
		).rejects.toMatchObject({
			code: StorageErrorCode.PROVIDER,
		});
		await expect(client.exists(`${PREFIX}/invalid.txt`)).resolves.toBe(false);

		const readAgain = protectedView(storage, cipher);
		await expect(readAgain.readText("canonical.txt")).resolves.toMatchObject({ text: "protected" });
	});

	it("binds ciphertext to scope, policy, full mounted path, record, version, and purpose", async () => {
		const { cipher, client, storage, workspace } = fixture();
		await workspace.writeFile("source.txt", "bound content", { mode: "create" });
		const sourceRaw = await rawText(client, "source.txt");

		await putRaw(client, "replayed.txt", sourceRaw);
		await expect(workspace.readText("replayed.txt")).rejects.toMatchObject({
			code: StorageErrorCode.PROVIDER,
		});

		const otherScope = protectedView(storage, cipher, { scopeContext: "tenant/other" });
		await expect(otherScope.readText("source.txt")).rejects.toMatchObject({
			code: StorageErrorCode.PROVIDER,
		});
		const otherPolicy = protectedView(storage, cipher, { policyRevision: "policy-v2" });
		await expect(otherPolicy.readText("source.txt")).rejects.toMatchObject({
			code: StorageErrorCode.PROVIDER,
		});

		const versionReplay = { ...parseRaw(sourceRaw), version: randomUUID() };
		await putRaw(client, "source.txt", JSON.stringify(versionReplay));
		await expect(workspace.stat("source.txt")).rejects.toMatchObject({
			code: StorageErrorCode.PROVIDER,
		});

		const recordReplay = { ...parseRaw(sourceRaw), record: randomUUID() };
		await putRaw(client, "source.txt", JSON.stringify(recordReplay));
		await expect(workspace.stat("source.txt")).rejects.toMatchObject({
			code: StorageErrorCode.PROVIDER,
		});

		const purposeReplay = parseRaw(sourceRaw);
		await putRaw(
			client,
			"source.txt",
			JSON.stringify({
				...purposeReplay,
				metadata: purposeReplay.content,
				content: purposeReplay.metadata,
			}),
		);
		await expect(workspace.stat("source.txt")).rejects.toMatchObject({
			code: StorageErrorCode.PROVIDER,
		});

		await putRaw(client, "source.txt", sourceRaw);
		const child = workspace.mount("nested");
		await child.writeFile("mounted.txt", "same full path", { mode: "create" });
		await expect(workspace.readText("nested/mounted.txt")).resolves.toMatchObject({
			text: "same full path",
		});
	});

	it("authenticates metadata for stat/list and content for reads", async () => {
		const { cipher, client, storage, workspace } = fixture();
		await workspace.writeFile("entry.txt", "authenticated body", {
			contentType: "text/custom",
			mode: "create",
		});
		const original = parseRaw(await rawText(client, "entry.txt"));

		await putRaw(
			client,
			"entry.txt",
			JSON.stringify({ ...original, content: mutateEnvelope(original.content) }),
		);
		await expect(workspace.stat("entry.txt")).resolves.toMatchObject({
			contentType: "text/custom",
			size: 18,
		});
		await expect(workspace.list()).resolves.toMatchObject({
			entries: [expect.objectContaining({ contentType: "text/custom", path: "entry.txt" })],
		});
		await expect(workspace.readText("entry.txt")).rejects.toMatchObject({
			code: StorageErrorCode.PROVIDER,
		});

		await putRaw(
			client,
			"entry.txt",
			JSON.stringify({ ...original, metadata: mutateEnvelope(original.metadata) }),
		);
		await expect(workspace.stat("entry.txt")).rejects.toMatchObject({
			code: StorageErrorCode.PROVIDER,
		});
		await expect(workspace.list()).rejects.toMatchObject({
			code: StorageErrorCode.PROVIDER,
		});

		const metadataRewriter: AuthenticatedWorkspaceCipher = {
			decryptBytes: cipher.decryptBytes.bind(cipher),
			async encryptBytes(plaintext, context): Promise<string> {
				const decoded = new TextDecoder().decode(plaintext);
				const marker = '"contentType":"text/plain"';
				if (!decoded.startsWith("{") || !decoded.includes(marker)) {
					return await cipher.encryptBytes(plaintext, context);
				}
				const rewritten = new TextEncoder().encode(
					decoded.replace(marker, '"contentType":" text/plain"'),
				);
				try {
					return await cipher.encryptBytes(rewritten, context);
				} finally {
					rewritten.fill(0);
				}
			},
		};
		const poisoned = protectedView(storage, metadataRewriter);
		await poisoned.writeFile("invalid-content-type.txt", "body", {
			contentType: "text/plain",
			mode: "create",
		});
		await expect(poisoned.stat("invalid-content-type.txt")).rejects.toMatchObject({
			code: StorageErrorCode.PROVIDER,
		});
	});

	it("preserves create, CAS replace, and explicit overwrite semantics", async () => {
		const { client, workspace } = fixture();
		const created = await workspace.writeFile("cas.txt", "v1", { mode: "create" });
		const firstOuter = parseRaw(await rawText(client, "cas.txt"));

		await expect(
			workspace.writeFile("cas.txt", "duplicate", { mode: "create" }),
		).rejects.toMatchObject({
			code: StorageErrorCode.CONFLICT,
			message: "Protected workspace write failed.",
		});
		await expect(
			workspace.writeFile("cas.txt", "stale", { etag: "stale-etag", mode: "replace" }),
		).rejects.toMatchObject({ code: StorageErrorCode.CONFLICT });
		await expect(workspace.readText("cas.txt")).resolves.toMatchObject({ text: "v1" });

		const replaced = await workspace.writeFile("cas.txt", "v2", {
			etag: created.etag ?? "",
			mode: "replace",
		});
		const secondOuter = parseRaw(await rawText(client, "cas.txt"));
		expect(secondOuter.record).toBe(firstOuter.record);
		expect(secondOuter.version).not.toBe(firstOuter.version);
		await expect(workspace.readText("cas.txt")).resolves.toMatchObject({ text: "v2" });

		await workspace.writeFile("cas.txt", "v3", { mode: "overwrite" });
		const thirdOuter = parseRaw(await rawText(client, "cas.txt"));
		expect(thirdOuter.record).not.toBe(secondOuter.record);
		expect(thirdOuter.version).not.toBe(secondOuter.version);
		await expect(workspace.readText("cas.txt")).resolves.toMatchObject({ text: "v3" });

		await expect(
			workspace.writeFile("metadata.txt", "no", {
				metadata: { leaked: "plaintext" },
				mode: "create",
			}),
		).rejects.toMatchObject({ code: StorageErrorCode.INVALID_ARGUMENT });
		const createWithEtag = {
			etag: replaced.etag ?? "etag",
			mode: "create" as const,
		};
		await expect(
			workspace.writeFile("etag-create.txt", "no", createWithEtag),
		).rejects.toMatchObject({ code: StorageErrorCode.INVALID_ARGUMENT });
		const overwriteWithEtag = {
			etag: "unexpected",
			mode: "overwrite" as const,
		};
		await expect(
			workspace.writeFile("etag-overwrite.txt", "no", overwriteWithEtag),
		).rejects.toMatchObject({ code: StorageErrorCode.INVALID_ARGUMENT });
	});

	it("reads retained key revisions and writes new versions with the active key", async () => {
		const { client, storage, workspace } = fixture();
		const created = await workspace.writeFile("rotation.txt", "encrypted with v1", {
			mode: "create",
		});
		const firstOuter = parseRaw(await rawText(client, "rotation.txt"));

		const rotatedEngine = new CipherEngine({
			defaultProvider: "local",
			maxPayloadBytes: LOGICAL_LIMITS.maxWriteBytes,
			providers: [
				{
					name: "local",
					provider: new AesKeyRingProvider({
						activeKeyId: "test-key-v2",
						keys: {
							"test-key-v1": KEY,
							"test-key-v2": new Uint8Array(32).fill(0x42),
						},
					}),
				},
			],
		});
		const rotated = protectedView(storage, createCipherEngineWorkspaceCipher(rotatedEngine));
		await expect(rotated.readText("rotation.txt")).resolves.toMatchObject({
			text: "encrypted with v1",
		});
		expect(rotatedEngine.inspect(firstOuter.content).keyReference).toBe("test-key-v1");

		await rotated.writeFile("rotation.txt", "encrypted with v2", {
			etag: created.etag ?? "",
			mode: "replace",
		});
		await expect(rotated.readText("rotation.txt")).resolves.toMatchObject({
			text: "encrypted with v2",
		});
		const secondOuter = parseRaw(await rawText(client, "rotation.txt"));
		expect(rotatedEngine.inspect(secondOuter.metadata).keyReference).toBe("test-key-v2");
		expect(rotatedEngine.inspect(secondOuter.content).keyReference).toBe("test-key-v2");
	});

	it("preserves list/search query fields and makes path disclosure explicit", async () => {
		const { cipher, storage, workspace } = fixture();
		await workspace.writeFile("root.txt", "root", { mode: "create" });
		await workspace.writeFile("reports/Quarter.TXT", "quarter", { mode: "create" });
		await workspace.writeFile("reports/second.txt", "second", { mode: "create" });

		const first = await workspace.list({ directory: "reports", limit: 1, recursive: true });
		expect(first.entries).toHaveLength(1);
		expect(first.entries[0]?.path).toMatch(/^reports\//u);
		expect(first.cursor).toEqual(expect.any(String));
		const second = await workspace.list({
			cursor: first.cursor,
			directory: "reports",
			limit: 1,
			recursive: true,
		});
		expect(second.entries).toHaveLength(1);
		expect(second.entries[0]?.path).toMatch(/^reports\//u);

		await expect(workspace.search("Quarter")).rejects.toMatchObject({
			code: StorageErrorCode.NOT_SUPPORTED,
		});
		expect(workspace.permissions.has("search")).toBe(false);

		const searchable = protectedView(storage, cipher, { pathSearch: "provider-visible" });
		expect(searchable.protection.pathSearch).toBe("provider-visible");
		expect(searchable.allows("search")).toBe(true);
		const results = await searchable.search("quarter", {
			caseInsensitive: true,
			directory: "reports",
			limit: 1,
			match: "substring",
		});
		expect(results.entries).toEqual([
			expect.objectContaining({ path: "reports/Quarter.TXT", size: 7 }),
		]);
	});

	it("forwards conditional and unconditional delete without exposing copy/move", async () => {
		const { workspace } = fixture();
		const conditional = await workspace.writeFile("conditional.txt", "delete me", {
			mode: "create",
		});
		await workspace.deleteFile("conditional.txt", { etag: conditional.etag ?? "" });
		await expect(workspace.stat("conditional.txt")).rejects.toMatchObject({
			code: StorageErrorCode.NOT_FOUND,
		});

		await workspace.writeFile("unconditional.txt", "delete me too", { mode: "create" });
		await workspace.deleteFile("unconditional.txt", { mode: "unconditional" });
		await expect(workspace.stat("unconditional.txt")).rejects.toMatchObject({
			code: StorageErrorCode.NOT_FOUND,
		});

		await expect(
			workspace.copyFile("source.txt", "copy.txt", { mode: "overwrite" }),
		).rejects.toMatchObject({ code: StorageErrorCode.NOT_SUPPORTED });
		await expect(
			workspace.moveFile("source.txt", "move.txt", { etag: "etag" }),
		).rejects.toMatchObject({ code: StorageErrorCode.NOT_SUPPORTED });
	});

	it("narrows dependent permissions and logical limits across mounts", async () => {
		const { cipher, client, storage, workspace } = fixture();
		await workspace.writeFile("child/existing.txt", "123456", { mode: "create" });
		const child = workspace.mount("child", {
			limits: {
				maxPageSize: 2,
				maxPathBytes: 16,
				maxReadBytes: 10,
				maxWriteBytes: 5,
			},
			permissions: ["list", "read", "create"],
		});
		await expect(child.writeFile("five.txt", "12345", { mode: "create" })).resolves.toMatchObject({
			size: 5,
		});
		await expect(child.writeFile("six.txt", "123456", { mode: "create" })).rejects.toMatchObject({
			code: StorageErrorCode.LIMIT_EXCEEDED,
		});
		await expect(child.list({ limit: 3 })).rejects.toMatchObject({
			code: StorageErrorCode.LIMIT_EXCEEDED,
		});
		await expect(
			child.writeFile("this-path-is-too-long.txt", "1", { mode: "create" }),
		).rejects.toMatchObject({ code: StorageErrorCode.INVALID_ARGUMENT });
		await expect(workspace.readText("child/five.txt")).resolves.toMatchObject({ text: "12345" });
		await expect(child.readText("existing.txt")).resolves.toMatchObject({ text: "123456" });
		const reconstructed = protectedView(storage, cipher, {
			limits: Object.freeze({
				...LOGICAL_LIMITS,
				maxReadBytes: 10,
				maxWriteBytes: 5,
			}),
		});
		await expect(reconstructed.readText("child/existing.txt")).resolves.toMatchObject({
			text: "123456",
		});
		expect(child.permissions).toEqual(new Set(["list", "read", "create"]));
		expect(() => child.mount("forbidden", { permissions: ["copy"] })).toThrowError(
			expect.objectContaining({ code: StorageErrorCode.UNAUTHORIZED }),
		);

		const listOnlyStorage = backing(client, "list-only", ["list"]);
		const listOnly = protectedView(listOnlyStorage, cipher, { scopeContext: "list-only" });
		expect(listOnly.allows("list")).toBe(false);
		expect(listOnly.permissions.has("list")).toBe(false);

		const replaceOnlyStorage = backing(client, "replace-only", ["replace"]);
		const replaceOnly = protectedView(replaceOnlyStorage, cipher, { scopeContext: "replace-only" });
		expect(replaceOnly.allows("replace")).toBe(false);

		const searchWithoutReadStorage = backing(client, "search-only", ["search"]);
		const searchWithoutRead = protectedView(searchWithoutReadStorage, cipher, {
			pathSearch: "provider-visible",
			scopeContext: "search-only",
		});
		expect(searchWithoutRead.allows("search")).toBe(false);
	});

	it("enforces lifetime/caller cancellation and one whole-operation timeout", async () => {
		const { cipher, storage } = fixture();
		const lifetime = new AbortController();
		const workspace = protectedView(storage, cipher, { signal: lifetime.signal });
		const listenersBefore = getEventListeners(lifetime.signal, "abort").length;
		await workspace.writeFile("before.txt", "protected", {
			mode: "create",
			signal: lifetime.signal,
		});
		expect(getEventListeners(lifetime.signal, "abort")).toHaveLength(listenersBefore);
		const child = workspace.mount("child");
		lifetime.abort("do-not-expose-this-reason");
		const backingRead = vi.spyOn(storage, "readText");

		await expect(workspace.readText("before.txt")).rejects.toMatchObject({
			aborted: true,
			cause: undefined,
			code: StorageErrorCode.ABORTED,
			message: "Protected workspace read failed.",
		});
		expect(backingRead).not.toHaveBeenCalled();
		await expect(child.list()).rejects.toMatchObject({
			aborted: true,
			code: StorageErrorCode.ABORTED,
		});
		expect(() => workspace.mount("late")).toThrowError(
			expect.objectContaining({ aborted: true, code: StorageErrorCode.ABORTED }),
		);

		const caller = new AbortController();
		caller.abort({ secret: "reason" });
		const fresh = protectedView(storage, cipher);
		const backingList = vi.spyOn(storage, "list");
		await expect(fresh.list({ signal: caller.signal })).rejects.toMatchObject({
			aborted: true,
			cause: undefined,
			code: StorageErrorCode.ABORTED,
		});
		expect(backingList).not.toHaveBeenCalled();
		await expect(fresh.list({ timeout: Number.MAX_SAFE_INTEGER })).rejects.toMatchObject({
			code: StorageErrorCode.INVALID_ARGUMENT,
		});
		expect(backingList).not.toHaveBeenCalled();

		const encryptSpy = vi.fn(cipher.encryptBytes.bind(cipher));
		const guardedCipher: AuthenticatedWorkspaceCipher = {
			decryptBytes: vi.fn(cipher.decryptBytes.bind(cipher)),
			encryptBytes: encryptSpy,
		};
		const guarded = protectedView(storage, guardedCipher, { scopeContext: "pre-aborted" });
		await expect(
			guarded.writeFile("never-started.txt", "secret", {
				mode: "create",
				signal: caller.signal,
			}),
		).rejects.toMatchObject({ code: StorageErrorCode.ABORTED });
		expect(encryptSpy).not.toHaveBeenCalled();

		const hangingCipher: AuthenticatedWorkspaceCipher = Object.freeze({
			decryptBytes: async () => await new Promise<Uint8Array>(() => undefined),
			encryptBytes: async () => await new Promise<string>(() => undefined),
		});
		const hanging = protectedView(storage, hangingCipher, { scopeContext: "timeout" });
		await expect(
			hanging.writeFile("timeout.txt", "never", { mode: "create", timeout: 10 }),
		).rejects.toMatchObject({
			aborted: true,
			code: StorageErrorCode.TIMEOUT,
			timedOut: true,
		});
	});

	it("enforces separate logical and physical bounds", async () => {
		const { cipher, storage } = fixture();
		expect(() =>
			protectedView(storage, cipher, {
				limits: Object.freeze({ ...LOGICAL_LIMITS, maxPageSize: 1 }),
			}),
		).toThrowError(/must match its backing workspace limit/u);
		expect(() =>
			protectedView(storage, cipher, {
				maxCiphertextBytes: BACKING_LIMITS.maxReadBytes + 1,
			}),
		).toThrowError(/ciphertext limit/u);

		const tinyLimits: Readonly<StorageWorkspaceLimits> = Object.freeze({
			...LOGICAL_LIMITS,
			maxReadBytes: 8,
			maxWriteBytes: 8,
		});
		const tinyPhysical = protectedView(storage, cipher, {
			limits: tinyLimits,
			maxCiphertextBytes: 8,
			scopeContext: "tiny",
		});
		await expect(
			tinyPhysical.writeFile("tiny.txt", "12345678", { mode: "create" }),
		).rejects.toMatchObject({ code: StorageErrorCode.LIMIT_EXCEEDED });
		await expect(
			tinyPhysical.writeFile("too-large.txt", "123456789", { mode: "create" }),
		).rejects.toMatchObject({ code: StorageErrorCode.LIMIT_EXCEEDED });
	});

	it("sanitizes backing and cipher failures at the public boundary", async () => {
		const { cipher, storage, workspace } = fixture();
		vi.spyOn(storage, "readText").mockRejectedValueOnce(
			new StorageError("credential=provider-secret", {
				cause: new Error("provider stack secret"),
				code: StorageErrorCode.PROVIDER,
				key: "physical/provider/key",
				operation: "download",
			}),
		);
		await expect(workspace.readText("logical.txt")).rejects.toMatchObject({
			cause: undefined,
			code: StorageErrorCode.PROVIDER,
			key: "logical.txt",
			message: "Protected workspace read failed.",
			operation: "read",
		});

		await workspace.writeFile("cipher.txt", "protected", { mode: "create" });
		const failingCipher: AuthenticatedWorkspaceCipher = Object.freeze({
			decryptBytes: async () => {
				throw new Error("kms credential and ciphertext details");
			},
			encryptBytes: cipher.encryptBytes.bind(cipher),
		});
		const failing = protectedView(storage, failingCipher);
		await expect(failing.stat("cipher.txt")).rejects.toMatchObject({
			cause: undefined,
			code: StorageErrorCode.PROVIDER,
			message: "Protected workspace stat failed.",
		});
	});
});

describe("CipherEngine workspace cipher adapter", () => {
	it("fails configuration that could write envelopes its read policy rejects", () => {
		const testEngine = engine();
		expect(() =>
			createCipherEngineWorkspaceCipher(testEngine, {
				allowedProviders: ["legacy"],
			}),
		).toThrowError(/write provider/u);
		expect(() =>
			createCipherEngineWorkspaceCipher(testEngine, {
				allowedProviders: ["missing"],
				provider: "missing",
			}),
		).toThrowError(/not registered/u);
	});
});
