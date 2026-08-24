import type { StorageOperationOptions } from "@nestm/storage/core";
import type {
	StorageWorkspace,
	StorageWorkspaceFile,
	StorageWorkspaceLimits,
	StorageWorkspaceMountOptions,
	StorageWorkspaceReadOptions,
} from "@nestm/storage/workspace";

/** Inputs authenticated by a workspace cipher for one protected value. */
export interface AuthenticatedWorkspaceCipherContext {
	readonly authenticatedData: Uint8Array;
	readonly keyContext: Uint8Array;
	readonly signal?: AbortSignal;
}

/**
 * Minimal authenticated-encryption boundary required by a protected workspace.
 *
 * Implementations must return canonical `nmc1` envelopes and must authenticate
 * both context byte strings during decryption. Inputs and context buffers are
 * borrowed for one call: implementations must stay within application-owned
 * bounds, honor the supplied signal, and retain no buffer after settlement.
 */
export interface AuthenticatedWorkspaceCipher {
	encryptBytes(
		plaintext: Uint8Array,
		context: AuthenticatedWorkspaceCipherContext,
	): Promise<string>;
	decryptBytes(envelope: string, context: AuthenticatedWorkspaceCipherContext): Promise<Uint8Array>;
}

export interface ProtectedStorageWorkspaceByteFile extends StorageWorkspaceFile {
	readonly bytes: Uint8Array;
}

export type ProtectedStorageWorkspacePathSearch = "disabled" | "provider-visible";

export interface ProtectedStorageWorkspaceProtection {
	readonly kind: "authenticated-encryption";
	readonly outerFormat: "nestm-protected-storage-workspace";
	readonly outerVersion: 1;
	readonly cipherEnvelope: "nmc1";
	readonly metadata: "encrypted";
	readonly body: "encrypted";
	readonly pathBinding: "scope-policy-path-record-version-purpose";
	readonly pathSearch: ProtectedStorageWorkspacePathSearch;
	readonly policyRevision: string;
}

export interface ProtectedStorageWorkspace extends StorageWorkspace {
	readonly protection: Readonly<ProtectedStorageWorkspaceProtection>;
	readBytes(
		path: string,
		options?: StorageWorkspaceReadOptions,
	): Promise<ProtectedStorageWorkspaceByteFile>;
	mount(directory: string, options?: StorageWorkspaceMountOptions): ProtectedStorageWorkspace;
}

export interface ProtectStorageWorkspaceOptions {
	readonly storage: StorageWorkspace;
	readonly cipher: AuthenticatedWorkspaceCipher;
	/** Opaque deployment/tenant/workspace scope. It is copied and never exposed. */
	readonly scopeContext: string | Uint8Array;
	/** Application-owned policy/key-domain revision authenticated with every value. */
	readonly policyRevision: string;
	/**
	 * Logical limits exposed by the protected view. At initial composition,
	 * non-buffer limits must equal the backing workspace; maxReadBytes and
	 * maxWriteBytes may be lower. Derived mounts can narrow every limit.
	 */
	readonly limits: Readonly<StorageWorkspaceLimits>;
	/**
	 * Physical bound for the complete encrypted outer object. It must cover the
	 * larger logical read/write ceiling and fit the backing read/write limits.
	 */
	readonly maxCiphertextBytes: number;
	/** Registry-owned lifetime cancellation inherited by every derived mount. */
	readonly signal?: AbortSignal;
	/** Explicitly allows cleartext path/query search at the storage provider. */
	readonly pathSearch?: ProtectedStorageWorkspacePathSearch;
}

export interface CipherEngineWorkspaceCipherOptions {
	/** Provider selected for new envelopes. Defaults to the engine provider. */
	readonly provider?: string;
	/** Cipher selected for new envelopes. Defaults to the engine cipher. */
	readonly cipher?: string;
	/** Providers admitted while reading, for explicit key-rotation windows. */
	readonly allowedProviders?: readonly string[];
}

export type ProtectedStorageOperationOptions = StorageOperationOptions;
