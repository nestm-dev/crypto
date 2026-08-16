import type { KeyProviderRegistration } from "../core/types.js";

export type FileByteSource = ReadableStream<Uint8Array> | AsyncIterable<Uint8Array>;

export type EncryptedFileStream = ReadableStream<Uint8Array>;
export type DecryptedFileStream = ReadableStream<Uint8Array>;

export interface FileCipherEngineOptions {
	readonly providers: readonly KeyProviderRegistration[];
	readonly defaultProvider: string;
	readonly maxPlaintextBytes: bigint;
	/** Test seam only. Production callers omit this and use the platform CSPRNG. */
	readonly randomBytes?: (length: number) => Uint8Array;
}

export interface DetachedFileKey {
	readonly version: 1;
	readonly provider: string;
	readonly keyReference: string;
	readonly wrappingAlgorithm: string;
	readonly wrappedKey: Uint8Array;
}

export interface FileEncryptInput {
	readonly aad: Uint8Array;
	readonly provider?: string;
	readonly expectedPlaintextBytes?: bigint;
	readonly signal?: AbortSignal;
}

export interface FileDecryptInput {
	readonly aad: Uint8Array;
	readonly detachedKey: DetachedFileKey;
	readonly allowedProviders: readonly string[];
	/** Generic callers may omit this; Artifact Studio always supplies 52 bytes. */
	readonly expectedHeaderBytes?: Uint8Array;
	readonly expectedPlaintextBytes?: bigint;
	readonly expectedCiphertextBytes?: bigint;
	readonly expectedCiphertextSha256?: string;
	readonly signal?: AbortSignal;
}

export interface FileHeaderInfo {
	readonly format: "NMF1";
	readonly version: 1;
	readonly suite: "A256GCM-SHA256-CHUNKED";
	readonly chunkSize: 1_048_576;
	readonly noncePrefix: Uint8Array;
	readonly fileContextDigest: Uint8Array;
	readonly authenticated: false;
}

export interface FileEncryptionSummary {
	readonly format: "NMF1";
	readonly dataFrameCount: number;
	readonly plaintextBytes: bigint;
	readonly ciphertextBytes: bigint;
	readonly ciphertextSha256: string;
	readonly authenticated: true;
}

export type FileDecryptionSummary = FileEncryptionSummary;

export interface FileEncryptResult {
	readonly encrypted: EncryptedFileStream;
	readonly detachedKey: DetachedFileKey;
	readonly header: FileHeaderInfo;
	/** Exact immutable-by-contract NMF1 header persisted before stream consumption. */
	readonly headerBytes: Uint8Array;
	/** SHA-256 of the exact provider wrapping context as lowercase hexadecimal. */
	readonly wrappingContextDigest: string;
	readonly completion: Promise<FileEncryptionSummary>;
	cancel(reason?: unknown): Promise<void>;
}

export interface FileDecryptResult {
	readonly plaintext: DecryptedFileStream;
	readonly inspectedHeader: FileHeaderInfo;
	readonly verification: Promise<FileDecryptionSummary>;
	cancel(reason?: unknown): Promise<void>;
}

export interface FileSizeOptions {
	readonly format?: "NMF1";
}
