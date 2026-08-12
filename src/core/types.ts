import type { KeyObject } from "node:crypto";

export type CipherAad = string | Uint8Array;

export interface CipherRegistration {
	readonly name: string;
	readonly cipher: CipherAlgorithm;
}

export interface KeyProviderRegistration {
	readonly name: string;
	readonly provider: DataKeyProvider;
}

export interface CipherAlgorithm {
	readonly name: string;
	readonly keyLength: number;
	readonly nonceLength: number;
	readonly tagLength: number;
	encrypt(input: CipherEncryptInput): CipherEncryptResult;
	decrypt(input: CipherDecryptInput): Uint8Array;
}

export interface CipherEncryptInput {
	readonly plaintext: Uint8Array;
	readonly key: KeyObject;
	readonly nonce: Uint8Array;
	readonly aad: Uint8Array;
}

export interface CipherEncryptResult {
	readonly ciphertext: Uint8Array;
	readonly tag: Uint8Array;
}

export interface CipherDecryptInput {
	readonly ciphertext: Uint8Array;
	readonly key: KeyObject;
	readonly nonce: Uint8Array;
	readonly tag: Uint8Array;
	readonly aad: Uint8Array;
}

export interface DataKeyContext {
	readonly wrappingContext: Uint8Array;
	readonly signal?: AbortSignal;
}

export interface GeneratedDataKey {
	readonly plaintextKey: KeyObject;
	readonly wrappedKey: Uint8Array;
	readonly keyReference: string;
	readonly wrappingAlgorithm: string;
}

export interface WrappedDataKey {
	readonly wrappedKey: Uint8Array;
	readonly keyReference: string;
	readonly wrappingAlgorithm: string;
}

export interface DataKeyProvider {
	generateDataKey(context: DataKeyContext): Promise<GeneratedDataKey>;
	unwrapDataKey(dataKey: WrappedDataKey, context: DataKeyContext): Promise<KeyObject>;
	close?(): void | Promise<void>;
}

export interface CipherEngineOptions {
	readonly providers: readonly KeyProviderRegistration[];
	readonly defaultProvider: string;
	readonly ciphers?: readonly CipherRegistration[];
	readonly defaultCipher?: string;
	readonly maxPayloadBytes?: number;
	readonly maxBatchItems?: number;
	readonly maxBatchBytes?: number;
	/** Test seam. Production callers should use the default CSPRNG. */
	readonly nonceSource?: (length: number) => Uint8Array;
}

export interface EncryptOptions {
	readonly aad?: CipherAad;
	readonly keyContext?: CipherAad;
	readonly provider?: string;
	readonly cipher?: string;
	readonly signal?: AbortSignal;
}

export interface BatchEncryptItem {
	readonly plaintext: Uint8Array;
	readonly aad?: CipherAad;
}

export interface BatchEncryptTextItem {
	readonly plaintext: string;
	readonly aad?: CipherAad;
}

export interface BatchEncryptOptions extends Omit<EncryptOptions, "aad"> {}

export interface DecryptOptions {
	readonly aad?: CipherAad;
	readonly keyContext?: CipherAad;
	readonly allowedProviders?: readonly string[];
	readonly signal?: AbortSignal;
}

export interface BatchDecryptItem {
	readonly envelope: string;
	readonly aad?: CipherAad;
}

export interface BatchDecryptTextItem {
	readonly envelope: string;
	readonly aad?: CipherAad;
}

export interface BatchDecryptOptions extends Omit<DecryptOptions, "aad"> {}

export interface ReencryptOptions extends DecryptOptions {
	readonly provider?: string;
	readonly cipher?: string;
}

export interface CipherEnvelopeInfo {
	readonly version: 1;
	readonly cipher: string;
	readonly provider: string;
	readonly keyReference: string;
	readonly wrappingAlgorithm: string;
	readonly ciphertextBytes: number;
	readonly authenticated: false;
}
