export { Aes256GcmCipher, AES_256_GCM } from "./aes-256-gcm.js";
export {
	AesKeyRingProvider,
	AES_GCM_KEY_WRAP,
	type AesKeyRingProviderOptions,
} from "./aes-key-ring.provider.js";
export {
	CipherEngine,
	DEFAULT_MAX_BATCH_ITEMS,
	DEFAULT_MAX_PAYLOAD_BYTES,
} from "./cipher-engine.js";
export { jsonCodec, type CipherCodec } from "./cipher-codec.js";
export {
	authenticationFailed,
	CryptoError,
	isCryptoError,
	type CryptoErrorCode,
} from "./errors.js";
export { ENVELOPE_PREFIX, isCipherEnvelope } from "./envelope.js";
export { aadBytes, base64url, decodeUtf8, frame, parseBase64url, utf8 } from "./encoding.js";
export type {
	BatchDecryptItem,
	BatchDecryptOptions,
	BatchDecryptTextItem,
	BatchEncryptItem,
	BatchEncryptOptions,
	BatchEncryptTextItem,
	CipherAad,
	CipherAlgorithm,
	CipherDecryptInput,
	CipherEncryptInput,
	CipherEncryptResult,
	CipherEngineOptions,
	CipherEnvelopeInfo,
	CipherRegistration,
	DataKeyContext,
	DataKeyProvider,
	DecryptOptions,
	EncryptOptions,
	GeneratedDataKey,
	KeyProviderRegistration,
	ReencryptOptions,
	WrappedDataKey,
} from "./types.js";
