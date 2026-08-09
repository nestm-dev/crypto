import { createCipheriv, createDecipheriv } from "node:crypto";
import { authenticationFailed, CryptoError } from "./errors.js";
import type {
	CipherAlgorithm,
	CipherDecryptInput,
	CipherEncryptInput,
	CipherEncryptResult,
} from "./types.js";

export const AES_256_GCM = "AES-256-GCM";

function assertKey(input: CipherEncryptInput | CipherDecryptInput): void {
	if (input.key.type !== "secret" || input.key.symmetricKeySize !== 32) {
		throw new CryptoError("INVALID_KEY", "AES-256-GCM requires a 32-byte secret key.");
	}
	if (input.nonce.byteLength !== 12) {
		throw new CryptoError("INVALID_ARGUMENT", "AES-256-GCM requires a 12-byte nonce.");
	}
}

export class Aes256GcmCipher implements CipherAlgorithm {
	readonly name = AES_256_GCM;
	readonly keyLength = 32;
	readonly nonceLength = 12;
	readonly tagLength = 16;

	encrypt(input: CipherEncryptInput): CipherEncryptResult {
		assertKey(input);
		try {
			const cipher = createCipheriv("aes-256-gcm", input.key, input.nonce, {
				authTagLength: this.tagLength,
			});
			cipher.setAAD(input.aad, { plaintextLength: input.plaintext.byteLength });
			const ciphertext = Buffer.concat([cipher.update(input.plaintext), cipher.final()]);
			return {
				ciphertext: new Uint8Array(ciphertext),
				tag: new Uint8Array(cipher.getAuthTag()),
			};
		} catch (error: unknown) {
			if (error instanceof CryptoError) throw error;
			throw new CryptoError("CIPHER_FAILURE", "Encryption failed.", { cause: error });
		}
	}

	decrypt(input: CipherDecryptInput): Uint8Array {
		assertKey(input);
		if (input.tag.byteLength !== this.tagLength) throw authenticationFailed();
		let first: Buffer | undefined;
		let last: Buffer | undefined;
		let raw: Buffer | undefined;
		try {
			const decipher = createDecipheriv("aes-256-gcm", input.key, input.nonce, {
				authTagLength: this.tagLength,
			});
			decipher.setAAD(input.aad, { plaintextLength: input.ciphertext.byteLength });
			decipher.setAuthTag(input.tag);
			first = decipher.update(input.ciphertext);
			last = decipher.final();
			raw = Buffer.concat([first, last]);
			return new Uint8Array(raw);
		} catch (error: unknown) {
			throw authenticationFailed({ cause: error });
		} finally {
			first?.fill(0);
			last?.fill(0);
			raw?.fill(0);
		}
	}
}
