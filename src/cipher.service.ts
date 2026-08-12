import { Inject, Injectable, type OnModuleDestroy } from "@nestjs/common";
import {
	type BatchDecryptItem,
	type BatchDecryptOptions,
	type BatchDecryptTextItem,
	type BatchEncryptItem,
	type BatchEncryptOptions,
	type BatchEncryptTextItem,
	type CipherCodec,
	CipherEngine,
	type CipherEnvelopeInfo,
	type DecryptOptions,
	type EncryptOptions,
	type ReencryptOptions,
} from "./core/index.js";
import { CIPHER_ENGINE } from "./crypto.tokens.js";

@Injectable()
export class CipherService implements OnModuleDestroy {
	readonly #engine: CipherEngine;

	constructor(@Inject(CIPHER_ENGINE) engine: CipherEngine) {
		this.#engine = engine;
	}

	get defaultProvider(): string {
		return this.#engine.defaultProvider;
	}

	get maxBatchItems(): number {
		return this.#engine.maxBatchItems;
	}

	hasProvider(name: string): boolean {
		return this.#engine.hasProvider(name);
	}

	encryptBytes(plaintext: Uint8Array, options?: EncryptOptions): Promise<string> {
		return this.#engine.encryptBytes(plaintext, options);
	}

	encryptText(plaintext: string, options?: EncryptOptions): Promise<string> {
		return this.#engine.encryptText(plaintext, options);
	}

	encryptBatch(
		items: readonly BatchEncryptItem[],
		options?: BatchEncryptOptions,
	): Promise<readonly string[]> {
		return this.#engine.encryptBatch(items, options);
	}

	encryptTextBatch(
		items: readonly BatchEncryptTextItem[],
		options?: BatchEncryptOptions,
	): Promise<readonly string[]> {
		return this.#engine.encryptTextBatch(items, options);
	}

	encryptValue<Value>(
		value: Value,
		codec: CipherCodec<Value>,
		options?: EncryptOptions,
	): Promise<string> {
		return this.#engine.encryptValue(value, codec, options);
	}

	decryptBytes(envelope: string, options?: DecryptOptions): Promise<Uint8Array> {
		return this.#engine.decryptBytes(envelope, options);
	}

	decryptText(envelope: string, options?: DecryptOptions): Promise<string> {
		return this.#engine.decryptText(envelope, options);
	}

	decryptBatch(
		items: readonly BatchDecryptItem[],
		options?: BatchDecryptOptions,
	): Promise<readonly Uint8Array[]> {
		return this.#engine.decryptBatch(items, options);
	}

	decryptTextBatch(
		items: readonly BatchDecryptTextItem[],
		options?: BatchDecryptOptions,
	): Promise<readonly string[]> {
		return this.#engine.decryptTextBatch(items, options);
	}

	decryptValue<Value>(
		envelope: string,
		codec: CipherCodec<Value>,
		options?: DecryptOptions,
	): Promise<Value> {
		return this.#engine.decryptValue(envelope, codec, options);
	}

	reencrypt(envelope: string, options?: ReencryptOptions): Promise<string> {
		return this.#engine.reencrypt(envelope, options);
	}

	inspect(envelope: string): CipherEnvelopeInfo {
		return this.#engine.inspect(envelope);
	}

	async onModuleDestroy(): Promise<void> {
		await this.#engine.close();
	}
}
