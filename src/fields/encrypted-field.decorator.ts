import { CryptoError } from "../core/index.js";

export const ENCRYPTED_FIELDS_METADATA = Symbol("@nestm/crypto/encrypted-fields");

export interface EncryptedFieldMetadata {
	readonly propertyKey: string | symbol;
	readonly purpose: string;
}

interface MetadataHost {
	[ENCRYPTED_FIELDS_METADATA]?: Map<string | symbol, EncryptedFieldMetadata>;
}

export function assertFieldPurpose(purpose: string): void {
	if (
		typeof purpose !== "string" ||
		purpose.length === 0 ||
		Buffer.byteLength(purpose, "utf8") > 255 ||
		purpose.trim() !== purpose ||
		/\p{Cc}/u.test(purpose)
	) {
		throw new CryptoError(
			"FIELD_POLICY",
			"An encrypted field purpose must be a printable value of at most 255 UTF-8 bytes.",
		);
	}
}

export function EncryptedField(purpose: string): PropertyDecorator {
	assertFieldPurpose(purpose);
	return (target: object, propertyKey: string | symbol): void => {
		const host = target as MetadataHost;
		let metadata = Object.prototype.hasOwnProperty.call(host, ENCRYPTED_FIELDS_METADATA)
			? host[ENCRYPTED_FIELDS_METADATA]
			: undefined;
		if (!metadata) {
			metadata = new Map();
			Object.defineProperty(host, ENCRYPTED_FIELDS_METADATA, {
				value: metadata,
				configurable: false,
				enumerable: false,
				writable: false,
			});
		}
		metadata.set(propertyKey, Object.freeze({ propertyKey, purpose }));
	};
}

export function getEncryptedFieldMetadata(instance: object): readonly EncryptedFieldMetadata[] {
	const levels: object[] = [];
	let prototype = Object.getPrototypeOf(instance) as object | null;
	while (prototype && prototype !== Object.prototype) {
		levels.unshift(prototype);
		prototype = Object.getPrototypeOf(prototype) as object | null;
	}
	const result = new Map<string | symbol, EncryptedFieldMetadata>();
	for (const level of levels) {
		if (!Object.prototype.hasOwnProperty.call(level, ENCRYPTED_FIELDS_METADATA)) continue;
		const metadata = (level as MetadataHost)[ENCRYPTED_FIELDS_METADATA];
		if (!metadata) continue;
		for (const [key, value] of metadata) result.set(key, value);
	}
	return Object.freeze([...result.values()]);
}
