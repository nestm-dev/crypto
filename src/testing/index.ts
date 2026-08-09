export function fixedNonceSource(noncePrefix: Uint8Array): (length: number) => Uint8Array {
	const copy = new Uint8Array(noncePrefix);
	return (length: number): Uint8Array => {
		if (copy.byteLength !== length) {
			throw new Error(`Expected a ${copy.byteLength}-byte nonce request but received ${length}.`);
		}
		return new Uint8Array(copy);
	};
}
