export type CryptoErrorCode =
	| "CONFIGURATION"
	| "INVALID_ARGUMENT"
	| "MALFORMED_ENVELOPE"
	| "UNSUPPORTED_VERSION"
	| "UNSUPPORTED_CIPHER"
	| "PROVIDER_NOT_FOUND"
	| "KEY_NOT_FOUND"
	| "INVALID_KEY"
	| "KEY_PROVIDER"
	| "AUTHENTICATION_FAILED"
	| "LIMIT_EXCEEDED"
	| "ABORTED"
	| "TENANT_POLICY"
	| "FIELD_POLICY"
	| "CIPHER_FAILURE";

class SanitizedCryptoCause extends Error {
	readonly code?: string | number;
	readonly statusCode?: number;

	constructor(cause: unknown) {
		super("An underlying operation failed.");
		this.name = "Error";
		try {
			if (typeof cause !== "object" || cause === null) return;
			const safeNames = new Set([
				"AbortError",
				"AccessDeniedException",
				"BadParameter",
				"DependencyTimeoutException",
				"Error",
				"IncorrectKeyException",
				"InvalidCiphertextException",
				"KMSInternalException",
				"NotFoundException",
				"RangeError",
				"RestError",
				"ServiceUnavailableException",
				"ThrottlingException",
				"TypeError",
			]);
			if ("name" in cause && typeof cause.name === "string" && safeNames.has(cause.name)) {
				this.name = cause.name;
			}
			if ("code" in cause && typeof cause.code === "number") {
				this.code = cause.code;
			}
			if (
				"statusCode" in cause &&
				typeof cause.statusCode === "number" &&
				Number.isInteger(cause.statusCode)
			) {
				this.statusCode = cause.statusCode;
			}
		} catch {
			// Error causes cross an extension boundary. Hostile proxies and accessors must
			// never replace the library's redacted failure with their own exception.
		}
	}
}

export class CryptoError extends Error {
	constructor(
		public readonly code: CryptoErrorCode,
		message: string,
		options?: ErrorOptions,
	) {
		super(
			message,
			options?.cause === undefined ? undefined : { cause: new SanitizedCryptoCause(options.cause) },
		);
		this.name = new.target.name;
	}
}

export function isCryptoError(error: unknown, code?: CryptoErrorCode): error is CryptoError {
	return error instanceof CryptoError && (code === undefined || error.code === code);
}

export function authenticationFailed(options?: ErrorOptions): CryptoError {
	return new CryptoError("AUTHENTICATION_FAILED", "Ciphertext authentication failed.", options);
}

export function throwIfAborted(signal?: AbortSignal): void {
	if (signal?.aborted) {
		throw new CryptoError("ABORTED", "The cryptographic operation was aborted.", {
			cause: signal.reason,
		});
	}
}

export async function providerCall<Result>(
	operation: () => Promise<Result>,
	signal?: AbortSignal,
): Promise<Result> {
	throwIfAborted(signal);
	try {
		const pending = Promise.resolve().then(() => {
			throwIfAborted(signal);
			return operation();
		});
		const result =
			signal === undefined
				? await pending
				: await new Promise<Result>((resolve, reject) => {
						let settled = false;
						const finish = (callback: () => void): void => {
							if (settled) return;
							settled = true;
							signal.removeEventListener("abort", onAbort);
							callback();
						};
						const onAbort = (): void => {
							finish(() =>
								reject(new CryptoError("ABORTED", "The cryptographic operation was aborted.")),
							);
						};
						signal.addEventListener("abort", onAbort, { once: true });
						if (signal.aborted) onAbort();
						void pending.then(
							(value) => finish(() => resolve(value)),
							(error: unknown) => finish(() => reject(error)),
						);
					});
		throwIfAborted(signal);
		return result;
	} catch (error: unknown) {
		if (signal?.aborted) throwIfAborted(signal);
		if (isCryptoError(error, "ABORTED")) {
			throw new CryptoError("ABORTED", "The cryptographic operation was aborted.", {
				cause: error,
			});
		}
		if (isCryptoError(error, "AUTHENTICATION_FAILED")) {
			throw authenticationFailed({ cause: error });
		}
		if (isCryptoError(error, "KEY_NOT_FOUND")) {
			throw new CryptoError("KEY_NOT_FOUND", "The wrapping key was not found.", {
				cause: error,
			});
		}
		if (isCryptoError(error, "INVALID_KEY")) {
			throw new CryptoError("INVALID_KEY", "The key provider returned invalid key material.", {
				cause: error,
			});
		}
		if (isCryptoError(error, "LIMIT_EXCEEDED")) {
			throw new CryptoError("LIMIT_EXCEEDED", "The key provider request exceeded its limit.", {
				cause: error,
			});
		}
		throw new CryptoError("KEY_PROVIDER", "The key provider operation failed.", {
			cause: error,
		});
	}
}
