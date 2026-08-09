import { randomUUID } from "node:crypto";
import type { TokenCredential } from "@azure/core-auth";
import { describe, expect, it } from "vitest";
import { CipherEngine, type DataKeyProvider } from "../../src/core/index.js";
import { AwsKmsProvider } from "../../src/kms/aws/index.js";
import { AzureKeyVaultProvider } from "../../src/kms/azure/index.js";
import { GcpKmsProvider } from "../../src/kms/gcp/index.js";

const awsKeyId = process.env.NESTM_CRYPTO_LIVE_AWS_KEY_ID;
const gcpKeyName = process.env.NESTM_CRYPTO_LIVE_GCP_KEY_NAME;
const azureKeyId = process.env.NESTM_CRYPTO_LIVE_AZURE_KEY_ID;
const azureAccessToken = process.env.NESTM_CRYPTO_LIVE_AZURE_ACCESS_TOKEN;

async function verifyLiveProvider(alias: string, provider: DataKeyProvider): Promise<void> {
	const engine = new CipherEngine({
		providers: [{ name: alias, provider }],
		defaultProvider: alias,
	});
	const plaintext = `nestm-live-${randomUUID()}`;
	try {
		const envelope = await engine.encryptText(plaintext, {
			aad: "live-suite:v1",
			keyContext: "live-suite-key-context:v1",
		});
		expect(
			await engine.decryptText(envelope, {
				aad: "live-suite:v1",
				keyContext: "live-suite-key-context:v1",
			}),
		).toBe(plaintext);
		await expect(
			engine.decryptText(envelope, {
				aad: "wrong-live-suite",
				keyContext: "live-suite-key-context:v1",
			}),
		).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
	} finally {
		await engine.close();
	}
}

describe("credential-gated cloud KMS providers", () => {
	it.runIf(awsKeyId !== undefined)("round-trips through AWS KMS", async () => {
		await verifyLiveProvider(
			"aws-live",
			new AwsKmsProvider({
				keyId: awsKeyId!,
				clientConfig:
					process.env.AWS_REGION === undefined ? {} : { region: process.env.AWS_REGION },
			}),
		);
	});

	it.runIf(gcpKeyName !== undefined)("round-trips through Google Cloud KMS", async () => {
		await verifyLiveProvider(
			"gcp-live",
			new GcpKmsProvider({
				keyName: gcpKeyName!,
			}),
		);
	});

	it.runIf(azureKeyId !== undefined && azureAccessToken !== undefined)(
		"round-trips through Azure Key Vault or Managed HSM",
		async () => {
			const credential: TokenCredential = {
				getToken: async () => ({
					token: azureAccessToken!,
					expiresOnTimestamp: Number(
						process.env.NESTM_CRYPTO_LIVE_AZURE_TOKEN_EXPIRES_AT ?? Date.now() + 3_600_000,
					),
				}),
			};
			await verifyLiveProvider(
				"azure-live",
				new AzureKeyVaultProvider({
					keyId: azureKeyId!,
					credential,
				}),
			);
		},
	);
});
