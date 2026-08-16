import { execFileSync } from "node:child_process";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	readdirSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const temporaryRoot = mkdtempSync(join(tmpdir(), "nestm-crypto-pack-"));
const packageDirectory = join(temporaryRoot, "package");
mkdirSync(packageDirectory);

try {
	run("pnpm", ["pack", "--pack-destination", packageDirectory], root);
	const tarballName = readdirSync(packageDirectory).find((file) => file.endsWith(".tgz"));
	if (!tarballName) throw new Error("pnpm pack did not produce a tarball");
	const tarball = join(packageDirectory, tarballName);

	testCoreConsumer(tarball);
	testIntegrationConsumer(tarball);
	verifyTarball(tarball);
} finally {
	rmSync(temporaryRoot, { force: true, recursive: true });
}

function testCoreConsumer(tarball) {
	const directory = join(temporaryRoot, "core-consumer");
	mkdirSync(directory);
	writeJson(join(directory, "package.json"), {
		name: "@nestm/crypto-core-consumer",
		private: true,
		type: "module",
	});
	run(
		"npm",
		[
			"install",
			"--ignore-scripts",
			"--no-audit",
			"--no-fund",
			"--legacy-peer-deps",
			tarball,
			"typescript@7.0.2",
			"@types/node@24.13.3",
		],
		directory,
	);
	writeFileSync(
		join(directory, "consumer.ts"),
		`import assert from "node:assert/strict";
import { generateKeySync } from "node:crypto";
import * as core from "@nestm/crypto/core";
import { fixedNonceSource } from "@nestm/crypto/testing";

if (Object.keys(core).length === 0) throw new Error("empty core entry");
const engine = new core.CipherEngine({
  defaultProvider: "packed",
  nonceSource: fixedNonceSource(new Uint8Array(8).fill(7)),
  providers: [{
    name: "packed",
    provider: new core.AesKeyRingProvider({
      activeKeyId: "packed-key",
      keys: { "packed-key": generateKeySync("aes", { length: 256 }) },
    }),
  }],
});
const encrypted = await engine.encryptText("packed core", { aad: "packed.test" });
assert.equal(await engine.decryptText(encrypted, { aad: "packed.test" }), "packed core");
const batch = await engine.encryptTextBatch([
  { plaintext: "first", aad: "packed.batch.first" },
  { plaintext: "second", aad: "packed.batch.second" },
]);
assert.deepEqual(await engine.decryptTextBatch([
  { envelope: batch[0] ?? "", aad: "packed.batch.first" },
  { envelope: batch[1] ?? "", aad: "packed.batch.second" },
]), ["first", "second"]);
const packedCodec = core.jsonCodec<{ readonly value: string }>((value) => {
  if (typeof value !== "object" || value === null || !("value" in value) || typeof value.value !== "string") {
    throw new TypeError("invalid packed value");
  }
  return { value: value.value };
});
const encodedValue = await engine.encryptValue({ value: "typed" }, packedCodec);
assert.deepEqual(await engine.decryptValue(encodedValue, packedCodec), { value: "typed" });
assert.equal(engine.inspect(encrypted).authenticated, false);
await engine.close();
`,
	);
	writeTypeScriptConfig(directory);
	run(join(directory, "node_modules/.bin/tsc"), ["-p", "tsconfig.json"], directory);
	run(process.execPath, ["dist/consumer.js"], directory);

	for (const absent of ["@nestjs", "@nestm/tenant", "@aws-sdk", "@google-cloud", "@azure"]) {
		if (existsSync(join(directory, "node_modules", ...absent.split("/")))) {
			throw new Error(`Core-only consumer unexpectedly installed ${absent}`);
		}
	}
}

function testIntegrationConsumer(tarball) {
	const directory = join(temporaryRoot, "integration-consumer");
	mkdirSync(directory);
	writeJson(join(directory, "package.json"), {
		name: "@nestm/crypto-integration-consumer",
		private: true,
		type: "module",
	});

	const tenantPackage = resolveTenantPackage();
	run(
		"npm",
		[
			"install",
			"--ignore-scripts",
			"--no-audit",
			"--no-fund",
			"--legacy-peer-deps",
			tarball,
			tenantPackage,
			"typescript@7.0.2",
			"@types/node@24.13.3",
			"@nestjs/common@12.0.0-alpha.5",
			"@nestjs/core@12.0.0-alpha.5",
			"@nestjs/testing@12.0.0-alpha.5",
			"class-transformer@0.5.1",
			"@standard-schema/spec@1.1.0",
			"reflect-metadata@0.2.2",
			"rxjs@7.8.2",
			"@aws-sdk/client-kms@3.1106.0",
			"@google-cloud/kms@5.7.0",
			"@azure/core-auth@1.11.0",
			"@azure/keyvault-keys@4.10.2",
		],
		directory,
	);

	const subpaths = [
		"@nestm/crypto",
		"@nestm/crypto/core",
		"@nestm/crypto/keys",
		"@nestm/crypto/password",
		"@nestm/crypto/stream",
		"@nestm/crypto/fields",
		"@nestm/crypto/tenant",
		"@nestm/crypto/http",
		"@nestm/crypto/prisma",
		"@nestm/crypto/key-wrap/rsa",
		"@nestm/crypto/kms/aws",
		"@nestm/crypto/kms/gcp",
		"@nestm/crypto/kms/azure",
		"@nestm/crypto/testing",
	];
	writeFileSync(
		join(directory, "consumer.ts"),
		[
			'import "reflect-metadata";',
			'import assert from "node:assert/strict";',
			'import { generateKeySync } from "node:crypto";',
			'import { Module } from "@nestjs/common";',
			'import { Test } from "@nestjs/testing";',
			'import { TENANT_CONTEXT_READER, type TenantContextReader, type TenantSnapshot } from "@nestm/tenant/context";',
			'import manifest from "@nestm/crypto/package.json" with { type: "json" };',
			...subpaths.map(
				(subpath, index) => `import * as entry${index} from ${JSON.stringify(subpath)};`,
			),
			`const entries = [${subpaths.map((_, index) => `entry${index}`).join(", ")}];`,
			'if (entries.some((entry) => Object.keys(entry).length === 0)) throw new Error("empty entry");',
			'assert.equal(manifest.name, "@nestm/crypto");',
			// The new subpaths must work from a packed tarball, not just from source.
			"const packedKeyPair = entry2.generateX25519KeyPair();",
			'const packedDek = generateKeySync("aes", { length: 256 });',
			'const packedRecord = entry2.wrapKeyToRecipient(packedKeyPair.publicKey, packedDek, { recipientId: "user:packed" });',
			"assert.equal(entry2.unwrapKeyFromRecipient(packedKeyPair.privateKey, packedRecord).symmetricKeySize, 32);",
			'const packedSealed = entry4.sealChunked(packedDek, Buffer.from("packed stream"), { keyReference: "ws:packed", wrapRecords: [packedRecord] });',
			'assert.equal(Buffer.from(entry4.openChunked(packedDek, packedSealed)).toString(), "packed stream");',
			"assert.equal(entry4.inspectChunked(packedSealed).wrapRecords.length, 1);",
			"const packedKdf = entry3.createPasswordKdf();",
			"const packedSalt = entry3.generatePasswordSalt();",
			'const packedKek = await packedKdf.derive({ password: "packed pw", salt: packedSalt, kdf: entry3.PASSWORD_KDF_SCRYPT_DEFAULT });',
			"assert.equal(packedKek.symmetricKeySize, 32);",
			"const packedRecovery = entry3.generateRecoveryCode();",
			"assert.deepEqual(entry3.parseRecoveryCode(packedRecovery.code), packedRecovery.secret);",
			'assert.equal(entry1.isCipherEnvelope("nmc1.a.b.c.d.e"), true);',
			'const moduleRef = await Test.createTestingModule({ imports: [entry0.CryptoModule.forRoot({ defaultProvider: "packed", providers: [{ name: "packed", provider: new entry0.AesKeyRingProvider({ activeKeyId: "packed-key", keys: { "packed-key": generateKeySync("aes", { length: 256 }) } }) }] })] }).compile();',
			"const cipher = moduleRef.get(entry0.CipherService);",
			"const fieldCipher = moduleRef.get(entry0.FieldCipherService);",
			'class PackedSecret { secret = "packed field"; }',
			'entry0.EncryptedField("packed.field")(PackedSecret.prototype, "secret");',
			"const packedSecret = new PackedSecret();",
			"await fieldCipher.encryptFieldsInPlace(packedSecret);",
			"assert.match(packedSecret.secret, /^nmc1\\./u);",
			"await fieldCipher.decryptFieldsInPlace(packedSecret);",
			'assert.equal(packedSecret.secret, "packed field");',
			'const encrypted = await cipher.encryptText("packed Nest", { aad: "packed.nest" });',
			'assert.equal(await cipher.decryptText(encrypted, { aad: "packed.nest" }), "packed Nest");',
			"await moduleRef.close();",
			'let activeTenantId = "tenant-a";',
			'const snapshot = (): TenantSnapshot => ({ id: activeTenantId, settings: {}, source: "packed" });',
			'const tenantReader: TenantContextReader = { current: () => ({ mode: "tenant", tenant: snapshot() }), require: () => ({ mode: "tenant", tenant: snapshot() }), requireTenant: snapshot, requireTenantId: () => activeTenantId, requireTenantTarget: () => ({ authority: "tenant", tenant: snapshot() }) };',
			"class PackedContextModule {}",
			"Module({ providers: [{ provide: TENANT_CONTEXT_READER, useValue: tenantReader }], exports: [TENANT_CONTEXT_READER] })(PackedContextModule);",
			'const tenantModuleRef = await Test.createTestingModule({ imports: [entry6.TenantCryptoModule.forRoot({ namespace: "packed-app", imports: [PackedContextModule, entry0.CryptoModule.forRoot({ defaultProvider: "packed-tenant", providers: [{ name: "packed-tenant", provider: new entry0.AesKeyRingProvider({ activeKeyId: "packed-tenant-key", keys: { "packed-tenant-key": generateKeySync("aes", { length: 256 }) } }) }] })] })] }).compile();',
			"const tenantCipher = tenantModuleRef.get(entry6.TenantCipherService);",
			'const tenantEnvelope = await tenantCipher.encryptText("tenant secret", { purpose: "packed.tenant" });',
			'activeTenantId = "tenant-b";',
			'await assert.rejects(() => tenantCipher.decryptText(tenantEnvelope, { purpose: "packed.tenant" }), (error: unknown) => entry0.isCryptoError(error, "AUTHENTICATION_FAILED"));',
			'activeTenantId = "tenant-a";',
			'assert.equal(await tenantCipher.decryptText(tenantEnvelope, { purpose: "packed.tenant" }), "tenant secret");',
			"const tenantFields = tenantModuleRef.get(entry6.TenantFieldCipherService);",
			'class PackedHttpSecret { secret = "packed HTTP"; }',
			'entry0.EncryptedField("packed.http")(PackedHttpSecret.prototype, "secret");',
			"const packedHttpSecret = new PackedHttpSecret();",
			"const httpPipe = new entry7.TenantEncryptFieldsPipe(tenantFields);",
			'await httpPipe.transform(packedHttpSecret, { type: "body", metatype: PackedHttpSecret });',
			"assert.match(packedHttpSecret.secret, /^nmc1\\./u);",
			"await tenantFields.decryptFieldsInPlace(packedHttpSecret);",
			'assert.equal(packedHttpSecret.secret, "packed HTTP");',
			'const prismaEncryption = entry8.createTenantPrismaFieldEncryption(tenantCipher, { registry: { PackedRecord: { secret: { purpose: "packed.prisma" } } } });',
			'const prismaArgs = { data: { secret: "packed Prisma" } };',
			'await prismaEncryption.encryptWriteArgs({ model: "PackedRecord", operation: "create", args: prismaArgs });',
			"assert.match(prismaArgs.data.secret, /^nmc1\\./u);",
			'await prismaEncryption.assertWriteArgsEncrypted({ model: "PackedRecord", operation: "create", args: prismaArgs });',
			'assert.equal(await tenantCipher.decryptText(prismaArgs.data.secret, { purpose: "packed.prisma" }), "packed Prisma");',
			"await tenantModuleRef.close();",
		].join("\n"),
	);
	writeTypeScriptConfig(directory);
	run(join(directory, "node_modules/.bin/tsc"), ["-p", "tsconfig.json"], directory);
	run(process.execPath, ["dist/consumer.js"], directory);
}

function resolveTenantPackage() {
	if (process.env.NESTM_TENANT_PACKAGE) return process.env.NESTM_TENANT_PACKAGE;
	const sibling = resolve(root, "../tenant");
	if (existsSync(join(sibling, "package.json"))) {
		const destination = join(temporaryRoot, "tenant-package");
		mkdirSync(destination);
		run("pnpm", ["pack", "--pack-destination", destination], sibling);
		const name = readdirSync(destination).find((file) => file.endsWith(".tgz"));
		if (!name) throw new Error("Packing sibling @nestm/tenant produced no tarball");
		return join(destination, name);
	}
	return "@nestm/tenant@>=0.1.0-alpha.3 <0.2.0";
}

function verifyTarball(tarball) {
	const packed = execFileSync("tar", ["-tzf", tarball], { encoding: "utf8" });
	for (const forbidden of [
		"package/src/",
		"package/tests/",
		".spec.",
		".test.",
		".js.map",
		".mjs.map",
		".d.ts.map",
		".d.mts.map",
	]) {
		if (packed.includes(forbidden)) {
			throw new Error(`Packed tarball contains forbidden content: ${forbidden}`);
		}
	}
	const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
	if (manifest.name !== "@nestm/crypto") throw new Error("Unexpected package name");
}

function writeTypeScriptConfig(directory) {
	writeJson(join(directory, "tsconfig.json"), {
		compilerOptions: {
			module: "NodeNext",
			moduleResolution: "NodeNext",
			resolveJsonModule: true,
			target: "ES2023",
			strict: true,
			skipLibCheck: false,
			outDir: "dist",
			types: ["node"],
		},
		include: ["consumer.ts"],
	});
}

function writeJson(path, value) {
	writeFileSync(path, `${JSON.stringify(value, undefined, 2)}\n`);
}

function run(command, arguments_, cwd) {
	execFileSync(command, arguments_, { cwd, env: process.env, stdio: "inherit" });
}
