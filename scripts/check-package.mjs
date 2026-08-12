import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(import.meta.dirname, "..");
const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const expectedExports = [
	".",
	"./core",
	"./fields",
	"./tenant",
	"./http",
	"./prisma",
	"./key-wrap/rsa",
	"./kms/aws",
	"./kms/gcp",
	"./kms/azure",
	"./testing",
	"./package.json",
];

for (const subpath of expectedExports) {
	if (manifest.exports?.[subpath] === undefined) {
		throw new Error(`Missing package export: ${subpath}`);
	}
}

for (const [subpath, target] of Object.entries(manifest.exports)) {
	if (typeof target === "string") continue;
	for (const file of Object.values(target)) {
		if (!existsSync(join(root, file))) {
			throw new Error(`Missing export artifact for ${subpath}: ${file}`);
		}
	}
}

const dist = join(root, "dist");
const files = readdirSync(dist, { recursive: true }).map(String);
if (files.some((file) => file.endsWith(".map"))) {
	throw new Error("Published build must not contain source or declaration maps");
}

const optionalPeers = [
	"@nestjs/common",
	"@nestjs/core",
	"@nestm/tenant",
	"@aws-sdk/client-kms",
	"@google-cloud/kms",
	"@azure/core-auth",
	"@azure/keyvault-keys",
	"class-transformer",
];
for (const peer of optionalPeers) {
	if (manifest.peerDependenciesMeta?.[peer]?.optional !== true) {
		throw new Error(`Integration peer must remain optional: ${peer}`);
	}
}
const coreSource = readFileSync(join(root, "dist/core/index.mjs"), "utf8");
for (const peer of optionalPeers) {
	if (coreSource.includes(peer)) {
		throw new Error(`The framework-neutral core unexpectedly imports optional peer ${peer}`);
	}
}

const core = await import(pathToFileURL(join(root, "dist/core/index.mjs")).href);
if (Object.keys(core).length === 0) throw new Error("The core entry point exports no values");

const rootEntry = await import(pathToFileURL(join(root, "dist/index.mjs")).href);
for (const name of ["CryptoModule", "CipherService"]) {
	if (typeof rootEntry[name] !== "function") {
		throw new Error(`Root entry point does not export ${name}`);
	}
}
