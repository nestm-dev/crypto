#!/usr/bin/env node

import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv, createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const CHUNK_SIZE = 1_048_576;
const FILE_HEADER_BYTES = 52;
const DATA_HEADER_BYTES = 12;
const FINAL_HEADER_BYTES = 16;
const TAG_BYTES = 16;
const FILE_AAD_DIGEST_PREFIX = Buffer.from("nestm:nmf1:file-aad-digest:v1\0", "utf8");
const FRAME_AAD_PREFIX = Buffer.from("nestm:nmf1:frame-aad:v1\0", "utf8");
const KEY_CONTEXT_PREFIX = Buffer.from("nestm:nmf1:file-key-context:v1\0", "utf8");
const CONSTANT_FILE_HEADER = Buffer.from("4e4d46310100003400100000", "hex");

function parseHex(value, label) {
	assert.equal(typeof value, "string", `${label} must be a string`);
	assert.match(value, /^(?:[0-9a-f]{2})*$/, `${label} must be canonical lowercase hex`);
	return Buffer.from(value, "hex");
}

function lp(value) {
	assert.ok(value.byteLength <= 0xffff_fffe, "length-prefixed value is too large");
	const length = Buffer.alloc(4);
	length.writeUInt32BE(value.byteLength);
	return Buffer.concat([length, value]);
}

function digest(...parts) {
	const hash = createHash("sha256");
	for (const part of parts) hash.update(part);
	return hash.digest();
}

function encryptAesGcm(key, nonce, plaintext, aad) {
	const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_BYTES });
	cipher.setAAD(aad, { plaintextLength: plaintext.byteLength });
	return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

function decryptAesGcm(key, nonce, ciphertext, tag, aad) {
	const decipher = createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_BYTES });
	decipher.setAAD(aad, { plaintextLength: ciphertext.byteLength });
	decipher.setAuthTag(tag);
	return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function frameNonce(prefix, index) {
	const nonce = Buffer.alloc(12);
	prefix.copy(nonce);
	nonce.writeUInt32BE(index, 8);
	return nonce;
}

function frameAad(header, fileAad, frameHeader) {
	return Buffer.concat([FRAME_AAD_PREFIX, lp(header), lp(fileAad), lp(frameHeader)]);
}

export function buildDeterministicVector(input) {
	const plaintext = parseHex(input.plaintextHex, "input.plaintextHex");
	const fileAad = parseHex(input.fileAadHex, "input.fileAadHex");
	const dek = parseHex(input.dekHex, "input.dekHex");
	const noncePrefix = parseHex(input.noncePrefixHex, "input.noncePrefixHex");
	const wrapperNonce = parseHex(input.wrapperNonceHex, "input.wrapperNonceHex");
	const domainKey = parseHex(input.domainKeyHex, "input.domainKeyHex");
	assert.equal(dek.byteLength, 32, "fixture DEK must be 32 bytes");
	assert.equal(noncePrefix.byteLength, 8, "fixture nonce prefix must be 8 bytes");
	assert.equal(wrapperNonce.byteLength, 12, "fixture wrapper nonce must be 12 bytes");
	assert.equal(domainKey.byteLength, 32, "fixture domain key must be 32 bytes");

	const contextDigest = digest(FILE_AAD_DIGEST_PREFIX, lp(fileAad));
	const header = Buffer.concat([CONSTANT_FILE_HEADER, noncePrefix, contextDigest]);
	const wrappingContext = Buffer.concat([KEY_CONTEXT_PREFIX, lp(fileAad), lp(header)]);
	const wrappedDek = encryptAesGcm(domainKey, wrapperNonce, dek, wrappingContext);
	const wrappedKey = Buffer.concat([Buffer.of(1), wrapperNonce, wrappedDek]);
	const frames = [header];
	let dataFrameCount = 0;
	for (let offset = 0; offset < plaintext.byteLength; offset += CHUNK_SIZE) {
		const chunk = plaintext.subarray(offset, Math.min(offset + CHUNK_SIZE, plaintext.byteLength));
		const frameHeader = Buffer.alloc(DATA_HEADER_BYTES);
		frameHeader[0] = 1;
		frameHeader.writeUInt16BE(DATA_HEADER_BYTES, 2);
		frameHeader.writeUInt32BE(dataFrameCount, 4);
		frameHeader.writeUInt32BE(chunk.byteLength, 8);
		frames.push(
			frameHeader,
			encryptAesGcm(
				dek,
				frameNonce(noncePrefix, dataFrameCount),
				chunk,
				frameAad(header, fileAad, frameHeader),
			),
		);
		dataFrameCount += 1;
	}
	const finalHeader = Buffer.alloc(FINAL_HEADER_BYTES);
	finalHeader[0] = 2;
	finalHeader.writeUInt16BE(FINAL_HEADER_BYTES, 2);
	finalHeader.writeUInt32BE(dataFrameCount, 4);
	finalHeader.writeBigUInt64BE(BigInt(plaintext.byteLength), 8);
	frames.push(
		finalHeader,
		encryptAesGcm(
			dek,
			frameNonce(noncePrefix, dataFrameCount),
			Buffer.alloc(0),
			frameAad(header, fileAad, finalHeader),
		),
	);
	const nmf1 = Buffer.concat(frames);
	return {
		plaintext,
		fileAad,
		header,
		wrappingContext,
		wrappedKey,
		nmf1,
		dataFrameCount,
		ciphertextSha256: digest(nmf1).toString("hex"),
	};
}

function independentlyDecrypt(nmf1, fileAad, wrappedKey, domainKey) {
	assert.ok(nmf1.byteLength >= FILE_HEADER_BYTES, "truncated NMF1 file header");
	const header = nmf1.subarray(0, FILE_HEADER_BYTES);
	assert.deepEqual(header.subarray(0, 12), CONSTANT_FILE_HEADER, "non-canonical NMF1 header");
	const expectedContextDigest = digest(FILE_AAD_DIGEST_PREFIX, lp(fileAad));
	assert.deepEqual(header.subarray(20), expectedContextDigest, "file AAD digest mismatch");
	assert.equal(wrappedKey.byteLength, 61, "detached wrapper must be 61 bytes");
	assert.equal(wrappedKey[0], 1, "detached wrapper version must be one");
	const wrappingContext = Buffer.concat([KEY_CONTEXT_PREFIX, lp(fileAad), lp(header)]);
	const dek = decryptAesGcm(
		domainKey,
		wrappedKey.subarray(1, 13),
		wrappedKey.subarray(13, 45),
		wrappedKey.subarray(45),
		wrappingContext,
	);
	const noncePrefix = header.subarray(12, 20);
	const plaintext = [];
	let offset = FILE_HEADER_BYTES;
	let expectedIndex = 0;
	let total = 0n;
	let previousLength;
	for (;;) {
		assert.ok(offset + 4 <= nmf1.byteLength, "missing frame header");
		const type = nmf1[offset];
		const flags = nmf1[offset + 1];
		const headerLength = nmf1.readUInt16BE(offset + 2);
		assert.equal(flags, 0, "frame flags must be zero");
		if (type === 1) {
			assert.equal(headerLength, DATA_HEADER_BYTES, "data header must be 12 bytes");
			assert.ok(offset + DATA_HEADER_BYTES <= nmf1.byteLength, "truncated data header");
			const frameHeader = nmf1.subarray(offset, offset + DATA_HEADER_BYTES);
			const index = frameHeader.readUInt32BE(4);
			const length = frameHeader.readUInt32BE(8);
			assert.equal(index, expectedIndex, "data frame indices must be contiguous");
			assert.ok(length >= 1 && length <= CHUNK_SIZE, "invalid data frame length");
			if (previousLength !== undefined) {
				assert.equal(previousLength, CHUNK_SIZE, "a short data frame may only be last");
			}
			const bodyStart = offset + DATA_HEADER_BYTES;
			const tagStart = bodyStart + length;
			const end = tagStart + TAG_BYTES;
			assert.ok(end <= nmf1.byteLength, "truncated data frame body or tag");
			plaintext.push(
				decryptAesGcm(
					dek,
					frameNonce(noncePrefix, index),
					nmf1.subarray(bodyStart, tagStart),
					nmf1.subarray(tagStart, end),
					frameAad(header, fileAad, frameHeader),
				),
			);
			expectedIndex += 1;
			total += BigInt(length);
			previousLength = length;
			offset = end;
			continue;
		}
		assert.equal(type, 2, "unknown NMF1 frame type");
		assert.equal(headerLength, FINAL_HEADER_BYTES, "final header must be 16 bytes");
		const end = offset + FINAL_HEADER_BYTES + TAG_BYTES;
		assert.equal(end, nmf1.byteLength, "final frame must end at physical EOF");
		const finalHeader = nmf1.subarray(offset, offset + FINAL_HEADER_BYTES);
		assert.equal(finalHeader.readUInt32BE(4), expectedIndex, "final frame count mismatch");
		assert.equal(finalHeader.readBigUInt64BE(8), total, "final plaintext length mismatch");
		decryptAesGcm(
			dek,
			frameNonce(noncePrefix, expectedIndex),
			Buffer.alloc(0),
			nmf1.subarray(offset + FINAL_HEADER_BYTES, end),
			frameAad(header, fileAad, finalHeader),
		);
		return Buffer.concat(plaintext);
	}
}

export function verifyNmf1Fixture(fixture) {
	assert.equal(fixture.schemaVersion, 1, "unsupported fixture schema");
	assert.equal(fixture.format, "NMF1", "fixture format must be NMF1");
	assert.match(fixture.name, /^V\d{2}[a-z]?-[a-z0-9-]+$/, "fixture name is not canonical");
	const built = buildDeterministicVector(fixture.input);
	const expected = fixture.expected;
	assert.equal(built.header.toString("hex"), expected.headerHex, "header bytes differ");
	assert.equal(
		built.wrappingContext.toString("hex"),
		expected.providerWrappingContextHex,
		"provider wrapping context differs",
	);
	assert.equal(
		digest(built.wrappingContext).toString("hex"),
		expected.wrappingContextDigest,
		"wrapping-context digest differs",
	);
	assert.equal(expected.detachedKeyVersion, 1);
	assert.equal(expected.detachedKeyProvider, fixture.input.provider);
	assert.equal(expected.detachedKeyReference, fixture.input.keyReference);
	assert.equal(expected.wrappingAlgorithm, "A256GCMKW");
	assert.equal(built.wrappedKey.toString("hex"), expected.wrappedKeyHex, "wrapped DEK differs");
	assert.equal(built.nmf1.toString("hex"), expected.nmf1Hex, "NMF1 bytes differ");
	assert.equal(String(built.plaintext.byteLength), expected.plaintextBytes);
	assert.equal(String(built.nmf1.byteLength), expected.ciphertextBytes);
	assert.equal(built.dataFrameCount, expected.dataFrameCount);
	assert.equal(built.ciphertextSha256, expected.ciphertextSha256);
	assert.deepEqual(
		independentlyDecrypt(
			parseHex(expected.nmf1Hex, "expected.nmf1Hex"),
			built.fileAad,
			parseHex(expected.wrappedKeyHex, "expected.wrappedKeyHex"),
			parseHex(fixture.input.domainKeyHex, "input.domainKeyHex"),
		),
		built.plaintext,
		"independent decrypt did not recover the fixture plaintext",
	);
	return fixture.name;
}

export async function verifyNmf1VectorDirectory(directory) {
	const entries = (await readdir(directory, { withFileTypes: true }))
		.filter((entry) => entry.isFile() && entry.name.endsWith(".json"))
		.map((entry) => entry.name)
		.toSorted();
	assert.ok(entries.length > 0, "no NMF1 fixture files found");
	const names = [];
	for (const entry of entries) {
		const fixture = JSON.parse(await readFile(resolve(directory, entry), "utf8"));
		names.push(verifyNmf1Fixture(fixture));
	}
	assert.equal(new Set(names).size, names.length, "fixture names must be unique");
	return names;
}

const invokedPath =
	process.argv[1] === undefined ? undefined : pathToFileURL(resolve(process.argv[1])).href;
if (invokedPath === import.meta.url) {
	const scriptDirectory = dirname(fileURLToPath(import.meta.url));
	const vectorDirectory = resolve(scriptDirectory, "../tests/vectors/nmf1");
	try {
		const names = await verifyNmf1VectorDirectory(vectorDirectory);
		process.stdout.write(`verified ${names.length} NMF1 vectors: ${names.join(", ")}\n`);
	} catch (error) {
		process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
		process.exitCode = 1;
	}
}
