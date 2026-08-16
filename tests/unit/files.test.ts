import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

describe("NMF1 conformance vectors", () => {
	it("pass the independent serializer, wrapper, parser, and decrypt verifier", () => {
		const verifier = fileURLToPath(
			new URL("../../scripts/verify-nmf1-vectors.mjs", import.meta.url),
		);
		const output = execFileSync(process.execPath, [verifier], {
			encoding: "utf8",
			env: { ...process.env, FORCE_COLOR: "0" },
		});

		expect(output).toBe(
			"verified 10 NMF1 vectors: V01-empty, V02-one-byte, V03-mixed-binary, " +
				"V04-chunk-minus-one, V05-exact-chunk, V06-chunk-plus-one, " +
				"V07-two-chunks-plus-seventeen, V08-null-workspace, V09a-owner-context-a, " +
				"V09b-owner-context-b\n",
		);
	});
});
