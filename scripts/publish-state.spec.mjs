import { describe, expect, it } from "vitest";

import { resolvePrereleaseTag } from "./publish-state.mjs";

describe("resolvePrereleaseTag", () => {
	it("uses the active Changesets prerelease tag", () => {
		expect(resolvePrereleaseTag("0.1.0-alpha.1", { mode: "pre", tag: "alpha" })).toBe("alpha");
	});

	it("allows stable versions outside prerelease mode", () => {
		expect(resolvePrereleaseTag("1.0.0", undefined)).toBeUndefined();
	});

	it("rejects prerelease state mismatches", () => {
		expect(() => resolvePrereleaseTag("0.1.0-alpha.1", undefined)).toThrow(
			"requires Changesets pre mode",
		);
		expect(() => resolvePrereleaseTag("0.1.0-beta.1", { mode: "pre", tag: "alpha" })).toThrow(
			"does not match Changesets tag alpha",
		);
		expect(() => resolvePrereleaseTag("1.0.0", { mode: "pre", tag: "alpha" })).toThrow(
			"cannot publish in Changesets pre mode",
		);
	});

	it("rejects invalid inputs", () => {
		expect(() => resolvePrereleaseTag(undefined, undefined)).toThrow(TypeError);
		expect(() => resolvePrereleaseTag("0.1.0-alpha.0", { mode: "pre", tag: "" })).toThrow(
			"non-empty tag",
		);
	});
});
