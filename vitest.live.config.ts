import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		globals: true,
		environment: "node",
		include: ["tests/live/**/*.test.ts"],
		clearMocks: true,
		restoreMocks: true,
		testTimeout: 60_000,
		hookTimeout: 60_000,
		pool: "forks",
	},
});
