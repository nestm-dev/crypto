import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		globals: true,
		environment: "node",
		include: ["src/**/*.spec.ts", "tests/**/*.test.ts", "scripts/**/*.spec.mjs"],
		exclude: ["tests/live/**/*.test.ts", "tests/packed/**"],
		clearMocks: true,
		restoreMocks: true,
		testTimeout: 20_000,
		hookTimeout: 20_000,
		pool: "forks",
		coverage: {
			provider: "v8",
			reportsDirectory: "./coverage",
			include: ["src/**/*.ts"],
			exclude: ["src/index.ts", "src/**/index.ts", "src/testing/**"],
		},
	},
});
