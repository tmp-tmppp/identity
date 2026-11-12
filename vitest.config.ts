import { defineConfig } from "vitest/config";

// Static checks of the realm file and the image definition; no network and no Docker. The tests against a real
// Keycloak live in tests/integration and run with "npm run test:integration" (vitest.integration.config.ts).
export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    exclude: ["tests/integration/**", "node_modules/**"],
    reporters: ["default", "junit"],
    outputFile: { junit: "reports/junit.xml" },
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      reporter: ["text", "lcov", "json-summary"],
      reportsDirectory: "coverage",
      thresholds: { lines: 80, functions: 80, statements: 80 },
    },
  },
});
