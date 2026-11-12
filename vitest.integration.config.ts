import { defineConfig } from "vitest/config";

// Tests against the real identity provider: compose.yaml builds the image and starts it with its database
// (needs a running Docker daemon; the first build takes a few minutes).
export default defineConfig({
  test: {
    include: ["tests/integration/**/*.test.ts"],
    testTimeout: 60_000,
    hookTimeout: 600_000,
    fileParallelism: false,
  },
});
