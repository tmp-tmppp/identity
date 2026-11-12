import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import tseslint from "typescript-eslint";

export default defineConfig(
  { ignores: ["coverage/", "reports/", "node_modules/", "helm/"] },
  {
    files: ["**/*.ts"],
    extends: [js.configs.recommended, tseslint.configs.recommendedTypeChecked],
    languageOptions: { parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname } },
    rules: {
      "@typescript-eslint/consistent-type-imports": "error",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", ignoreRestSiblings: true }],
    },
  },
  {
    files: ["**/*.js"],
    extends: [js.configs.recommended],
  },
  {
    files: ["tests/**/*.ts"],
    rules: {
      // Parsed JSON in tests is untyped on purpose.
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-member-access": "off",
      "@typescript-eslint/no-unsafe-argument": "off",
      "@typescript-eslint/no-unsafe-call": "off",
      "@typescript-eslint/no-unsafe-return": "off",
      "@typescript-eslint/no-explicit-any": "off",
    },
  },
);
