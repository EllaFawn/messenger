import { defineConfig } from "vitest/config";

// dist/ holds compiled copies of the test files (from `tsc -b`); run only the sources.
const exclude = ["**/node_modules/**", "**/dist/**"];

export default defineConfig({
  test: {
    projects: [
      { test: { name: "crypto", root: "./packages/crypto", passWithNoTests: true, exclude } },
      { test: { name: "protocol", root: "./packages/protocol", passWithNoTests: true, exclude } },
      { test: { name: "server", root: "./packages/server", passWithNoTests: true, exclude } },
      { test: { name: "web", root: "./packages/web", passWithNoTests: true, exclude } },
    ],
  },
});
