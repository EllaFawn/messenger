import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: [
      { test: { name: "crypto", root: "./packages/crypto", passWithNoTests: true } },
      { test: { name: "protocol", root: "./packages/protocol", passWithNoTests: true } },
      { test: { name: "server", root: "./packages/server", passWithNoTests: true } },
      { test: { name: "web", root: "./packages/web", passWithNoTests: true } },
    ],
  },
});
