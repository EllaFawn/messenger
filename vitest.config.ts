import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// dist/ holds compiled copies of the test files (from `tsc -b`); run only the sources.
const exclude = ["**/node_modules/**", "**/dist/**"];

// The workspace packages export their compiled dist/ output, which is what
// Node runs. Tests resolve them to source instead, so they never depend on a
// build being present or up to date.
const alias = {
  "@messager/crypto": fileURLToPath(new URL("./packages/crypto/src/index.ts", import.meta.url)),
  "@messager/protocol": fileURLToPath(new URL("./packages/protocol/src/index.ts", import.meta.url)),
};

function project(name: string) {
  return {
    resolve: { alias },
    test: { name, root: `./packages/${name}`, passWithNoTests: true, exclude },
  };
}

export default defineConfig({
  test: {
    projects: [project("crypto"), project("protocol"), project("server"), project("web")],
  },
});
