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
  "@messager/ratchet": fileURLToPath(new URL("./packages/ratchet/src/index.ts", import.meta.url)),
};

/** Loads the ratchet's WebAssembly before tests that use it, as the page does at start-up. */
const ratchetSetup = fileURLToPath(new URL("./vitest.ratchet-setup.ts", import.meta.url));

function project(name: string, setupFiles: string[] = []) {
  return {
    resolve: { alias },
    test: { name, root: `./packages/${name}`, passWithNoTests: true, exclude, setupFiles },
  };
}

export default defineConfig({
  test: {
    projects: [
      project("crypto"),
      project("protocol"),
      project("ratchet"),
      project("server"),
      project("web", [ratchetSetup]),
      // Real web-client code against the real server; see e2e/client-server.test.ts.
      { resolve: { alias }, test: { name: "e2e", root: "./e2e", exclude, setupFiles: [ratchetSetup] } },
    ],
  },
});
