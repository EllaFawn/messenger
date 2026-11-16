import { readFile } from "node:fs/promises";
import { initRatchet } from "./index.js";

/** Loads the WebAssembly module from disk. For tests and other non-browser use. */
export async function initRatchetForNode(): Promise<void> {
  const bytes = await readFile(new URL("../wasm/messager_ratchet_bg.wasm", import.meta.url));
  await initRatchet(bytes);
}
