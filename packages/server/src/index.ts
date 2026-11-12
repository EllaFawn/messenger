import * as crypto from "@messager/crypto";
import { loadServerConfig } from "./config.js";
import { createPool } from "./db/pool.js";
import { startServer } from "./server.js";

let config;
try {
  config = loadServerConfig();
} catch (err) {
  console.error((err as Error).message);
  process.exit(1);
}

await crypto.ready;
const pool = createPool(config.databaseUrl);
const server = await startServer({ ...config, pool });
console.log(`Listening on ${server.url}`);

let stopping = false;
async function shutdown(): Promise<void> {
  if (stopping) return;
  stopping = true;
  await server.close();
  await pool.end();
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
