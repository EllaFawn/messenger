import { loadConfig } from "../config.js";
import { createPool } from "../db/pool.js";
import { runAdmin } from "./admin.js";

const pool = createPool(loadConfig().databaseUrl);
try {
  process.exitCode = await runAdmin(process.argv.slice(2), pool, (line) => console.log(line));
} catch (err) {
  console.error((err as Error).message);
  process.exitCode = 1;
} finally {
  await pool.end();
}
