import { loadConfig } from "../config.js";
import { migrate } from "./migrate.js";
import { createPool } from "./pool.js";

const pool = createPool(loadConfig().databaseUrl);
try {
  const { applied } = await migrate(pool);
  if (applied.length === 0) {
    console.log("Database is up to date; nothing to apply.");
  } else {
    for (const name of applied) {
      console.log(`Applied ${name}`);
    }
  }
} catch (err) {
  console.error((err as Error).message);
  process.exitCode = 1;
} finally {
  await pool.end();
}
