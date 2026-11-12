import { randomBytes } from "node:crypto";
import { loadConfig } from "../config.js";
import { createPool, type Pool } from "./pool.js";

export interface TestDatabase {
  pool: Pool;
  /** Closes the pool and drops the throwaway database. */
  drop(): Promise<void>;
}

/**
 * Creates an empty, randomly named database on the configured Postgres
 * server so tests never touch the dev database.
 */
export async function createTestDatabase(): Promise<TestDatabase> {
  const { databaseUrl } = loadConfig();
  const name = `messager_test_${randomBytes(8).toString("hex")}`;
  const admin = createPool(databaseUrl);
  try {
    await admin.query(`CREATE DATABASE ${name}`);
  } catch (err) {
    await admin.end();
    throw new Error(
      `Could not reach Postgres at ${new URL(databaseUrl).host}. Start it with \`docker compose up -d\`.`,
      { cause: err },
    );
  }

  const testUrl = new URL(databaseUrl);
  testUrl.pathname = `/${name}`;
  const pool = createPool(testUrl.toString());

  return {
    pool,
    async drop() {
      await pool.end();
      // pool.end() can resolve before the server has finished closing every
      // connection. Wait for them to go so the drop does not cut one off mid-close.
      for (let attempt = 0; attempt < 200; attempt++) {
        const open = await admin.query("SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = $1", [
          name,
        ]);
        if (open.rows[0].n === 0) break;
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
      await admin.end();
    },
  };
}
