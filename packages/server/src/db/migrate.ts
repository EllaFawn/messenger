import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Pool } from "./pool.js";

/** packages/server/migrations — resolves the same from src/db and dist/db. */
export const DEFAULT_MIGRATIONS_DIR = fileURLToPath(new URL("../../migrations", import.meta.url));

const MIGRATION_FILE = /^\d+_.+\.sql$/;

/** Arbitrary constant identifying this app's migration lock. */
const ADVISORY_LOCK_KEY = 7_265_114_001;

export interface MigrateResult {
  /** Filenames applied by this run, in order. */
  applied: string[];
}

/**
 * Applies every numbered .sql file in `dir` that has not been applied yet,
 * in filename order. Each file runs in its own transaction. Throws if a
 * file that was already applied has since been edited.
 */
export async function migrate(pool: Pool, dir: string = DEFAULT_MIGRATIONS_DIR): Promise<MigrateResult> {
  const files = (await readdir(dir)).filter((name) => MIGRATION_FILE.test(name)).sort();
  const applied: string[] = [];

  const client = await pool.connect();
  try {
    // Session-level lock: a second concurrent run waits here instead of racing.
    await client.query("SELECT pg_advisory_lock($1)", [ADVISORY_LOCK_KEY]);
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS schema_migrations (
          name       text PRIMARY KEY,
          checksum   text NOT NULL,
          applied_at timestamptz NOT NULL DEFAULT now()
        )
      `);
      const existing = await client.query<{ name: string; checksum: string }>(
        "SELECT name, checksum FROM schema_migrations",
      );
      const checksums = new Map(existing.rows.map((row) => [row.name, row.checksum]));

      for (const name of files) {
        const sql = await readFile(join(dir, name), "utf8");
        const checksum = createHash("sha256").update(sql).digest("hex");

        const recorded = checksums.get(name);
        if (recorded !== undefined) {
          if (recorded !== checksum) {
            throw new Error(
              `migration ${name} has changed since it was applied; add a new migration instead of editing it`,
            );
          }
          continue;
        }

        await client.query("BEGIN");
        try {
          await client.query(sql);
          await client.query("INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)", [
            name,
            checksum,
          ]);
          await client.query("COMMIT");
        } catch (err) {
          await client.query("ROLLBACK");
          throw new Error(`migration ${name} failed: ${(err as Error).message}`, { cause: err });
        }
        applied.push(name);
      }
    } finally {
      await client.query("SELECT pg_advisory_unlock($1)", [ADVISORY_LOCK_KEY]);
    }
  } finally {
    client.release();
  }

  return { applied };
}
