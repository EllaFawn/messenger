import { cp, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_MIGRATIONS_DIR, migrate } from "./migrate.js";
import { createTestDatabase, type TestDatabase } from "./test-db.js";

let db: TestDatabase;
let onlyFirst: string;

beforeAll(async () => {
  db = await createTestDatabase();
  // A migrations folder as it was before 002 existed.
  onlyFirst = await mkdtemp(join(tmpdir(), "messager-migrations-"));
  await cp(join(DEFAULT_MIGRATIONS_DIR, "001_initial.sql"), join(onlyFirst, "001_initial.sql"));
});

afterAll(async () => {
  await db.drop();
  await rm(onlyFirst, { recursive: true, force: true });
});

describe("002_exchange_key_signature", () => {
  it("upgrades a database that already holds unsigned accounts by removing them", async () => {
    await migrate(db.pool, onlyFirst);
    await db.pool.query(
      "INSERT INTO users (user_id, identity_pubkey, exchange_pubkey) VALUES ('old', $1, $2)",
      [Buffer.alloc(32, 1), Buffer.alloc(32, 2)],
    );
    await db.pool.query(
      "INSERT INTO messages (from_user_id, to_user_id, nonce, ciphertext) VALUES ('old', 'old', $1, $2)",
      [Buffer.alloc(24), Buffer.alloc(16)],
    );
    await db.pool.query(
      "INSERT INTO auth_nonces (nonce, user_id, expires_at) VALUES ('n', 'old', now() + interval '1 minute')",
    );

    const result = await migrate(db.pool);
    expect(result.applied).toEqual(["002_exchange_key_signature.sql"]);

    for (const table of ["users", "messages", "auth_nonces"]) {
      const rows = await db.pool.query(`SELECT count(*)::int AS n FROM ${table}`);
      expect(rows.rows[0].n).toBe(0);
    }
    // No account can exist without a signature from now on.
    await expect(
      db.pool.query("INSERT INTO users (user_id, identity_pubkey, exchange_pubkey) VALUES ('new', $1, $2)", [
        Buffer.alloc(32, 1),
        Buffer.alloc(32, 2),
      ]),
    ).rejects.toThrow(/exchange_sig/);
  });
});
