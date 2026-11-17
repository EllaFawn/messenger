import { cp, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_MIGRATIONS_DIR, migrate } from "./migrate.js";
import { createTestDatabase, type TestDatabase } from "./test-db.js";

let db: TestDatabase;
let upTo004: string;

const BEFORE_005 = ["001_initial.sql", "002_exchange_key_signature.sql", "003_invites.sql", "004_ratchet_keys.sql"];

beforeAll(async () => {
  db = await createTestDatabase();
  // A migrations folder as it was before the clean break.
  upTo004 = await mkdtemp(join(tmpdir(), "messager-migrations-"));
  for (const file of BEFORE_005) {
    await cp(join(DEFAULT_MIGRATIONS_DIR, file), join(upTo004, file));
  }
});

afterAll(async () => {
  await db.drop();
  await rm(upTo004, { recursive: true, force: true });
});

describe("005_ratchet_only", () => {
  it("removes static-key accounts and their data, keeps invites, and makes the ratchet key required", async () => {
    await migrate(db.pool, upTo004);
    await db.pool.query(
      `INSERT INTO users (user_id, identity_pubkey, exchange_pubkey, exchange_sig, ratchet_pubkey, ratchet_sig)
       VALUES ('old', $1, $2, $3, $2, $3), ('older', $1, $2, $3, NULL, NULL)`,
      [Buffer.alloc(32, 1), Buffer.alloc(32, 2), Buffer.alloc(64, 3)],
    );
    await db.pool.query(
      "INSERT INTO messages (from_user_id, to_user_id, nonce, ciphertext) VALUES ('old', 'older', $1, $2)",
      [Buffer.alloc(24), Buffer.alloc(16)],
    );
    await db.pool.query(
      "INSERT INTO messages (from_user_id, to_user_id, ciphertext, v, msg_type) VALUES ('old', 'older', $1, 2, 0)",
      [Buffer.alloc(16)],
    );
    await db.pool.query("INSERT INTO one_time_keys (user_id, key_id, pubkey, sig) VALUES ('old', 'k', $1, $2)", [
      Buffer.alloc(32),
      Buffer.alloc(64),
    ]);
    await db.pool.query(
      "INSERT INTO auth_nonces (nonce, user_id, expires_at) VALUES ('n', 'old', now() + interval '1 minute')",
    );
    await db.pool.query(
      `INSERT INTO invites (code_hash, note, expires_at, used_at, used_by)
       VALUES ($1, 'used', now() + interval '1 day', now(), 'old'), ($2, 'unused', now() + interval '1 day', NULL, NULL)`,
      [Buffer.alloc(32, 7), Buffer.alloc(32, 8)],
    );

    const result = await migrate(db.pool);
    expect(result.applied).toEqual(["005_ratchet_only.sql"]);

    for (const table of ["users", "messages", "one_time_keys", "auth_nonces"]) {
      const rows = await db.pool.query(`SELECT count(*)::int AS n FROM ${table}`);
      expect(rows.rows[0].n).toBe(0);
    }
    // Invites survive; the record of who used one is cleared with the account.
    const invites = await db.pool.query("SELECT note, used_at IS NOT NULL AS used, used_by FROM invites ORDER BY note");
    expect(invites.rows).toEqual([
      { note: "unused", used: false, used_by: null },
      { note: "used", used: true, used_by: null },
    ]);

    await expect(
      db.pool.query("INSERT INTO users (user_id, identity_pubkey) VALUES ('new', $1)", [Buffer.alloc(32, 1)]),
    ).rejects.toThrow(/ratchet_pubkey/);
    await db.pool.query(
      "INSERT INTO users (user_id, identity_pubkey, ratchet_pubkey, ratchet_sig) VALUES ('new', $1, $2, $3)",
      [Buffer.alloc(32, 1), Buffer.alloc(32, 2), Buffer.alloc(64, 3)],
    );
  });
});
