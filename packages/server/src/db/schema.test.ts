import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { migrate } from "./migrate.js";
import { createTestDatabase, type TestDatabase } from "./test-db.js";

let db: TestDatabase;

const KEY_A = Buffer.alloc(32, 1);
const KEY_B = Buffer.alloc(32, 2);
const NONCE = Buffer.alloc(24, 3);
const CIPHERTEXT = Buffer.from("opaque ciphertext");

beforeAll(async () => {
  db = await createTestDatabase();
  await migrate(db.pool);
});

afterAll(async () => {
  await db.drop();
});

beforeEach(async () => {
  await db.pool.query("TRUNCATE messages, auth_nonces, users");
});

function insertUser(userId: string, identityKey: Buffer = KEY_A, exchangeKey: Buffer = KEY_B) {
  return db.pool.query(
    "INSERT INTO users (user_id, identity_pubkey, exchange_pubkey) VALUES ($1, $2, $3) RETURNING *",
    [userId, identityKey, exchangeKey],
  );
}

function insertMessage(from: string, to: string, nonce: Buffer = NONCE) {
  return db.pool.query(
    "INSERT INTO messages (from_user_id, to_user_id, nonce, ciphertext) VALUES ($1, $2, $3, $4) RETURNING *",
    [from, to, nonce, CIPHERTEXT],
  );
}

describe("initial schema", () => {
  it("creates the users, messages and auth_nonces tables", async () => {
    const result = await db.pool.query(
      "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name",
    );
    expect(result.rows.map((r) => r.table_name)).toEqual([
      "auth_nonces",
      "messages",
      "schema_migrations",
      "users",
    ]);
  });

  describe("users", () => {
    it("stores a user and fills in created_at", async () => {
      const result = await insertUser("alice");
      expect(result.rows[0].identity_pubkey).toEqual(KEY_A);
      expect(result.rows[0].exchange_pubkey).toEqual(KEY_B);
      expect(result.rows[0].created_at).toBeInstanceOf(Date);
    });

    it("rejects a duplicate user_id", async () => {
      await insertUser("alice");
      await expect(insertUser("alice")).rejects.toThrow(/users_pkey/);
    });

    it("rejects an identity key that is not 32 bytes", async () => {
      await expect(insertUser("alice", Buffer.alloc(31, 1))).rejects.toThrow(/identity_pubkey/);
    });

    it("rejects an exchange key that is not 32 bytes", async () => {
      await expect(insertUser("alice", KEY_A, Buffer.alloc(33, 2))).rejects.toThrow(/exchange_pubkey/);
    });
  });

  describe("messages", () => {
    beforeEach(async () => {
      await insertUser("alice");
      await insertUser("bob");
    });

    it("stores a message with a generated id, created_at, and no delivered_at", async () => {
      const result = await insertMessage("alice", "bob");
      const row = result.rows[0];
      expect(row.message_id).toMatch(/^[0-9a-f-]{36}$/);
      expect(row.created_at).toBeInstanceOf(Date);
      expect(row.delivered_at).toBeNull();
      expect(row.ciphertext).toEqual(CIPHERTEXT);
    });

    it("rejects a message to an unknown user", async () => {
      await expect(insertMessage("alice", "nobody")).rejects.toThrow(/to_user_id/);
    });

    it("rejects a message from an unknown user", async () => {
      await expect(insertMessage("nobody", "bob")).rejects.toThrow(/from_user_id/);
    });

    it("rejects a nonce that is not 24 bytes", async () => {
      await expect(insertMessage("alice", "bob", Buffer.alloc(12, 3))).rejects.toThrow(/nonce/);
    });
  });

  describe("auth_nonces", () => {
    function insertNonce(nonce: string) {
      return db.pool.query(
        "INSERT INTO auth_nonces (nonce, user_id, expires_at) VALUES ($1, 'alice', now() + interval '60 seconds')",
        [nonce],
      );
    }

    it("accepts a new nonce", async () => {
      await expect(insertNonce("n1")).resolves.toBeDefined();
    });

    it("rejects a replayed nonce", async () => {
      await insertNonce("n1");
      await expect(insertNonce("n1")).rejects.toThrow(/auth_nonces_pkey/);
    });
  });
});
