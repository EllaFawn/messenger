import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { migrate } from "./migrate.js";
import { createTestDatabase, type TestDatabase } from "./test-db.js";

let db: TestDatabase;

const KEY_A = Buffer.alloc(32, 1);
const KEY_B = Buffer.alloc(32, 2);
const CIPHERTEXT = Buffer.from("opaque ciphertext");

beforeAll(async () => {
  db = await createTestDatabase();
  await migrate(db.pool);
});

afterAll(async () => {
  await db.drop();
});

beforeEach(async () => {
  await db.pool.query("TRUNCATE one_time_keys, invites, messages, auth_nonces, users");
});

const SIG = Buffer.alloc(64, 3);

function insertUser(
  userId: string,
  identityKey: Buffer = KEY_A,
  ratchetKey: Buffer | null = KEY_B,
  ratchetSig: Buffer | null = SIG,
) {
  return db.pool.query(
    "INSERT INTO users (user_id, identity_pubkey, ratchet_pubkey, ratchet_sig) VALUES ($1, $2, $3, $4) RETURNING *",
    [userId, identityKey, ratchetKey, ratchetSig],
  );
}

function insertMessage(from: string, to: string, type: number | null = 1) {
  return db.pool.query(
    "INSERT INTO messages (from_user_id, to_user_id, msg_type, ciphertext) VALUES ($1, $2, $3, $4) RETURNING *",
    [from, to, type, CIPHERTEXT],
  );
}

describe("schema", () => {
  it("creates exactly the expected tables", async () => {
    const result = await db.pool.query(
      "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name",
    );
    expect(result.rows.map((r) => r.table_name)).toEqual([
      "auth_nonces",
      "invites",
      "messages",
      "one_time_keys",
      "schema_migrations",
      "users",
    ]);
  });

  describe("users", () => {
    it("stores a user and fills in created_at", async () => {
      const result = await insertUser("alice");
      expect(result.rows[0].identity_pubkey).toEqual(KEY_A);
      expect(result.rows[0].ratchet_pubkey).toEqual(KEY_B);
      expect(result.rows[0].key_epoch).toBe(1);
      expect(result.rows[0].created_at).toBeInstanceOf(Date);
    });

    it("rejects a duplicate user_id", async () => {
      await insertUser("alice");
      await expect(insertUser("alice")).rejects.toThrow(/users_pkey/);
    });

    it("rejects an identity key that is not 32 bytes", async () => {
      await expect(insertUser("alice", Buffer.alloc(31, 1))).rejects.toThrow(/identity_pubkey/);
    });

    it("rejects a ratchet key that is not 32 bytes", async () => {
      await expect(insertUser("alice", KEY_A, Buffer.alloc(33, 2))).rejects.toThrow(/ratchet_pubkey/);
    });

    it("stores the ratchet-key signature", async () => {
      const result = await insertUser("alice");
      expect(result.rows[0].ratchet_sig).toEqual(SIG);
    });

    it("rejects a user with no ratchet key or no signature", async () => {
      await expect(insertUser("alice", KEY_A, null)).rejects.toThrow(/ratchet_pubkey/);
      await expect(insertUser("alice", KEY_A, KEY_B, null)).rejects.toThrow(/ratchet_sig/);
    });

    it("rejects a ratchet-key signature that is not 64 bytes", async () => {
      await expect(insertUser("alice", KEY_A, KEY_B, Buffer.alloc(63, 3))).rejects.toThrow(/ratchet_sig/);
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
      expect(row.v).toBe(2);
    });

    it("rejects a message to an unknown user", async () => {
      await expect(insertMessage("alice", "nobody")).rejects.toThrow(/to_user_id/);
    });

    it("rejects a message from an unknown user", async () => {
      await expect(insertMessage("nobody", "bob")).rejects.toThrow(/from_user_id/);
    });

    it("rejects a message with no type or an unknown type", async () => {
      await expect(insertMessage("alice", "bob", null)).rejects.toThrow(/msg_type/);
      await expect(insertMessage("alice", "bob", 2)).rejects.toThrow(/messages_are_ratchet_messages/);
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
