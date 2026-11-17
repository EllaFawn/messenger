import * as crypto from "@messager/crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../app.js";
import { migrate } from "../db/migrate.js";
import { createTestDatabase, type TestDatabase } from "../db/test-db.js";
import { insertUser, makeIdentity, signedFetch, type TestIdentity } from "../test-client.js";
import { startTestServer, type TestServer } from "../test-http.js";

let db: TestDatabase;
let server: TestServer;
let alice: TestIdentity;
let bob: TestIdentity;

beforeAll(async () => {
  await crypto.ready;
  db = await createTestDatabase();
  await migrate(db.pool);
  server = await startTestServer(createApp({ pool: db.pool }));
});

afterAll(async () => {
  await server.close();
  await db.drop();
});

beforeEach(async () => {
  await db.pool.query("TRUNCATE one_time_keys, invites, messages, auth_nonces, users");
  alice = makeIdentity();
  bob = makeIdentity();
  await insertUser(db.pool, alice);
  await insertUser(db.pool, bob);
});

/** A ratchet (v2) envelope with random bytes standing in for ciphertext. */
function ratchetEnvelope(to: string, type: number, overrides: Record<string, unknown> = {}) {
  return { v: 2, to, type, ciphertext: crypto.toBase64(crypto.randomBytes(80)), ...overrides };
}

const send = (from: TestIdentity, body: unknown) =>
  signedFetch(server.url, from, "/messages", { method: "POST", body: JSON.stringify(body), timestamp: Date.now() });

const inbox = async (who: TestIdentity) =>
  (await (await signedFetch(server.url, who, "/messages/inbox", { timestamp: Date.now() })).json()) as Record<
    string,
    unknown
  >[];

async function stored(): Promise<number> {
  return (await db.pool.query("SELECT count(*)::int AS n FROM messages")).rows[0].n;
}

describe("ratchet message types", () => {
  it.each([
    ["a pre-key message", 0],
    ["a normal message", 1],
  ])("stores and delivers %s with its type", async (_name, type) => {
    const envelope = ratchetEnvelope(bob.userId, type);
    const res = await send(alice, envelope);
    expect(res.status).toBe(201);
    const sent = (await res.json()) as { message_id: string };

    const row = (await db.pool.query("SELECT v, msg_type, from_user_id FROM messages")).rows[0];
    expect(row).toEqual({ v: 2, msg_type: type, from_user_id: alice.userId });

    const items = await inbox(bob);
    expect(items).toHaveLength(1);
    expect(items[0]).toEqual({
      message_id: sent.message_id,
      from: alice.userId,
      v: 2,
      type,
      ciphertext: envelope.ciphertext,
      created_at: expect.any(String),
      cursor: expect.any(String),
    });
    expect(items[0]).not.toHaveProperty("nonce");
  });

  it.each([
    ["a missing type", { type: undefined }],
    ["an unknown type", { type: 2 }],
    ["a type sent as text", { type: "0" }],
    ["a negative type", { type: -1 }],
        ["an empty ciphertext", { ciphertext: "" }],
    ["a ciphertext that is not base64", { ciphertext: "not base64!!" }],
    ["a malformed recipient", { to: "nobody" }],
    ["an unknown version", { v: 3 }],
  ])("rejects %s", async (_name, overrides) => {
    const res = await send(alice, ratchetEnvelope(bob.userId, 1, overrides));
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_request" });
    expect(await stored()).toBe(0);
  });

  it("rejects the retired static-key (v1) format", async () => {
    const v1 = { v: 1, to: bob.userId, nonce: "A".repeat(32), ciphertext: crypto.toBase64(crypto.randomBytes(32)) };
    const res = await send(alice, v1);
    expect(res.status).toBe(400);
    expect(await stored()).toBe(0);
  });

  it("takes the sender from the signature, not the body", async () => {
    await send(alice, ratchetEnvelope(bob.userId, 1, { from: bob.userId }));
    expect((await inbox(bob))[0]!.from).toBe(alice.userId);
  });

  it("can be acknowledged like any other message", async () => {
    const sent = (await (await send(alice, ratchetEnvelope(bob.userId, 0))).json()) as { message_id: string };
    const res = await signedFetch(server.url, bob, `/messages/${sent.message_id}/ack`, {
      method: "POST",
      timestamp: Date.now(),
    });
    expect(res.status).toBe(204);
    expect(await stored()).toBe(0);
  });
});

describe("message shape in the database", () => {
  const insert = (v: number, type: number | null) =>
    db.pool.query("INSERT INTO messages (from_user_id, to_user_id, ciphertext, v, msg_type) VALUES ($1, $2, $3, $4, $5)", [
      alice.userId,
      bob.userId,
      Buffer.alloc(32),
      v,
      type,
    ]);

  it("refuses anything that is not a typed ratchet message", async () => {
    await expect(insert(1, 1)).rejects.toThrow(/messages_are_ratchet_messages/);
    await expect(insert(3, 1)).rejects.toThrow(/messages_are_ratchet_messages/);
    await expect(insert(2, 5)).rejects.toThrow(/messages_are_ratchet_messages/);
    await expect(insert(2, null)).rejects.toThrow(/msg_type/);
  });

  it("has no nonce column any more", async () => {
    const columns = await db.pool.query(
      "SELECT column_name FROM information_schema.columns WHERE table_name = 'messages' ORDER BY column_name",
    );
    expect(columns.rows.map((r) => r.column_name)).toEqual([
      "ciphertext",
      "created_at",
      "delivered_at",
      "from_user_id",
      "message_id",
      "msg_type",
      "to_user_id",
      "v",
    ]);
  });

  it("accepts both message types", async () => {
    await insert(2, 0);
    await insert(2, 1);
    expect(await stored()).toBe(2);
  });
});

describe("ratchet key columns in the database", () => {
  it("requires a ratchet key and signature of the right length", async () => {
    const update = (key: Buffer | null, sig: Buffer | null) =>
      db.pool.query("UPDATE users SET ratchet_pubkey = $1, ratchet_sig = $2 WHERE user_id = $3", [
        key,
        sig,
        alice.userId,
      ]);
    await expect(update(Buffer.alloc(32), null)).rejects.toThrow(/ratchet_sig/);
    await expect(update(null, Buffer.alloc(64))).rejects.toThrow(/ratchet_pubkey/);
    await expect(update(Buffer.alloc(31), Buffer.alloc(64))).rejects.toThrow(/ratchet_pubkey/);
    await expect(update(Buffer.alloc(32), Buffer.alloc(63))).rejects.toThrow(/ratchet_sig/);
    await update(Buffer.alloc(32), Buffer.alloc(64));
  });

  it("no longer has the static exchange key columns", async () => {
    const columns = await db.pool.query(
      "SELECT column_name FROM information_schema.columns WHERE table_name = 'users' ORDER BY column_name",
    );
    expect(columns.rows.map((r) => r.column_name)).toEqual([
      "created_at",
      "identity_pubkey",
      "key_epoch",
      "ratchet_pubkey",
      "ratchet_sig",
      "user_id",
    ]);
  });

  it("allows only one fallback key per user", async () => {
    const insert = (id: string) =>
      db.pool.query(
        "INSERT INTO one_time_keys (user_id, key_id, pubkey, sig, is_fallback) VALUES ($1, $2, $3, $4, true)",
        [alice.userId, id, Buffer.alloc(32), Buffer.alloc(64)],
      );
    await insert("a");
    await expect(insert("b")).rejects.toThrow(/one_time_keys_one_fallback_idx/);
  });
});
