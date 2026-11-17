import * as crypto from "@messager/crypto";
import { encodeEnvelope } from "@messager/protocol";
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

describe("ratchet (v2) messages", () => {
  it.each([
    ["a pre-key message", 0],
    ["a normal message", 1],
  ])("stores and delivers %s with its type and no nonce", async (_name, type) => {
    const envelope = ratchetEnvelope(bob.userId, type);
    const res = await send(alice, envelope);
    expect(res.status).toBe(201);
    const sent = (await res.json()) as { message_id: string };

    const row = (await db.pool.query("SELECT v, msg_type, nonce, from_user_id FROM messages")).rows[0];
    expect(row).toEqual({ v: 2, msg_type: type, nonce: null, from_user_id: alice.userId });

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
    ["a nonce, which ratchet messages do not have", { nonce: "A".repeat(32) }],
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

  it("rejects a v1 message that carries a ratchet type", async () => {
    const v1 = { ...encodeEnvelope(bob.userId, crypto.randomBytes(24), crypto.randomBytes(32)), type: 1 };
    expect((await send(alice, v1)).status).toBe(400);
  });

  it("takes the sender from the signature, as with v1", async () => {
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

  it("delivers v1 and v2 messages side by side, each in its own shape", async () => {
    const v1 = encodeEnvelope(bob.userId, crypto.randomBytes(24), crypto.randomBytes(32));
    await send(alice, v1);
    await send(alice, ratchetEnvelope(bob.userId, 1));

    const items = await inbox(bob);
    expect(items.map((item) => item.v)).toEqual([1, 2]);
    expect(items[0]).toMatchObject({ v: 1, nonce: v1.nonce });
    expect(items[0]).not.toHaveProperty("type");
    expect(items[1]).toMatchObject({ v: 2, type: 1 });
    expect(items[1]).not.toHaveProperty("nonce");
  });
});

describe("message shape in the database", () => {
  const insert = (v: number, nonce: Buffer | null, type: number | null) =>
    db.pool.query(
      "INSERT INTO messages (from_user_id, to_user_id, nonce, ciphertext, v, msg_type) VALUES ($1, $2, $3, $4, $5, $6)",
      [alice.userId, bob.userId, nonce, Buffer.alloc(32), v, type],
    );

  it("refuses rows that mix the two versions", async () => {
    await expect(insert(1, null, null)).rejects.toThrow(/messages_shape_matches_version/);
    await expect(insert(1, Buffer.alloc(24), 1)).rejects.toThrow(/messages_shape_matches_version/);
    await expect(insert(2, Buffer.alloc(24), 1)).rejects.toThrow(/messages_shape_matches_version/);
    await expect(insert(2, null, null)).rejects.toThrow(/messages_shape_matches_version/);
    await expect(insert(2, null, 5)).rejects.toThrow(/messages_shape_matches_version/);
    await expect(insert(3, null, 1)).rejects.toThrow(/messages_shape_matches_version/);
  });

  it("accepts well-formed rows of either version", async () => {
    await insert(1, Buffer.alloc(24), null);
    await insert(2, null, 0);
    await insert(2, null, 1);
    expect(await stored()).toBe(3);
  });
});

describe("ratchet key columns in the database", () => {
  it("requires the ratchet key and its signature together", async () => {
    const update = (key: Buffer | null, sig: Buffer | null) =>
      db.pool.query("UPDATE users SET ratchet_pubkey = $1, ratchet_sig = $2 WHERE user_id = $3", [
        key,
        sig,
        alice.userId,
      ]);
    await expect(update(Buffer.alloc(32), null)).rejects.toThrow(/users_ratchet_key_and_sig_together/);
    await expect(update(null, Buffer.alloc(64))).rejects.toThrow(/users_ratchet_key_and_sig_together/);
    await expect(update(Buffer.alloc(31), Buffer.alloc(64))).rejects.toThrow(/ratchet_pubkey/);
    await expect(update(Buffer.alloc(32), Buffer.alloc(63))).rejects.toThrow(/ratchet_sig/);
    await update(null, null);
    await update(Buffer.alloc(32), Buffer.alloc(64));
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
