import * as crypto from "@messager/crypto";
import { encodeEnvelope } from "@messager/protocol";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp, MAX_BODY_BYTES } from "../app.js";
import { migrate } from "../db/migrate.js";
import { createTestDatabase, type TestDatabase } from "../db/test-db.js";
import { insertUser, makeIdentity, signedFetch, type TestIdentity } from "../test-client.js";
import { startTestServer, type TestServer } from "../test-http.js";

const NOW = 1_800_000_000_000;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

let db: TestDatabase;
let server: TestServer;
let alice: TestIdentity;
let bob: TestIdentity;

beforeAll(async () => {
  await crypto.ready;
  db = await createTestDatabase();
  await migrate(db.pool);
  server = await startTestServer(
    createApp({ pool: db.pool, inviteCode: "test-invite-code-0123456789", now: () => NOW }),
  );
});

afterAll(async () => {
  await server.close();
  await db.drop();
});

beforeEach(async () => {
  await db.pool.query("TRUNCATE messages, auth_nonces, users");
  alice = makeIdentity();
  bob = makeIdentity();
  await insertUser(db.pool, alice);
  await insertUser(db.pool, bob);
});

/** A well-formed envelope with random bytes standing in for real ciphertext. */
function envelopeTo(to: string, ciphertextBytes = 64): Record<string, unknown> {
  return { ...encodeEnvelope(to, crypto.randomBytes(24), crypto.randomBytes(ciphertextBytes)) };
}

function send(from: TestIdentity, body: unknown): Promise<Response> {
  return signedFetch(server.url, from, "/messages", {
    method: "POST",
    body: JSON.stringify(body),
    timestamp: NOW,
  });
}

async function storedMessages(): Promise<
  { message_id: string; from_user_id: string; to_user_id: string; nonce: Buffer; ciphertext: Buffer }[]
> {
  const result = await db.pool.query(
    "SELECT message_id, from_user_id, to_user_id, nonce, ciphertext FROM messages ORDER BY created_at",
  );
  return result.rows;
}

describe("POST /messages", () => {
  it("stores the envelope and returns its id", async () => {
    const envelope = envelopeTo(bob.userId);
    const res = await send(alice, envelope);
    expect(res.status).toBe(201);

    const json = (await res.json()) as { message_id: string; created_at: string };
    expect(Object.keys(json).sort()).toEqual(["created_at", "message_id"]);
    expect(json.message_id).toMatch(UUID_PATTERN);
    expect(Number.isNaN(Date.parse(json.created_at))).toBe(false);

    const rows = await storedMessages();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.message_id).toBe(json.message_id);
    expect(rows[0]!.from_user_id).toBe(alice.userId);
    expect(rows[0]!.to_user_id).toBe(bob.userId);
    expect(rows[0]!.nonce.toString("base64")).toBe(envelope.nonce);
    expect(rows[0]!.ciphertext.toString("base64")).toBe(envelope.ciphertext);
  });

  it("takes the sender from the signature, never from the body", async () => {
    const res = await send(alice, { ...envelopeTo(bob.userId), from: bob.userId, from_user_id: bob.userId });
    expect(res.status).toBe(201);
    const rows = await storedMessages();
    expect(rows[0]!.from_user_id).toBe(alice.userId);
  });

  it("rejects an unsigned request and stores nothing", async () => {
    const res = await fetch(`${server.url}/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(envelopeTo(bob.userId)),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
    expect(await storedMessages()).toHaveLength(0);
  });

  it("rejects a sender who is not registered", async () => {
    const res = await send(makeIdentity(), envelopeTo(bob.userId));
    expect(res.status).toBe(401);
    expect(await storedMessages()).toHaveLength(0);
  });

  it("rejects a body that was changed after signing", async () => {
    const signed = JSON.stringify(envelopeTo(bob.userId));
    const sent = JSON.stringify(envelopeTo(bob.userId));
    const res = await signedFetch(server.url, alice, "/messages", {
      method: "POST",
      body: sent,
      signAs: { body: signed },
      timestamp: NOW,
    });
    expect(res.status).toBe(401);
    expect(await storedMessages()).toHaveLength(0);
  });

  it("rejects a replayed request", async () => {
    const body = JSON.stringify(envelopeTo(bob.userId));
    const nonce = crypto.toBase64(crypto.randomBytes(16));
    const options = { method: "POST", body, nonce, timestamp: NOW };
    expect((await signedFetch(server.url, alice, "/messages", options)).status).toBe(201);
    expect((await signedFetch(server.url, alice, "/messages", options)).status).toBe(401);
    expect(await storedMessages()).toHaveLength(1);
  });

  it("returns 404 when the recipient does not exist", async () => {
    const res = await send(alice, envelopeTo(makeIdentity().userId));
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "recipient_not_found" });
    expect(await storedMessages()).toHaveLength(0);
  });

  it.each([
    ["a missing version", (e: Record<string, unknown>) => ({ ...e, v: undefined })],
    ["an unsupported version", (e: Record<string, unknown>) => ({ ...e, v: 2 })],
    ["a version sent as text", (e: Record<string, unknown>) => ({ ...e, v: "1" })],
    ["a missing recipient", (e: Record<string, unknown>) => ({ ...e, to: undefined })],
    ["a malformed recipient", (e: Record<string, unknown>) => ({ ...e, to: "not-a-real-id" })],
    ["a missing nonce", (e: Record<string, unknown>) => ({ ...e, nonce: undefined })],
    [
      "a nonce of the wrong length",
      (e: Record<string, unknown>) => ({ ...e, nonce: crypto.toBase64(crypto.randomBytes(16)) }),
    ],
    ["a nonce that is not base64", (e: Record<string, unknown>) => ({ ...e, nonce: "!".repeat(32) })],
    ["a missing ciphertext", (e: Record<string, unknown>) => ({ ...e, ciphertext: undefined })],
    ["an empty ciphertext", (e: Record<string, unknown>) => ({ ...e, ciphertext: "" })],
    [
      "a ciphertext shorter than the authentication tag",
      (e: Record<string, unknown>) => ({ ...e, ciphertext: crypto.toBase64(crypto.randomBytes(15)) }),
    ],
    ["a ciphertext that is not base64", (e: Record<string, unknown>) => ({ ...e, ciphertext: "not base64!!" })],
    [
      "a ciphertext with stray padding bits",
      // "AAAAAAAAAAAAAAAAAAAAAB==" decodes, but is not the canonical encoding of any bytes.
      (e: Record<string, unknown>) => ({ ...e, ciphertext: "AAAAAAAAAAAAAAAAAAAAAB==" }),
    ],
    ["a ciphertext sent as a number", (e: Record<string, unknown>) => ({ ...e, ciphertext: 12345 })],
  ])("rejects %s", async (_name, corrupt) => {
    const res = await send(alice, corrupt(envelopeTo(bob.userId)));
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_request" });
    expect(await storedMessages()).toHaveLength(0);
  });

  it.each([
    ["an array", []],
    ["a string", "hello"],
    ["null", null],
  ])("rejects a body that is %s", async (_name, body) => {
    const res = await send(alice, body);
    expect(res.status).toBe(400);
    expect(await storedMessages()).toHaveLength(0);
  });

  it("accepts a ciphertext of exactly the authentication tag length", async () => {
    const res = await send(alice, envelopeTo(bob.userId, 16));
    expect(res.status).toBe(201);
  });

  it("rejects a body over the size limit", async () => {
    const res = await send(alice, envelopeTo(bob.userId, MAX_BODY_BYTES));
    expect(res.status).toBe(413);
    expect(await storedMessages()).toHaveLength(0);
  });

  it("stores two messages with the same contents as separate rows", async () => {
    const envelope = envelopeTo(bob.userId);
    const first = (await (await send(alice, envelope)).json()) as { message_id: string };
    const second = (await (await send(alice, envelope)).json()) as { message_id: string };
    expect(first.message_id).not.toBe(second.message_id);
    expect(await storedMessages()).toHaveLength(2);
  });

  it("does not echo the ciphertext back", async () => {
    const envelope = envelopeTo(bob.userId);
    const text = await (await send(alice, envelope)).text();
    expect(text).not.toContain(envelope.ciphertext as string);
  });
});
