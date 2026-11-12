import * as crypto from "@messager/crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../app.js";
import { TIMESTAMP_WINDOW_MS } from "../auth/signed-request.js";
import { migrate } from "../db/migrate.js";
import { createTestDatabase, type TestDatabase } from "../db/test-db.js";
import { makeIdentity, signedFetch, type SignedFetchOptions, type TestIdentity } from "../test-client.js";
import { startTestServer, type TestServer } from "../test-http.js";

const NOW = 1_800_000_000_000;
const INVITE = "test-invite-code-0123456789";

let db: TestDatabase;
let server: TestServer;
let alice: TestIdentity;

beforeAll(async () => {
  await crypto.ready;
  db = await createTestDatabase();
  await migrate(db.pool);
  server = await startTestServer(createApp({ pool: db.pool, inviteCode: INVITE, now: () => NOW }));
});

afterAll(async () => {
  await server.close();
  await db.drop();
});

beforeEach(async () => {
  await db.pool.query("TRUNCATE messages, auth_nonces, users");
  alice = makeIdentity();
});

function registrationBody(who: TestIdentity, overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    userID: who.userId,
    identity_pubkey: crypto.toBase64(who.identity.publicKey),
    exchange_pubkey: crypto.toBase64(who.exchange.publicKey),
    inviteCode: INVITE,
    ...overrides,
  });
}

function register(signer: TestIdentity, body: string, options: Partial<SignedFetchOptions> = {}) {
  return signedFetch(server.url, signer, "/register", { method: "POST", body, timestamp: NOW, ...options });
}

async function count(table: "users" | "auth_nonces"): Promise<number> {
  const result = await db.pool.query(`SELECT count(*)::int AS n FROM ${table}`);
  return result.rows[0].n;
}

async function expectRejected(res: Response, status: number, error: string) {
  expect(res.status).toBe(status);
  expect(await res.json()).toEqual({ error });
  expect(await count("users")).toBe(0);
}

describe("POST /register", () => {
  it("registers a new user and stores both public keys", async () => {
    const res = await register(alice, registrationBody(alice));

    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ userID: alice.userId });
    const stored = await db.pool.query("SELECT * FROM users");
    expect(stored.rows).toHaveLength(1);
    expect(stored.rows[0].user_id).toBe(alice.userId);
    expect(new Uint8Array(stored.rows[0].identity_pubkey)).toEqual(alice.identity.publicKey);
    expect(new Uint8Array(stored.rows[0].exchange_pubkey)).toEqual(alice.exchange.publicKey);
  });

  it("lets the new user make signed requests straight away", async () => {
    await register(alice, registrationBody(alice));
    const res = await signedFetch(server.url, alice, `/users/${alice.userId}/pubkeys`, { timestamp: NOW });
    expect(res.status).toBe(200);
  });

  describe("invite code", () => {
    it("rejects a wrong invite code", async () => {
      const res = await register(alice, registrationBody(alice, { inviteCode: "wrong-invite-code-000000000" }));
      await expectRejected(res, 403, "invalid_invite");
    });

    it("rejects a code that only shares a prefix with the real one", async () => {
      const res = await register(alice, registrationBody(alice, { inviteCode: INVITE.slice(0, -1) }));
      await expectRejected(res, 403, "invalid_invite");
    });

    it("does not store a nonce when the invite code is wrong", async () => {
      await register(alice, registrationBody(alice, { inviteCode: "wrong-invite-code-000000000" }));
      expect(await count("auth_nonces")).toBe(0);
    });
  });

  describe("proof that the caller owns the key", () => {
    it("rejects a registration signed by a different key than the one being registered", async () => {
      // Mallory tries to register Alice's public key without holding Alice's private key.
      const mallory = makeIdentity();
      const res = await register(mallory, registrationBody(alice), { headers: { "x-user-id": alice.userId } });
      await expectRejected(res, 401, "unauthorized");
    });

    it("rejects a userID that is not derived from the identity key", async () => {
      const other = makeIdentity();
      const res = await register(alice, registrationBody(alice, { userID: other.userId }), {
        headers: { "x-user-id": other.userId },
      });
      await expectRejected(res, 400, "invalid_request");
    });

    it("rejects an X-User-ID header that differs from the body", async () => {
      const other = makeIdentity();
      const res = await register(alice, registrationBody(alice), { headers: { "x-user-id": other.userId } });
      await expectRejected(res, 401, "unauthorized");
    });

    it("rejects a body changed after signing", async () => {
      const attackerKey = crypto.toBase64(makeIdentity().exchange.publicKey);
      const res = await register(alice, registrationBody(alice, { exchange_pubkey: attackerKey }), {
        signAs: { body: registrationBody(alice) },
      });
      await expectRejected(res, 401, "unauthorized");
    });

    it("rejects an unsigned request", async () => {
      const res = await fetch(server.url + "/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: registrationBody(alice),
      });
      await expectRejected(res, 401, "unauthorized");
    });

    it("rejects a stale timestamp", async () => {
      const res = await register(alice, registrationBody(alice), { timestamp: NOW - TIMESTAMP_WINDOW_MS - 1 });
      await expectRejected(res, 401, "unauthorized");
    });
  });

  describe("replay and duplicates", () => {
    it("rejects a replayed registration request", async () => {
      const nonce = crypto.toBase64(crypto.randomBytes(16));
      const body = registrationBody(alice);
      const first = await register(alice, body, { nonce });
      const second = await register(alice, body, { nonce });
      expect(first.status).toBe(201);
      expect(second.status).toBe(401);
      expect(await count("users")).toBe(1);
    });

    it("refuses to register the same user twice and never replaces stored keys", async () => {
      await register(alice, registrationBody(alice));
      const newExchangeKey = makeIdentity().exchange.publicKey;

      const res = await register(alice, registrationBody(alice, { exchange_pubkey: crypto.toBase64(newExchangeKey) }));

      expect(res.status).toBe(409);
      expect(await res.json()).toEqual({ error: "already_registered" });
      const stored = await db.pool.query("SELECT exchange_pubkey FROM users WHERE user_id = $1", [alice.userId]);
      expect(new Uint8Array(stored.rows[0].exchange_pubkey)).toEqual(alice.exchange.publicKey);
    });
  });

  describe("malformed bodies", () => {
    it.each([
      ["missing inviteCode", { inviteCode: undefined }],
      ["missing exchange_pubkey", { exchange_pubkey: undefined }],
      ["missing identity_pubkey", { identity_pubkey: undefined }],
      ["missing userID", { userID: undefined }],
      ["identity key of the wrong length", { identity_pubkey: "AAAA" }],
      ["exchange key of the wrong length", { exchange_pubkey: Buffer.alloc(33).toString("base64") }],
      ["key that is not base64", { exchange_pubkey: "!".repeat(44) }],
      ["non-string invite code", { inviteCode: 12345 }],
      ["empty invite code", { inviteCode: "" }],
      ["oversized invite code", { inviteCode: "x".repeat(300) }],
      ["non-string userID", { userID: { nested: true } }],
    ])("rejects a body with %s", async (_label, overrides) => {
      const res = await register(alice, registrationBody(alice, overrides));
      await expectRejected(res, 400, "invalid_request");
    });

    it("rejects a JSON array body", async () => {
      await expectRejected(await register(alice, "[]"), 400, "invalid_request");
    });

    it("rejects a request with no body", async () => {
      const res = await signedFetch(server.url, alice, "/register", { method: "POST", timestamp: NOW });
      await expectRejected(res, 400, "invalid_request");
    });
  });
});
