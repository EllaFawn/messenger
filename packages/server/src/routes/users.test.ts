import * as crypto from "@messager/crypto";
import { deriveUserId, verifyExchangeKey, verifyRatchetKey } from "@messager/protocol";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../app.js";
import { migrate } from "../db/migrate.js";
import { createTestDatabase, type TestDatabase } from "../db/test-db.js";
import { insertUser, makeIdentity, signedFetch, type TestIdentity } from "../test-client.js";
import { startTestServer, type TestServer } from "../test-http.js";

const NOW = 1_800_000_000_000;

let db: TestDatabase;
let server: TestServer;
let alice: TestIdentity;
let bob: TestIdentity;

beforeAll(async () => {
  await crypto.ready;
  db = await createTestDatabase();
  await migrate(db.pool);
  server = await startTestServer(
    createApp({ pool: db.pool, now: () => NOW }),
  );
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

describe("GET /users/:userID/pubkeys", () => {
  it("returns another user's public keys to a signed caller", async () => {
    const res = await signedFetch(server.url, alice, `/users/${bob.userId}/pubkeys`, { timestamp: NOW });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      userID: bob.userId,
      identity_pubkey: crypto.toBase64(bob.identity.publicKey),
      exchange_pubkey: crypto.toBase64(bob.exchange.publicKey),
      exchange_sig: crypto.toBase64(bob.exchangeSig),
      ratchet_pubkey: crypto.toBase64(bob.ratchetKey),
      ratchet_sig: crypto.toBase64(bob.ratchetSig),
      key_epoch: 1,
    });
  });

  it("returns the caller's own keys", async () => {
    const res = await signedFetch(server.url, alice, `/users/${alice.userId}/pubkeys`, { timestamp: NOW });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { userID: string }).userID).toBe(alice.userId);
  });

  it("returns 404 for a user that does not exist", async () => {
    const res = await signedFetch(server.url, alice, `/users/${makeIdentity().userId}/pubkeys`, {
      timestamp: NOW,
    });
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "not_found" });
  });

  it("returns 404 for a malformed userID", async () => {
    const res = await signedFetch(server.url, alice, "/users/not-a-real-id/pubkeys", { timestamp: NOW });
    expect(res.status).toBe(404);
  });

  it("rejects an unsigned request", async () => {
    const res = await fetch(`${server.url}/users/${bob.userId}/pubkeys`);
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
  });

  it("rejects a caller who is not registered", async () => {
    const res = await signedFetch(server.url, makeIdentity(), `/users/${bob.userId}/pubkeys`, {
      timestamp: NOW,
    });
    expect(res.status).toBe(401);
  });

  it("returns a signature that proves the exchange key belongs to the userID", async () => {
    const res = await signedFetch(server.url, alice, `/users/${bob.userId}/pubkeys`, { timestamp: NOW });
    const keys = (await res.json()) as { identity_pubkey: string; exchange_pubkey: string; exchange_sig: string };
    const identityKey = crypto.fromBase64(keys.identity_pubkey);
    expect(deriveUserId(identityKey)).toBe(bob.userId);
    expect(
      verifyExchangeKey(crypto.fromBase64(keys.exchange_pubkey), crypto.fromBase64(keys.exchange_sig), identityKey),
    ).toBe(true);
  });

  it("returns a ratchet key that verifies against the userID, without spending a one-time key", async () => {
    await db.pool.query(
      "INSERT INTO one_time_keys (user_id, key_id, pubkey, sig) VALUES ($1, 'k', $2, $3)",
      [bob.userId, Buffer.alloc(32, 1), Buffer.alloc(64, 2)],
    );
    const res = await signedFetch(server.url, alice, `/users/${bob.userId}/pubkeys`, { timestamp: NOW });
    const keys = (await res.json()) as { identity_pubkey: string; ratchet_pubkey: string; ratchet_sig: string };
    expect(
      verifyRatchetKey(
        crypto.fromBase64(keys.ratchet_pubkey),
        crypto.fromBase64(keys.ratchet_sig),
        crypto.fromBase64(keys.identity_pubkey),
      ),
    ).toBe(true);
    expect((await db.pool.query("SELECT count(*)::int AS n FROM one_time_keys")).rows[0].n).toBe(1);
  });

  it("reports no ratchet key for an account that has not set one", async () => {
    const carol = makeIdentity();
    await insertUser(db.pool, carol, { ratchet: false });
    const res = await signedFetch(server.url, alice, `/users/${carol.userId}/pubkeys`, { timestamp: NOW });
    const keys = (await res.json()) as { ratchet_pubkey: unknown; ratchet_sig: unknown };
    expect(keys.ratchet_pubkey).toBeNull();
    expect(keys.ratchet_sig).toBeNull();
  });

  it("never returns private key material", async () => {
    const res = await signedFetch(server.url, alice, `/users/${bob.userId}/pubkeys`, { timestamp: NOW });
    const text = await res.text();
    expect(text).not.toContain(crypto.toBase64(bob.identity.privateKey));
    expect(text).not.toContain(crypto.toBase64(bob.exchange.privateKey));
    expect(Object.keys(JSON.parse(text)).sort()).toEqual(["exchange_pubkey", "exchange_sig", "identity_pubkey", "key_epoch", "ratchet_pubkey", "ratchet_sig", "userID"]);
  });
});
