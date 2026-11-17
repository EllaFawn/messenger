import * as crypto from "@messager/crypto";
import { signRatchetKey } from "@messager/protocol";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../app.js";
import { TIMESTAMP_WINDOW_MS } from "../auth/signed-request.js";
import { migrate } from "../db/migrate.js";
import { createTestDatabase, type TestDatabase } from "../db/test-db.js";
import { issueInvite, makeIdentity, signedFetch, type SignedFetchOptions, type TestIdentity } from "../test-client.js";
import { startTestServer, type TestServer } from "../test-http.js";

const NOW = 1_800_000_000_000;

let db: TestDatabase;
let server: TestServer;
let alice: TestIdentity;
/** A fresh, valid invite for each test. */
let invite: string;

beforeAll(async () => {
  await crypto.ready;
  db = await createTestDatabase();
  await migrate(db.pool);
  server = await startTestServer(createApp({ pool: db.pool, now: () => NOW }));
});

afterAll(async () => {
  await server.close();
  await db.drop();
});

beforeEach(async () => {
  await db.pool.query("TRUNCATE one_time_keys, invites, messages, auth_nonces, users");
  alice = makeIdentity();
  invite = await issueInvite(db.pool);
});

function registrationBody(who: TestIdentity, overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    userID: who.userId,
    identity_pubkey: crypto.toBase64(who.identity.publicKey),
    ratchet_pubkey: crypto.toBase64(who.ratchetKey),
    ratchet_sig: crypto.toBase64(who.ratchetSig),
    inviteCode: invite,
    ...overrides,
  });
}

function register(signer: TestIdentity, body: string, options: Partial<SignedFetchOptions> = {}) {
  return signedFetch(server.url, signer, "/register", { method: "POST", body, timestamp: NOW, ...options });
}

async function inviteState(): Promise<{ used_at: Date | null; used_by: string | null }> {
  return (await db.pool.query("SELECT used_at, used_by FROM invites ORDER BY created_at LIMIT 1")).rows[0];
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
  it("registers a new user and stores the identity key and the signed ratchet key", async () => {
    const res = await register(alice, registrationBody(alice));

    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ userID: alice.userId });
    const stored = await db.pool.query("SELECT * FROM users");
    expect(stored.rows).toHaveLength(1);
    expect(stored.rows[0].user_id).toBe(alice.userId);
    expect(new Uint8Array(stored.rows[0].identity_pubkey)).toEqual(alice.identity.publicKey);
    expect(new Uint8Array(stored.rows[0].ratchet_pubkey)).toEqual(alice.ratchetKey);
    expect(new Uint8Array(stored.rows[0].ratchet_sig)).toEqual(alice.ratchetSig);
  });

  describe("ratchet key", () => {
    const withRatchet = registrationBody;

    it("stores a signed ratchet key given at registration", async () => {
      expect((await register(alice, withRatchet(alice))).status).toBe(201);
      const row = (await db.pool.query("SELECT ratchet_pubkey, ratchet_sig, key_epoch FROM users")).rows[0];
      expect(new Uint8Array(row.ratchet_pubkey)).toEqual(alice.ratchetKey);
      expect(new Uint8Array(row.ratchet_sig)).toEqual(alice.ratchetSig);
      expect(row.key_epoch).toBe(1);
    });

    it("refuses an account without one", async () => {
      const res = await register(alice, withRatchet(alice, { ratchet_pubkey: undefined, ratchet_sig: undefined }));
      await expectRejected(res, 400, "invalid_request");
    });

    it("rejects a ratchet key the identity key did not sign", async () => {
      const mallory = makeIdentity();
      const res = await register(alice, withRatchet(alice, { ratchet_pubkey: crypto.toBase64(mallory.ratchetKey) }));
      await expectRejected(res, 400, "invalid_request");
    });

    it("rejects a signature made by someone else", async () => {
      const mallory = makeIdentity();
      const forged = signRatchetKey(alice.ratchetKey, mallory.identity.privateKey);
      const res = await register(alice, withRatchet(alice, { ratchet_sig: crypto.toBase64(forged) }));
      await expectRejected(res, 400, "invalid_request");
    });

    it("does not accept a signature made for another purpose", async () => {
      // Same key bytes, signed as the retired static exchange key was.
      const prefix = crypto.utf8Encode("messager/v1/exchange-key\n");
      const statement = new Uint8Array(prefix.length + 32);
      statement.set(prefix, 0);
      statement.set(alice.ratchetKey, prefix.length);
      const wrongPurpose = crypto.sign(alice.identity.privateKey, statement);
      const res = await register(alice, withRatchet(alice, { ratchet_sig: crypto.toBase64(wrongPurpose) }));
      await expectRejected(res, 400, "invalid_request");
    });

    it.each([
      ["the key without the signature", { ratchet_sig: undefined }],
      ["the signature without the key", { ratchet_pubkey: undefined }],
      ["a key of the wrong length", { ratchet_pubkey: "AAAA" }],
      ["a signature of the wrong length", { ratchet_sig: "AAAA" }],
      ["a key that is not text", { ratchet_pubkey: 7 }],
      ["a null key", { ratchet_pubkey: null }],
      ["a key that is not base64", { ratchet_pubkey: "!".repeat(44) }],
      ["a signature that is not base64", { ratchet_sig: "!".repeat(88) }],
      ["a signature of all zero bytes", { ratchet_sig: Buffer.alloc(64).toString("base64") }],
      ["the retired exchange key in place of the ratchet key", { ratchet_pubkey: undefined, exchange_pubkey: "A".repeat(43) + "=" }],
    ])("rejects %s", async (_label, overrides) => {
      const res = await register(alice, withRatchet(alice, overrides));
      await expectRejected(res, 400, "invalid_request");
    });

    it("does not use up the invite when the ratchet key is refused", async () => {
      await register(alice, withRatchet(alice, { ratchet_sig: "AAAA" }));
      expect((await inviteState()).used_at).toBeNull();
    });
  });

  it("lets the new user make signed requests straight away", async () => {
    await register(alice, registrationBody(alice));
    const res = await signedFetch(server.url, alice, `/users/${alice.userId}/pubkeys`, { timestamp: NOW });
    expect(res.status).toBe(200);
  });

  describe("invite code", () => {
    it("marks the invite as used by the new user", async () => {
      expect((await register(alice, registrationBody(alice))).status).toBe(201);
      const state = await inviteState();
      expect(state.used_by).toBe(alice.userId);
      expect(state.used_at).toBeInstanceOf(Date);
    });

    it("rejects a code that was never issued", async () => {
      const res = await register(alice, registrationBody(alice, { inviteCode: "wrong-invite-code-000000000" }));
      await expectRejected(res, 403, "invalid_invite");
    });

    it("rejects a code that only shares a prefix with a real one", async () => {
      const res = await register(alice, registrationBody(alice, { inviteCode: invite.slice(0, -1) }));
      await expectRejected(res, 403, "invalid_invite");
    });

    it("lets an invite be used only once", async () => {
      expect((await register(alice, registrationBody(alice))).status).toBe(201);
      const bob = makeIdentity();
      const res = await register(bob, registrationBody(bob));
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ error: "invalid_invite" });
      expect(await count("users")).toBe(1);
    });

    it("lets only one of several simultaneous registrations use the same invite", async () => {
      const people = Array.from({ length: 6 }, () => makeIdentity());
      const results = await Promise.all(people.map((who) => register(who, registrationBody(who))));
      const statuses = results.map((res) => res.status).sort();
      expect(statuses).toEqual([201, 403, 403, 403, 403, 403]);
      expect(await count("users")).toBe(1);
    });

    it("rejects an expired invite", async () => {
      await db.pool.query("UPDATE invites SET expires_at = now() - interval '1 second'");
      const res = await register(alice, registrationBody(alice));
      await expectRejected(res, 403, "invalid_invite");
    });

    it("gives the same answer for unknown, used and expired codes", async () => {
      const unknown = await register(alice, registrationBody(alice, { inviteCode: "never-issued-code-0000000000" }));
      const usedCode = await issueInvite(db.pool);
      const carol = makeIdentity();
      await register(carol, registrationBody(carol, { inviteCode: usedCode }));
      const used = await register(alice, registrationBody(alice, { inviteCode: usedCode }));
      await db.pool.query("UPDATE invites SET expires_at = now() - interval '1 second' WHERE used_at IS NULL");
      const expired = await register(alice, registrationBody(alice));

      const bodies = await Promise.all([unknown, used, expired].map((res) => res.text()));
      expect([unknown.status, used.status, expired.status]).toEqual([403, 403, 403]);
      expect(new Set(bodies).size).toBe(1);
    });

    it("does not store a nonce when the invite code is wrong", async () => {
      await register(alice, registrationBody(alice, { inviteCode: "wrong-invite-code-000000000" }));
      expect(await count("auth_nonces")).toBe(0);
    });

    it("does not use up the invite when the registration is refused for another reason", async () => {
      // Signed by the wrong key.
      const mallory = makeIdentity();
      expect((await register(mallory, registrationBody(alice))).status).toBe(401);
      // Malformed.
      expect((await register(alice, registrationBody(alice, { identity_pubkey: "AAAA" }))).status).toBe(400);
      expect((await inviteState()).used_at).toBeNull();
      // And it still works afterwards.
      expect((await register(alice, registrationBody(alice))).status).toBe(201);
    });

    it("does not use up a second invite when the user is already registered", async () => {
      expect((await register(alice, registrationBody(alice))).status).toBe(201);
      const second = await issueInvite(db.pool);
      const res = await register(alice, registrationBody(alice, { inviteCode: second }));
      expect(res.status).toBe(409);
      const unused = await db.pool.query("SELECT count(*)::int AS n FROM invites WHERE used_at IS NULL");
      expect(unused.rows[0].n).toBe(1);
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
      // The swapped-in ratchet key is validly signed, so only the request signature can catch the change.
      const attackerKey = makeIdentity().ratchetKey;
      const tampered = registrationBody(alice, {
        ratchet_pubkey: crypto.toBase64(attackerKey),
        ratchet_sig: crypto.toBase64(signRatchetKey(attackerKey, alice.identity.privateKey)),
      });
      const res = await register(alice, tampered, { signAs: { body: registrationBody(alice) } });
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
      // The invite was used up by the first request, which is checked before the nonce.
      expect(second.status).toBe(403);
      expect(await count("users")).toBe(1);
    });

    it("rejects a reused nonce even when the invite is still good", async () => {
      // A signed request that fails at the last step leaves its invite unused...
      const nonce = crypto.toBase64(crypto.randomBytes(16));
      await db.pool.query(
        "INSERT INTO auth_nonces (nonce, user_id, expires_at) VALUES ($1, $2, now() + interval '1 minute')",
        [nonce, alice.userId],
      );
      // ...but the nonce has been seen, so the same request cannot be sent again.
      const res = await register(alice, registrationBody(alice), { nonce });
      await expectRejected(res, 401, "unauthorized");
      expect((await inviteState()).used_at).toBeNull();
    });

    it("refuses to register the same user twice and never replaces stored keys", async () => {
      await register(alice, registrationBody(alice));
      const newRatchetKey = makeIdentity().ratchetKey;

      // Properly signed by Alice's own identity key, so only the "already registered" rule can stop it.
      const res = await register(
        alice,
        registrationBody(alice, {
          ratchet_pubkey: crypto.toBase64(newRatchetKey),
          ratchet_sig: crypto.toBase64(signRatchetKey(newRatchetKey, alice.identity.privateKey)),
          inviteCode: await issueInvite(db.pool),
        }),
      );

      expect(res.status).toBe(409);
      expect(await res.json()).toEqual({ error: "already_registered" });
      const stored = await db.pool.query("SELECT ratchet_pubkey FROM users WHERE user_id = $1", [alice.userId]);
      expect(new Uint8Array(stored.rows[0].ratchet_pubkey)).toEqual(alice.ratchetKey);
    });
  });

  describe("malformed bodies", () => {
    it.each([
      ["missing inviteCode", { inviteCode: undefined }],
      ["missing ratchet_pubkey", { ratchet_pubkey: undefined }],
      ["missing identity_pubkey", { identity_pubkey: undefined }],
      ["missing userID", { userID: undefined }],
      ["identity key of the wrong length", { identity_pubkey: "AAAA" }],
      ["ratchet key of the wrong length", { ratchet_pubkey: Buffer.alloc(33).toString("base64") }],
      ["key that is not base64", { identity_pubkey: "!".repeat(44) }],
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
