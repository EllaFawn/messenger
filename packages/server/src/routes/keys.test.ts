import * as crypto from "@messager/crypto";
import { deriveUserId, signOneTimeKey, verifyOneTimeKey, verifyRatchetKey } from "@messager/protocol";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../app.js";
import { migrate } from "../db/migrate.js";
import { createTestDatabase, type TestDatabase } from "../db/test-db.js";
import { removeUser } from "../invites.js";
import { createLimiters, DEFAULT_RATE_LIMITS } from "../limits.js";
import {
  insertUser,
  makeIdentity,
  makeOneTimeKeys,
  oneTimeKeyJson,
  signedFetch,
  type TestIdentity,
  type TestOneTimeKey,
} from "../test-client.js";
import { startTestServer, type TestServer } from "../test-http.js";
import { MAX_ONE_TIME_KEYS_PER_UPLOAD, MAX_ONE_TIME_KEYS_PER_USER } from "./keys.js";

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

function upload(who: TestIdentity, body: unknown, base = server.url): Promise<Response> {
  return signedFetch(base, who, "/keys/one-time", {
    method: "POST",
    body: JSON.stringify(body),
    timestamp: Date.now(),
  });
}

const uploadKeys = (who: TestIdentity, keys: TestOneTimeKey[], fallback?: TestOneTimeKey) =>
  upload(who, { keys: keys.map(oneTimeKeyJson), ...(fallback ? { fallback: oneTimeKeyJson(fallback) } : {}) });

const count = async (who: TestIdentity) =>
  (await (await signedFetch(server.url, who, "/keys/count", { timestamp: Date.now() })).json()) as {
    count: number;
    has_fallback: boolean;
  };

const claim = (caller: TestIdentity, targetId: string, base = server.url) =>
  signedFetch(base, caller, `/users/${targetId}/keys/claim`, { method: "POST", timestamp: Date.now() });

interface Claimed {
  userID: string;
  identity_pubkey: string;
  ratchet_pubkey: string;
  ratchet_sig: string;
  key_epoch: number;
  one_time_key: { id: string; key: string; sig: string; fallback: boolean };
}

async function stored(): Promise<number> {
  return (await db.pool.query("SELECT count(*)::int AS n FROM one_time_keys")).rows[0].n;
}

describe("POST /keys/one-time", () => {
  it("stores signed one-time keys and reports how many are held", async () => {
    const res = await uploadKeys(bob, makeOneTimeKeys(bob, 5));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ count: 5, has_fallback: false });
    expect(await count(bob)).toEqual({ count: 5, has_fallback: false });
    expect(await count(alice)).toEqual({ count: 0, has_fallback: false });
  });

  it("stores a fallback key separately, and a new one replaces the old", async () => {
    const [first, second] = makeOneTimeKeys(bob, 2) as [TestOneTimeKey, TestOneTimeKey];
    expect(await (await uploadKeys(bob, [], first)).json()).toEqual({ count: 0, has_fallback: true });
    expect(await (await uploadKeys(bob, [], second)).json()).toEqual({ count: 0, has_fallback: true });
    const rows = await db.pool.query("SELECT key_id FROM one_time_keys WHERE is_fallback");
    expect(rows.rows).toEqual([{ key_id: second.id }]);
  });

  it("refuses a key that the caller's identity key did not sign", async () => {
    const forged = makeOneTimeKeys(alice, 1);
    const res = await uploadKeys(bob, forged);
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_request" });
    expect(await stored()).toBe(0);
  });

  it("refuses a key signed for a different ratchet key", async () => {
    const key = crypto.randomBytes(32);
    const otherRatchetKey = crypto.randomBytes(32);
    const res = await upload(bob, {
      keys: [
        {
          id: "k1",
          key: crypto.toBase64(key),
          sig: crypto.toBase64(signOneTimeKey(otherRatchetKey, key, bob.identity.privateKey)),
        },
      ],
    });
    expect(res.status).toBe(400);
    expect(await stored()).toBe(0);
  });

  it("stores nothing from a batch that contains one bad key", async () => {
    const good = makeOneTimeKeys(bob, 3);
    const bad = makeOneTimeKeys(alice, 1);
    expect((await uploadKeys(bob, [...good, ...bad])).status).toBe(400);
    expect(await stored()).toBe(0);
  });

  it("refuses a fallback key with a bad signature", async () => {
    expect((await uploadKeys(bob, makeOneTimeKeys(bob, 1), makeOneTimeKeys(alice, 1)[0])).status).toBe(400);
    expect(await stored()).toBe(0);
  });

  it("holds at most the cap, however many are uploaded", async () => {
    await uploadKeys(bob, makeOneTimeKeys(bob, 50));
    await uploadKeys(bob, makeOneTimeKeys(bob, 40));
    const res = await uploadKeys(bob, makeOneTimeKeys(bob, 50));
    expect(await res.json()).toEqual({ count: MAX_ONE_TIME_KEYS_PER_USER, has_fallback: false });
  });

  it("does not overshoot the cap when uploads arrive together", async () => {
    await Promise.all(Array.from({ length: 5 }, () => uploadKeys(bob, makeOneTimeKeys(bob, 50))));
    expect((await count(bob)).count).toBe(MAX_ONE_TIME_KEYS_PER_USER);
  });

  it("ignores a repeated key id rather than replacing the stored key", async () => {
    const [original] = makeOneTimeKeys(bob, 1) as [TestOneTimeKey];
    await uploadKeys(bob, [original]);
    const [other] = makeOneTimeKeys(bob, 1) as [TestOneTimeKey];
    await uploadKeys(bob, [{ ...other, id: original.id }]);
    const rows = await db.pool.query<{ pubkey: Buffer }>("SELECT pubkey FROM one_time_keys");
    expect(rows.rows).toHaveLength(1);
    expect(new Uint8Array(rows.rows[0]!.pubkey)).toEqual(original.key);
  });

  it.each([
    ["an empty upload", {}],
    ["an empty list and no fallback", { keys: [] }],
    ["keys that are not a list", { keys: "many" }],
    ["a key with no id", { keys: [{ key: "A".repeat(43) + "=", sig: "A".repeat(86) + "==" }] }],
    ["a key of the wrong length", { keys: [{ id: "a", key: "AAAA", sig: "A".repeat(86) + "==" }] }],
    ["a signature of the wrong length", { keys: [{ id: "a", key: "A".repeat(43) + "=", sig: "AAAA" }] }],
    ["an id with odd characters", { keys: [{ id: "a b", key: "A".repeat(43) + "=", sig: "A".repeat(86) + "==" }] }],
    ["an over-long id", { keys: [{ id: "a".repeat(65), key: "A".repeat(43) + "=", sig: "A".repeat(86) + "==" }] }],
    ["a fallback that is not an object", { fallback: "key" }],
  ])("rejects %s", async (_name, body) => {
    const res = await upload(bob, body);
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_request" });
  });

  it("rejects the same id twice in one upload", async () => {
    const [a, b] = makeOneTimeKeys(bob, 2) as [TestOneTimeKey, TestOneTimeKey];
    expect((await uploadKeys(bob, [a, { ...b, id: a.id }])).status).toBe(400);
  });

  it("accepts a full upload and rejects one key more", async () => {
    expect((await uploadKeys(bob, makeOneTimeKeys(bob, MAX_ONE_TIME_KEYS_PER_UPLOAD))).status).toBe(200);
    const res = await uploadKeys(bob, makeOneTimeKeys(bob, MAX_ONE_TIME_KEYS_PER_UPLOAD + 1));
    expect(res.status).toBe(400);
    expect(await stored()).toBe(MAX_ONE_TIME_KEYS_PER_UPLOAD);
  });

  it("requires a signed request", async () => {
    const res = await fetch(`${server.url}/keys/one-time`, { method: "POST" });
    expect(res.status).toBe(401);
    expect((await fetch(`${server.url}/keys/count`)).status).toBe(401);
  });

  it("only ever stores keys for the caller", async () => {
    await uploadKeys(bob, makeOneTimeKeys(bob, 2));
    const owners = await db.pool.query("SELECT DISTINCT user_id FROM one_time_keys");
    expect(owners.rows).toEqual([{ user_id: bob.userId }]);
  });
});

describe("POST /users/:userID/keys/claim", () => {
  it("returns the user's signed ratchet key and one one-time key, all verifiable from the userID", async () => {
    const keys = makeOneTimeKeys(bob, 3);
    await uploadKeys(bob, keys);

    const res = await claim(alice, bob.userId);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Claimed;
    expect(Object.keys(body).sort()).toEqual(
      ["identity_pubkey", "key_epoch", "one_time_key", "ratchet_pubkey", "ratchet_sig", "userID"].sort(),
    );
    expect(body.userID).toBe(bob.userId);
    expect(body.key_epoch).toBe(1);
    expect(body.one_time_key.fallback).toBe(false);

    // What a client does with the reply:
    const identityKey = crypto.fromBase64(body.identity_pubkey);
    const ratchetKey = crypto.fromBase64(body.ratchet_pubkey);
    expect(deriveUserId(identityKey)).toBe(bob.userId);
    expect(verifyRatchetKey(ratchetKey, crypto.fromBase64(body.ratchet_sig), identityKey)).toBe(true);
    expect(
      verifyOneTimeKey(
        ratchetKey,
        crypto.fromBase64(body.one_time_key.key),
        crypto.fromBase64(body.one_time_key.sig),
        identityKey,
      ),
    ).toBe(true);
    expect(keys.map((k) => k.id)).toContain(body.one_time_key.id);
  });

  it("gives each key out once and removes it", async () => {
    await uploadKeys(bob, makeOneTimeKeys(bob, 3));
    const ids: string[] = [];
    for (let i = 0; i < 3; i++) {
      ids.push(((await (await claim(alice, bob.userId)).json()) as Claimed).one_time_key.id);
    }
    expect(new Set(ids).size).toBe(3);
    expect(await count(bob)).toEqual({ count: 0, has_fallback: false });
  });

  it("never gives the same key to two simultaneous claims", async () => {
    await uploadKeys(bob, makeOneTimeKeys(bob, 8));
    const callers = Array.from({ length: 8 }, () => makeIdentity());
    for (const caller of callers) await insertUser(db.pool, caller);
    const replies = await Promise.all(callers.map((caller) => claim(caller, bob.userId)));
    const ids = await Promise.all(replies.map(async (res) => ((await res.json()) as Claimed).one_time_key.id));
    expect(replies.every((res) => res.status === 200)).toBe(true);
    expect(new Set(ids).size).toBe(8);
    expect(await stored()).toBe(0);
  });

  it("hands out the fallback key, without removing it, once the others are gone", async () => {
    const [fallback] = makeOneTimeKeys(bob, 1) as [TestOneTimeKey];
    await uploadKeys(bob, makeOneTimeKeys(bob, 1), fallback);

    const first = (await (await claim(alice, bob.userId)).json()) as Claimed;
    expect(first.one_time_key.fallback).toBe(false);
    const second = (await (await claim(alice, bob.userId)).json()) as Claimed;
    const third = (await (await claim(alice, bob.userId)).json()) as Claimed;
    expect(second.one_time_key).toEqual({ ...oneTimeKeyJson(fallback), fallback: true });
    expect(third.one_time_key.id).toBe(fallback.id);
    expect(await count(bob)).toEqual({ count: 0, has_fallback: true });
  });

  it("uses one-time keys before the fallback", async () => {
    const [fallback] = makeOneTimeKeys(bob, 1) as [TestOneTimeKey];
    await uploadKeys(bob, makeOneTimeKeys(bob, 2), fallback);
    const got = (await (await claim(alice, bob.userId)).json()) as Claimed;
    expect(got.one_time_key.fallback).toBe(false);
  });

  it("says so when the user has no keys at all", async () => {
    const res = await claim(alice, bob.userId);
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({ error: "no_one_time_keys" });
  });

  it("returns 404 for an unknown user and a malformed id", async () => {
    for (const target of [makeIdentity().userId, "not-an-id"]) {
      const res = await claim(alice, target);
      expect(res.status).toBe(404);
      expect(await res.json()).toEqual({ error: "not_found" });
    }
  });

  it("requires a signed request, and an unsigned one uses up no key", async () => {
    await uploadKeys(bob, makeOneTimeKeys(bob, 1));
    const res = await fetch(`${server.url}/users/${bob.userId}/keys/claim`, { method: "POST" });
    expect(res.status).toBe(401);
    expect(await stored()).toBe(1);
  });

  it("does not hand out keys on GET", async () => {
    await uploadKeys(bob, makeOneTimeKeys(bob, 1));
    const res = await signedFetch(server.url, alice, `/users/${bob.userId}/keys/claim`, { timestamp: Date.now() });
    expect(res.status).toBe(404);
    expect(await stored()).toBe(1);
  });

  it("removes a user's keys when their account is removed", async () => {
    await uploadKeys(bob, makeOneTimeKeys(bob, 4), makeOneTimeKeys(bob, 1)[0]);
    await removeUser(db.pool, bob.userId);
    expect(await stored()).toBe(0);
  });
});

describe("claim limits", () => {
  it("stops one user draining another's keys, without affecting anyone else", async () => {
    const limited = await startTestServer(
      createApp({
        pool: db.pool,
        limiters: createLimiters({ ...DEFAULT_RATE_LIMITS, keyClaim: { limit: 2, windowMs: 3_600_000 } }),
      }),
    );
    try {
      await uploadKeys(bob, makeOneTimeKeys(bob, 10));
      expect((await claim(alice, bob.userId, limited.url)).status).toBe(200);
      expect((await claim(alice, bob.userId, limited.url)).status).toBe(200);
      const refused = await claim(alice, bob.userId, limited.url);
      expect(refused.status).toBe(429);
      expect(await refused.json()).toEqual({ error: "rate_limited" });
      expect((await count(bob)).count).toBe(8);

      // Someone else can still start a conversation with Bob, and Alice with someone else.
      const carol = makeIdentity();
      await insertUser(db.pool, carol);
      await uploadKeys(carol, makeOneTimeKeys(carol, 1));
      expect((await claim(carol, bob.userId, limited.url)).status).toBe(200);
      expect((await claim(alice, carol.userId, limited.url)).status).toBe(200);
    } finally {
      await limited.close();
    }
  });

  it("does not count claims against users who do not exist", async () => {
    const limited = await startTestServer(
      createApp({
        pool: db.pool,
        limiters: createLimiters({ ...DEFAULT_RATE_LIMITS, keyClaim: { limit: 1, windowMs: 3_600_000 } }),
      }),
    );
    try {
      const ghost = makeIdentity().userId;
      expect((await claim(alice, ghost, limited.url)).status).toBe(404);
      expect((await claim(alice, ghost, limited.url)).status).toBe(404);
    } finally {
      await limited.close();
    }
  });
});
