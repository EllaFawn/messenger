import * as crypto from "@messager/crypto";
import { encodeEnvelope } from "@messager/protocol";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "./app.js";
import { migrate } from "./db/migrate.js";
import { createTestDatabase, type TestDatabase } from "./db/test-db.js";
import { createLimiters, DEFAULT_RATE_LIMITS, type RateLimits } from "./limits.js";
import {
  insertUser,
  issueInvite,
  makeIdentity,
  signedFetch,
  type SignedFetchOptions,
  type TestIdentity,
} from "./test-client.js";
import { startTestServer, type TestServer } from "./test-http.js";

const MINUTE = 60_000;
/** Small limits so the tests reach them quickly. */
const LIMITS: RateLimits = {
  register: { limit: 2, windowMs: 60 * MINUTE },
  failedAuth: { limit: 3, windowMs: MINUTE },
  wsUpgrade: { limit: 2, windowMs: MINUTE },
  sendMessage: { limit: 2, windowMs: MINUTE },
  keyLookup: { limit: 2, windowMs: MINUTE },
  signed: { limit: 3, windowMs: MINUTE },
  keyClaim: { limit: 2, windowMs: 60 * MINUTE },
};

let db: TestDatabase;
/** Behind one trusted proxy, so each test can choose which client address it appears to come from. */
let server: TestServer;
/** No trusted proxy: the forwarded header must be ignored. */
let direct: TestServer;
let alice: TestIdentity;
let bob: TestIdentity;

beforeAll(async () => {
  await crypto.ready;
  db = await createTestDatabase();
  await migrate(db.pool);
});

afterAll(async () => {
  await db.drop();
});

beforeEach(async () => {
  await db.pool.query("TRUNCATE one_time_keys, invites, messages, auth_nonces, users");
  // Fresh limiters for every test.
  server = await startTestServer(createApp({ pool: db.pool, limiters: createLimiters(LIMITS), trustedProxies: 1 }));
  direct = await startTestServer(createApp({ pool: db.pool, limiters: createLimiters(LIMITS) }));
  alice = makeIdentity();
  bob = makeIdentity();
  await insertUser(db.pool, alice);
  await insertUser(db.pool, bob);
  return async () => {
    await server.close();
    await direct.close();
  };
});

function call(who: TestIdentity, path: string, options: Partial<SignedFetchOptions> & { from?: string } = {}) {
  const { from, ...rest } = options;
  return signedFetch(server.url, who, path, {
    timestamp: Date.now(),
    ...rest,
    headers: { ...rest.headers, "x-forwarded-for": from ?? "198.51.100.1" },
  });
}

function send(from: TestIdentity, to: TestIdentity) {
  return call(from, "/messages", {
    method: "POST",
    body: JSON.stringify(encodeEnvelope(to.userId, { type: 1, body: crypto.randomBytes(32) })),
  });
}

async function registerFrom(address: string, base = server.url): Promise<Response> {
  const who = makeIdentity();
  return signedFetch(base, who, "/register", {
    method: "POST",
    timestamp: Date.now(),
    headers: { "x-forwarded-for": address },
    body: JSON.stringify({
      userID: who.userId,
      identity_pubkey: crypto.toBase64(who.identity.publicKey),
      ratchet_pubkey: crypto.toBase64(who.ratchetKey),
      ratchet_sig: crypto.toBase64(who.ratchetSig),
      inviteCode: await issueInvite(db.pool),
    }),
  });
}

async function expectLimited(res: Response): Promise<void> {
  expect(res.status).toBe(429);
  expect(Number(res.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
  expect(await res.json()).toEqual({ error: "rate_limited" });
}

describe("registration limit", () => {
  it("refuses further registrations from one address, even with valid invites", async () => {
    expect((await registerFrom("198.51.100.5")).status).toBe(201);
    expect((await registerFrom("198.51.100.5")).status).toBe(201);
    const before = (await db.pool.query("SELECT count(*)::int AS n FROM users")).rows[0].n;
    await expectLimited(await registerFrom("198.51.100.5"));
    expect((await db.pool.query("SELECT count(*)::int AS n FROM users")).rows[0].n).toBe(before);
    // The refused attempt did not use up its invite.
    expect((await db.pool.query("SELECT count(*)::int AS n FROM invites WHERE used_at IS NULL")).rows[0].n).toBe(1);
  });

  it("does not affect a different address", async () => {
    await registerFrom("198.51.100.5");
    await registerFrom("198.51.100.5");
    await expectLimited(await registerFrom("198.51.100.5"));
    expect((await registerFrom("198.51.100.6")).status).toBe(201);
  });

  it("cannot be dodged by sending a made-up forwarded address when no proxy is trusted", async () => {
    expect((await registerFrom("1.1.1.1", direct.url)).status).toBe(201);
    expect((await registerFrom("2.2.2.2", direct.url)).status).toBe(201);
    await expectLimited(await registerFrom("3.3.3.3", direct.url));
  });

  it("cannot be dodged by adding entries in front of the proxy's", async () => {
    const forged = (n: number) => `10.9.9.${n}, 198.51.100.5`;
    expect((await registerFrom(forged(1))).status).toBe(201);
    expect((await registerFrom(forged(2))).status).toBe(201);
    await expectLimited(await registerFrom(forged(3)));
  });
});

describe("failed-authentication limit", () => {
  const badRequest = (from: string) => fetch(`${server.url}/messages/inbox`, { headers: { "x-forwarded-for": from } });

  it("turns an address away entirely once it has failed too often", async () => {
    for (let i = 0; i < 3; i++) {
      expect((await badRequest("203.0.113.7")).status).toBe(401);
    }
    await expectLimited(await badRequest("203.0.113.7"));
    // Even a correctly signed request from that address is refused now.
    await expectLimited(await call(alice, "/messages/inbox", { from: "203.0.113.7" }));
    // And so is an unauthenticated route.
    await expectLimited(await fetch(`${server.url}/health`, { headers: { "x-forwarded-for": "203.0.113.7" } }));
  });

  it("does not affect other addresses", async () => {
    for (let i = 0; i < 4; i++) await badRequest("203.0.113.7");
    expect((await call(alice, "/messages/inbox", { from: "203.0.113.8" })).status).toBe(200);
  });

  it("does not count requests that succeed", async () => {
    await call(alice, "/users/" + bob.userId + "/pubkeys", { from: "203.0.113.9" });
    await call(alice, "/messages/inbox", { from: "203.0.113.9" });
    await call(alice, "/messages/inbox", { from: "203.0.113.9" });
    await call(bob, "/messages/inbox", { from: "203.0.113.9" });
    expect((await badRequest("203.0.113.9")).status).toBe(401);
  });

  it("stops a flood of forged signatures from reaching the database", async () => {
    const mallory = makeIdentity();
    const forged = () =>
      call(mallory, "/messages/inbox", { from: "203.0.113.10", headers: { "x-user-id": alice.userId } });
    for (let i = 0; i < 3; i++) expect((await forged()).status).toBe(401);
    await expectLimited(await forged());
  });
});

describe("per-user limits", () => {
  it("limits how fast one user can send, and stores nothing for a refused send", async () => {
    expect((await send(alice, bob)).status).toBe(201);
    expect((await send(alice, bob)).status).toBe(201);
    await expectLimited(await send(alice, bob));
    expect((await db.pool.query("SELECT count(*)::int AS n FROM messages")).rows[0].n).toBe(2);
  });

  it("counts each sender separately, whatever address they come from", async () => {
    await send(alice, bob);
    await send(alice, bob);
    await expectLimited(await send(alice, bob));
    expect((await send(bob, alice)).status).toBe(201);
  });

  it("follows the user, not the address", async () => {
    await send(alice, bob);
    await send(alice, bob);
    const res = await call(alice, "/messages", {
      method: "POST",
      from: "198.51.100.99",
      body: JSON.stringify(encodeEnvelope(bob.userId, { type: 1, body: crypto.randomBytes(32) })),
    });
    await expectLimited(res);
  });

  it("limits key lookups", async () => {
    const lookup = () => call(alice, `/users/${bob.userId}/pubkeys`);
    expect((await lookup()).status).toBe(200);
    expect((await lookup()).status).toBe(200);
    await expectLimited(await lookup());
  });

  it("limits other signed requests together", async () => {
    for (let i = 0; i < 3; i++) expect((await call(alice, "/messages/inbox")).status).toBe(200);
    await expectLimited(await call(alice, "/messages/inbox"));
    await expectLimited(
      await call(alice, "/messages/00000000-0000-4000-8000-000000000000/ack", { method: "POST" }),
    );
  });

  it("keeps the different kinds of limit apart", async () => {
    await send(alice, bob);
    await send(alice, bob);
    await expectLimited(await send(alice, bob));
    // Being unable to send does not stop Alice reading her inbox.
    expect((await call(alice, "/messages/inbox")).status).toBe(200);
  });

  it("checks the signature before the limit, so nobody can use up another user's allowance", async () => {
    const mallory = makeIdentity();
    for (let i = 0; i < 2; i++) {
      const res = await call(mallory, "/messages/inbox", {
        from: `192.0.2.${i}`,
        headers: { "x-user-id": alice.userId },
      });
      expect(res.status).toBe(401);
    }
    for (let i = 0; i < 3; i++) expect((await call(alice, "/messages/inbox")).status).toBe(200);
  });
});

describe("defaults", () => {
  it("match the design", () => {
    expect(DEFAULT_RATE_LIMITS).toEqual({
      register: { limit: 5, windowMs: 60 * MINUTE },
      failedAuth: { limit: 30, windowMs: MINUTE },
      wsUpgrade: { limit: 20, windowMs: MINUTE },
      sendMessage: { limit: 60, windowMs: MINUTE },
      keyLookup: { limit: 30, windowMs: MINUTE },
      signed: { limit: 300, windowMs: MINUTE },
      keyClaim: { limit: 10, windowMs: 60 * MINUTE },
    });
  });

  it("an app built without limiters is unlimited (used by tests that are not about limits)", async () => {
    const open = await startTestServer(createApp({ pool: db.pool }));
    try {
      for (let i = 0; i < 40; i++) {
        expect((await fetch(`${open.url}/messages/inbox`)).status).toBe(401);
      }
    } finally {
      await open.close();
    }
  });
});
