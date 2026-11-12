import * as crypto from "@messager/crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createBaseApp, installFallbackHandlers } from "../app.js";
import { migrate } from "../db/migrate.js";
import { createTestDatabase, type TestDatabase } from "../db/test-db.js";
import { insertUser, makeIdentity, signedFetch, type TestIdentity } from "../test-client.js";
import { startTestServer, type TestServer } from "../test-http.js";
import { authenticatedUserId, requireSignedRequest, TIMESTAMP_WINDOW_MS } from "./signed-request.js";

const NOW = 1_800_000_000_000;

let db: TestDatabase;
let server: TestServer;
let alice: TestIdentity;

beforeAll(async () => {
  await crypto.ready;
  db = await createTestDatabase();
  await migrate(db.pool);

  const app = createBaseApp();
  const auth = requireSignedRequest({ pool: db.pool, now: () => NOW });
  app.get("/_test/whoami", auth, (_req, res) => {
    res.json({ userId: authenticatedUserId(res) });
  });
  app.post("/_test/whoami", auth, (_req, res) => {
    res.json({ userId: authenticatedUserId(res) });
  });
  installFallbackHandlers(app);
  server = await startTestServer(app);
});

afterAll(async () => {
  await server.close();
  await db.drop();
});

beforeEach(async () => {
  await db.pool.query("TRUNCATE messages, auth_nonces, users");
  alice = makeIdentity();
  await insertUser(db.pool, alice);
});

async function nonceCount(): Promise<number> {
  const result = await db.pool.query("SELECT count(*)::int AS n FROM auth_nonces");
  return result.rows[0].n;
}

async function expectUnauthorized(res: Response) {
  expect(res.status).toBe(401);
  expect(await res.json()).toEqual({ error: "unauthorized" });
}

describe("requireSignedRequest", () => {
  it("accepts a correctly signed GET and identifies the caller", async () => {
    const res = await signedFetch(server.url, alice, "/_test/whoami", { timestamp: NOW });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ userId: alice.userId });
  });

  it("accepts a correctly signed POST with a body", async () => {
    const res = await signedFetch(server.url, alice, "/_test/whoami", {
      method: "POST",
      body: '{"hello":"world"}',
      timestamp: NOW,
    });
    expect(res.status).toBe(200);
  });

  it("records the nonce of an accepted request", async () => {
    await signedFetch(server.url, alice, "/_test/whoami", { timestamp: NOW });
    expect(await nonceCount()).toBe(1);
  });

  describe("timestamp window", () => {
    it("accepts a timestamp at the edge of the window", async () => {
      const past = await signedFetch(server.url, alice, "/_test/whoami", {
        timestamp: NOW - TIMESTAMP_WINDOW_MS,
      });
      const future = await signedFetch(server.url, alice, "/_test/whoami", {
        timestamp: NOW + TIMESTAMP_WINDOW_MS,
      });
      expect(past.status).toBe(200);
      expect(future.status).toBe(200);
    });

    it("rejects a stale timestamp", async () => {
      await expectUnauthorized(
        await signedFetch(server.url, alice, "/_test/whoami", { timestamp: NOW - TIMESTAMP_WINDOW_MS - 1 }),
      );
    });

    it("rejects a timestamp too far in the future", async () => {
      await expectUnauthorized(
        await signedFetch(server.url, alice, "/_test/whoami", { timestamp: NOW + TIMESTAMP_WINDOW_MS + 1 }),
      );
    });
  });

  describe("replay", () => {
    it("rejects a second request that reuses a nonce", async () => {
      const nonce = crypto.toBase64(crypto.randomBytes(16));
      const first = await signedFetch(server.url, alice, "/_test/whoami", { timestamp: NOW, nonce });
      const second = await signedFetch(server.url, alice, "/_test/whoami", { timestamp: NOW, nonce });
      expect(first.status).toBe(200);
      await expectUnauthorized(second);
    });
  });

  describe("signature", () => {
    it("rejects a request signed by a different key", async () => {
      const mallory = makeIdentity();
      const res = await signedFetch(server.url, mallory, "/_test/whoami", {
        timestamp: NOW,
        headers: { "x-user-id": alice.userId },
      });
      await expectUnauthorized(res);
    });

    it("rejects a user that is not registered", async () => {
      const stranger = makeIdentity();
      await expectUnauthorized(await signedFetch(server.url, stranger, "/_test/whoami", { timestamp: NOW }));
    });

    it("rejects a signature made for a different path", async () => {
      const res = await signedFetch(server.url, alice, "/_test/whoami", {
        timestamp: NOW,
        signAs: { path: "/_test/other" },
      });
      await expectUnauthorized(res);
    });

    it("rejects a query string that was not signed", async () => {
      const res = await signedFetch(server.url, alice, "/_test/whoami?extra=1", {
        timestamp: NOW,
        signAs: { path: "/_test/whoami" },
      });
      await expectUnauthorized(res);
    });

    it("rejects a signature made for a different method", async () => {
      const res = await signedFetch(server.url, alice, "/_test/whoami", {
        timestamp: NOW,
        signAs: { method: "POST" },
      });
      await expectUnauthorized(res);
    });

    it("rejects a body that was changed after signing", async () => {
      const res = await signedFetch(server.url, alice, "/_test/whoami", {
        method: "POST",
        body: '{"amount":9999}',
        timestamp: NOW,
        signAs: { body: '{"amount":1}' },
      });
      await expectUnauthorized(res);
    });

    it("rejects a timestamp header that differs from the signed one", async () => {
      const res = await signedFetch(server.url, alice, "/_test/whoami", {
        timestamp: NOW - 30_000,
        headers: { "x-timestamp": String(NOW) },
      });
      await expectUnauthorized(res);
    });
  });

  describe("malformed or missing headers", () => {
    it.each(["x-user-id", "x-timestamp", "x-nonce", "x-signature"])("rejects a missing %s", async (name) => {
      const res = await signedFetch(server.url, alice, "/_test/whoami", {
        timestamp: NOW,
        headers: { [name]: undefined },
      });
      await expectUnauthorized(res);
    });

    it.each([
      ["x-timestamp", "not-a-number"],
      ["x-timestamp", "1e12"],
      ["x-timestamp", "-5"],
      ["x-nonce", "c2hvcnQ="],
      ["x-nonce", "!!!!!!!!!!!!!!!!!!!!!!=="],
      ["x-signature", "AAAA"],
      ["x-signature", "not base64 at all"],
      ["x-user-id", "too-short"],
    ])("rejects a malformed %s (%s)", async (name, value) => {
      const res = await signedFetch(server.url, alice, "/_test/whoami", {
        timestamp: NOW,
        headers: { [name]: value },
      });
      await expectUnauthorized(res);
    });
  });

  describe("rejected requests leave no trace", () => {
    it("does not store a nonce when the signature is invalid", async () => {
      const mallory = makeIdentity();
      await signedFetch(server.url, mallory, "/_test/whoami", {
        timestamp: NOW,
        headers: { "x-user-id": alice.userId },
      });
      expect(await nonceCount()).toBe(0);
    });

    it("does not store a nonce when the user is unknown", async () => {
      await signedFetch(server.url, makeIdentity(), "/_test/whoami", { timestamp: NOW });
      expect(await nonceCount()).toBe(0);
    });

    it("does not store a nonce when the timestamp is stale", async () => {
      await signedFetch(server.url, alice, "/_test/whoami", { timestamp: NOW - TIMESTAMP_WINDOW_MS - 1 });
      expect(await nonceCount()).toBe(0);
    });
  });
});
