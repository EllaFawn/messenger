import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { migrate } from "./db/migrate.js";
import { createTestDatabase, type TestDatabase } from "./db/test-db.js";
import { startNonceSweeper, startServer } from "./server.js";

let db: TestDatabase;

beforeAll(async () => {
  db = await createTestDatabase();
  await migrate(db.pool);
});

afterAll(async () => {
  await db.drop();
});

async function nonces(): Promise<string[]> {
  const result = await db.pool.query("SELECT nonce FROM auth_nonces ORDER BY nonce");
  return result.rows.map((r) => r.nonce);
}

describe("startServer", () => {
  it("listens on the requested host, serves requests, and stops cleanly", async () => {
    const running = await startServer({
      pool: db.pool,
      inviteCode: "a-long-enough-invite-code-123",
      host: "127.0.0.1",
      port: 0,
      sweepIntervalMs: 60_000,
    });

    expect(running.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    const res = await fetch(running.url + "/health");
    expect(await res.json()).toEqual({ status: "ok" });

    await running.close();
    await expect(fetch(running.url + "/health")).rejects.toThrow();
    // The pool belongs to the caller and must still work after close().
    expect((await db.pool.query("SELECT 1 AS one")).rows[0].one).toBe(1);
  });
});

describe("startNonceSweeper", () => {
  it("periodically deletes expired nonces and keeps live ones", async () => {
    await db.pool.query(
      `INSERT INTO auth_nonces (nonce, user_id, expires_at) VALUES
         ('expired', 'alice', now() - interval '1 second'),
         ('live',    'alice', now() + interval '1 hour')`,
    );

    const stop = startNonceSweeper(db.pool, 20);
    try {
      await expect.poll(nonces, { timeout: 2000, interval: 20 }).toEqual(["live"]);
    } finally {
      stop();
    }
  });
});
