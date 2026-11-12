import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { migrate } from "../db/migrate.js";
import { createTestDatabase, type TestDatabase } from "../db/test-db.js";
import { consumeNonce, sweepExpiredNonces } from "./nonce-store.js";

let db: TestDatabase;

const NOW = new Date("2026-01-01T00:00:00Z");
const LATER = new Date("2026-01-01T00:02:00Z");

beforeAll(async () => {
  db = await createTestDatabase();
  await migrate(db.pool);
});

afterAll(async () => {
  await db.drop();
});

beforeEach(async () => {
  await db.pool.query("TRUNCATE auth_nonces");
});

async function storedNonces(): Promise<string[]> {
  const result = await db.pool.query("SELECT nonce FROM auth_nonces ORDER BY nonce");
  return result.rows.map((r) => r.nonce);
}

describe("consumeNonce", () => {
  it("accepts a nonce the first time it is seen", async () => {
    expect(await consumeNonce(db.pool, { nonce: "n1", userId: "alice", expiresAt: LATER })).toBe(true);
    expect(await storedNonces()).toEqual(["n1"]);
  });

  it("rejects the same nonce a second time", async () => {
    await consumeNonce(db.pool, { nonce: "n1", userId: "alice", expiresAt: LATER });
    expect(await consumeNonce(db.pool, { nonce: "n1", userId: "alice", expiresAt: LATER })).toBe(false);
  });

  it("rejects a nonce already used by a different user", async () => {
    await consumeNonce(db.pool, { nonce: "n1", userId: "alice", expiresAt: LATER });
    expect(await consumeNonce(db.pool, { nonce: "n1", userId: "bob", expiresAt: LATER })).toBe(false);
  });

  it("accepts different nonces independently", async () => {
    expect(await consumeNonce(db.pool, { nonce: "n1", userId: "alice", expiresAt: LATER })).toBe(true);
    expect(await consumeNonce(db.pool, { nonce: "n2", userId: "alice", expiresAt: LATER })).toBe(true);
  });

  it("lets exactly one of many simultaneous uses of the same nonce through", async () => {
    const attempts = await Promise.all(
      Array.from({ length: 10 }, () =>
        consumeNonce(db.pool, { nonce: "race", userId: "alice", expiresAt: LATER }),
      ),
    );
    expect(attempts.filter((accepted) => accepted)).toHaveLength(1);
  });
});

describe("sweepExpiredNonces", () => {
  it("deletes only nonces that have expired and reports how many", async () => {
    await consumeNonce(db.pool, { nonce: "old1", userId: "alice", expiresAt: new Date(NOW.getTime() - 1000) });
    await consumeNonce(db.pool, { nonce: "old2", userId: "alice", expiresAt: NOW });
    await consumeNonce(db.pool, { nonce: "live", userId: "alice", expiresAt: LATER });

    expect(await sweepExpiredNonces(db.pool, NOW)).toBe(2);
    expect(await storedNonces()).toEqual(["live"]);
  });

  it("returns 0 when nothing has expired", async () => {
    await consumeNonce(db.pool, { nonce: "live", userId: "alice", expiresAt: LATER });
    expect(await sweepExpiredNonces(db.pool, NOW)).toBe(0);
  });
});
