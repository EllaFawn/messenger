import * as crypto from "@messager/crypto";
import { encodeEnvelope } from "@messager/protocol";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../app.js";
import { migrate } from "../db/migrate.js";
import { createTestDatabase, type TestDatabase } from "../db/test-db.js";
import { insertUser, makeIdentity, signedFetch, type TestIdentity } from "../test-client.js";
import { startTestServer, type TestServer } from "../test-http.js";
import { DEFAULT_QUEUE_LIMITS, MESSAGE_MAX_AGE_MS, sweepExpiredMessages } from "./messages.js";

const PAGE = 3;

let db: TestDatabase;
/** Small queues and pages so the tests reach the edges quickly. */
let server: TestServer;
let alice: TestIdentity;
let bob: TestIdentity;
let carol: TestIdentity;

beforeAll(async () => {
  await crypto.ready;
  db = await createTestDatabase();
  await migrate(db.pool);
  server = await startTestServer(
    createApp({ pool: db.pool, queueLimits: { perPair: 3, perRecipient: 5 }, inboxPageSize: PAGE }),
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
  carol = makeIdentity();
  for (const who of [alice, bob, carol]) await insertUser(db.pool, who);
});

function send(from: TestIdentity, toUserId: string): Promise<Response> {
  return signedFetch(server.url, from, "/messages", {
    method: "POST",
    body: JSON.stringify(encodeEnvelope(toUserId, { type: 1, body: crypto.randomBytes(32) })),
    timestamp: Date.now(),
  });
}

interface Item {
  message_id: string;
  from: string;
  cursor: string;
}

async function page(who: TestIdentity, after?: string): Promise<Item[]> {
  const path = after === undefined ? "/messages/inbox" : `/messages/inbox?after=${encodeURIComponent(after)}`;
  const res = await signedFetch(server.url, who, path, { timestamp: Date.now() });
  expect(res.status).toBe(200);
  return (await res.json()) as Item[];
}

const ack = (who: TestIdentity, id: string) =>
  signedFetch(server.url, who, `/messages/${id}/ack`, { method: "POST", timestamp: Date.now() });

async function stored(): Promise<number> {
  return (await db.pool.query("SELECT count(*)::int AS n FROM messages")).rows[0].n;
}

/** Inserts messages for Bob directly, each one microsecond after the last, and returns their ids in order. */
async function fill(count: number, from: TestIdentity = alice, to: TestIdentity = bob): Promise<string[]> {
  const result = await db.pool.query<{ message_id: string }>(
    `INSERT INTO messages (from_user_id, to_user_id, msg_type, ciphertext, created_at)
     SELECT $1, $2, $3, $4, now() - interval '1 hour' + n * interval '1 microsecond'
     FROM generate_series(1, $5::int) AS n
     RETURNING message_id, created_at`,
    [from.userId, to.userId, 1, Buffer.alloc(16), count],
  );
  const ordered = await db.pool.query<{ message_id: string }>(
    "SELECT message_id FROM messages WHERE message_id = ANY($1) ORDER BY created_at, message_id",
    [result.rows.map((row) => row.message_id)],
  );
  return ordered.rows.map((row) => row.message_id);
}

describe("queue limits", () => {
  it("refuses more undelivered messages from one sender to one recipient than the limit", async () => {
    for (let i = 0; i < 3; i++) expect((await send(alice, bob.userId)).status).toBe(201);
    const res = await send(alice, bob.userId);
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: "recipient_queue_full" });
    expect(await stored()).toBe(3);
  });

  it("still lets that sender write to someone else, and others write to that recipient", async () => {
    for (let i = 0; i < 3; i++) await send(alice, bob.userId);
    expect((await send(alice, carol.userId)).status).toBe(201);
    expect((await send(carol, bob.userId)).status).toBe(201);
  });

  it("refuses everyone once the recipient's whole queue is full", async () => {
    for (let i = 0; i < 3; i++) await send(alice, bob.userId);
    for (let i = 0; i < 2; i++) expect((await send(carol, bob.userId)).status).toBe(201);
    const res = await send(carol, bob.userId);
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: "recipient_queue_full" });
    expect(await stored()).toBe(5);
  });

  it("makes room again when the recipient acknowledges a message", async () => {
    for (let i = 0; i < 3; i++) await send(alice, bob.userId);
    expect((await send(alice, bob.userId)).status).toBe(429);
    const [first] = await page(bob);
    expect((await ack(bob, first!.message_id)).status).toBe(204);
    expect((await send(alice, bob.userId)).status).toBe(201);
  });

  it("still answers 404, not 429, for a recipient who does not exist", async () => {
    const res = await send(alice, makeIdentity().userId);
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "recipient_not_found" });
  });

  it("defaults to the limits in the design", () => {
    expect(DEFAULT_QUEUE_LIMITS).toEqual({ perPair: 500, perRecipient: 5000 });
  });
});

describe("inbox paging", () => {
  it("gives every item a cursor and returns one page at a time", async () => {
    const ids = await fill(7);
    const first = await page(bob);
    expect(first.map((item) => item.message_id)).toEqual(ids.slice(0, PAGE));
    for (const item of first) expect(item.cursor).toMatch(/^\d+_[0-9a-f-]{36}$/);
  });

  it("walks the whole inbox in order with no gaps or repeats, a microsecond apart", async () => {
    const ids = await fill(10);
    const seen: string[] = [];
    let after: string | undefined;
    for (let guard = 0; guard < 10; guard++) {
      const items = await page(bob, after);
      if (items.length === 0) break;
      seen.push(...items.map((item) => item.message_id));
      after = items.at(-1)!.cursor;
    }
    expect(seen).toEqual(ids);
  });

  it("orders messages with exactly the same time consistently across pages", async () => {
    await db.pool.query(
      `INSERT INTO messages (from_user_id, to_user_id, msg_type, ciphertext, created_at)
       SELECT $1, $2, $3, $4, '2027-01-01T00:00:00Z' FROM generate_series(1, 8)`,
      [alice.userId, bob.userId, 1, Buffer.alloc(16)],
    );
    const seen = new Set<string>();
    let after: string | undefined;
    for (let guard = 0; guard < 10; guard++) {
      const items = await page(bob, after);
      if (items.length === 0) break;
      for (const item of items) seen.add(item.message_id);
      after = items.at(-1)!.cursor;
    }
    expect(seen.size).toBe(8);
  });

  it("keeps its place when the messages on the previous page have been acknowledged", async () => {
    const ids = await fill(6);
    const first = await page(bob);
    for (const item of first) await ack(bob, item.message_id);
    const second = await page(bob, first.at(-1)!.cursor);
    expect(second.map((item) => item.message_id)).toEqual(ids.slice(3, 6));
  });

  it("lets a client step past messages it leaves on the server", async () => {
    // Three from a sender Bob is ignoring, then one he wants.
    await fill(3, carol);
    const wanted = (await fill(1, alice))[0];
    const first = await page(bob);
    expect(first.every((item) => item.from === carol.userId)).toBe(true);
    const second = await page(bob, first.at(-1)!.cursor);
    expect(second.map((item) => item.message_id)).toEqual([wanted]);
    // Nothing was acknowledged; all four are still there.
    expect(await stored()).toBe(4);
  });

  it("returns nothing after the last message", async () => {
    await fill(2);
    const items = await page(bob);
    expect(await page(bob, items.at(-1)!.cursor)).toEqual([]);
  });

  it("never returns another user's messages, whatever cursor is given", async () => {
    await fill(3, alice, bob);
    await fill(3, alice, carol);
    const bobs = await page(bob);
    const carols = await page(carol, bobs[0]!.cursor);
    expect(carols.every((item) => item.message_id !== bobs[0]!.message_id)).toBe(true);
    const owners = await db.pool.query<{ to_user_id: string }>(
      "SELECT DISTINCT to_user_id FROM messages WHERE message_id = ANY($1)",
      [carols.map((item) => item.message_id)],
    );
    expect(owners.rows.map((row) => row.to_user_id)).toEqual(carols.length === 0 ? [] : [carol.userId]);
  });

  it.each([
    ["text"],
    ["123"],
    ["123_not-a-uuid"],
    ["_00000000-0000-4000-8000-000000000000"],
    ["-5_00000000-0000-4000-8000-000000000000"],
    ["99999999999999999999999_00000000-0000-4000-8000-000000000000"],
    ["1_00000000-0000-4000-8000-000000000000; DROP TABLE messages"],
    [""],
  ])("rejects the malformed cursor %j", async (cursor) => {
    await fill(1);
    const res = await signedFetch(server.url, bob, `/messages/inbox?after=${encodeURIComponent(cursor)}`, {
      timestamp: Date.now(),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_request" });
    expect(await stored()).toBe(1);
  });

  it("rejects a cursor given twice", async () => {
    const res = await signedFetch(server.url, bob, "/messages/inbox?after=1_a&after=2_b", { timestamp: Date.now() });
    expect(res.status).toBe(400);
  });

  it("covers the cursor with the signature", async () => {
    await fill(4);
    const [first] = await page(bob);
    const path = `/messages/inbox?after=${encodeURIComponent(first!.cursor)}`;
    const res = await signedFetch(server.url, bob, path, { timestamp: Date.now(), signAs: { path: "/messages/inbox" } });
    expect(res.status).toBe(401);
  });
});

describe("sweepExpiredMessages", () => {
  it("deletes undelivered messages older than the limit and keeps the rest", async () => {
    const day = 86_400_000;
    await db.pool.query(
      `INSERT INTO messages (from_user_id, to_user_id, msg_type, ciphertext, created_at) VALUES
         ($1, $2, $3, $4, now() - interval '31 days'),
         ($1, $2, $3, $4, now() - interval '29 days'),
         ($1, $2, $3, $4, now())`,
      [alice.userId, bob.userId, 1, Buffer.alloc(16)],
    );
    expect(await sweepExpiredMessages(db.pool, new Date(), 30 * day)).toBe(1);
    expect(await stored()).toBe(2);
    expect(await sweepExpiredMessages(db.pool, new Date(), 30 * day)).toBe(0);
  });

  it("keeps messages for 30 days by default", () => {
    expect(MESSAGE_MAX_AGE_MS).toBe(30 * 86_400_000);
  });
});
