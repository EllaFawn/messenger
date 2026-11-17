import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { migrate } from "./db/migrate.js";
import { createTestDatabase, type TestDatabase } from "./db/test-db.js";
import {
  claimInvite,
  createInvite,
  hashInviteCode,
  isInviteUsable,
  listInvites,
  removeUser,
  revokeInvite,
} from "./invites.js";
import { insertUser, makeIdentity } from "./test-client.js";
import * as crypto from "@messager/crypto";

let db: TestDatabase;

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
});

const inAnHour = () => new Date(Date.now() + 3_600_000);
const anHourAgo = () => new Date(Date.now() - 3_600_000);

/** Claims inside a transaction, the way registration does. */
async function claim(code: string, userId: string): Promise<boolean> {
  const client = await db.pool.connect();
  try {
    await client.query("BEGIN");
    const ok = await claimInvite(client, hashInviteCode(code), userId);
    await client.query(ok ? "COMMIT" : "ROLLBACK");
    return ok;
  } finally {
    client.release();
  }
}

async function newUser(): Promise<string> {
  const who = makeIdentity();
  await insertUser(db.pool, who);
  return who.userId;
}

describe("createInvite", () => {
  it("returns a long random code and stores only its hash", async () => {
    const { code } = await createInvite(db.pool, { note: "for Sam", expiresAt: inAnHour() });
    expect(code).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const rows = await db.pool.query("SELECT * FROM invites");
    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0].code_hash).toEqual(hashInviteCode(code));
    expect(rows.rows[0].note).toBe("for Sam");
    expect(rows.rows[0].used_at).toBeNull();
    expect(JSON.stringify(rows.rows)).not.toContain(code);
  });

  it("makes a different code every time", async () => {
    const a = await createInvite(db.pool, { note: "", expiresAt: inAnHour() });
    const b = await createInvite(db.pool, { note: "", expiresAt: inAnHour() });
    expect(a.code).not.toBe(b.code);
  });

  it("refuses an expiry in the past", async () => {
    await expect(createInvite(db.pool, { note: "", expiresAt: anHourAgo() })).rejects.toThrow(/future/);
  });

  it("refuses an over-long note", async () => {
    await expect(createInvite(db.pool, { note: "x".repeat(201), expiresAt: inAnHour() })).rejects.toThrow(/note/);
  });
});

describe("claimInvite", () => {
  it("lets a valid code be used once, and records who used it", async () => {
    const { code } = await createInvite(db.pool, { note: "", expiresAt: inAnHour() });
    const userId = await newUser();

    expect(await isInviteUsable(db.pool, hashInviteCode(code))).toBe(true);
    expect(await claim(code, userId)).toBe(true);

    const row = (await db.pool.query("SELECT used_at, used_by FROM invites")).rows[0];
    expect(row.used_by).toBe(userId);
    expect(row.used_at).toBeInstanceOf(Date);
    expect(await isInviteUsable(db.pool, hashInviteCode(code))).toBe(false);
  });

  it("refuses a second use", async () => {
    const { code } = await createInvite(db.pool, { note: "", expiresAt: inAnHour() });
    const first = await newUser();
    expect(await claim(code, first)).toBe(true);
    expect(await claim(code, await newUser())).toBe(false);
    expect((await db.pool.query("SELECT used_by FROM invites")).rows[0].used_by).toBe(first);
  });

  it("lets only one of two simultaneous claims succeed", async () => {
    const { code } = await createInvite(db.pool, { note: "", expiresAt: inAnHour() });
    const users = await Promise.all(Array.from({ length: 8 }, () => newUser()));
    const results = await Promise.all(users.map((userId) => claim(code, userId)));
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it("refuses an expired code", async () => {
    const { code } = await createInvite(db.pool, { note: "", expiresAt: inAnHour() });
    await db.pool.query("UPDATE invites SET expires_at = now() - interval '1 second'");
    expect(await isInviteUsable(db.pool, hashInviteCode(code))).toBe(false);
    expect(await claim(code, await newUser())).toBe(false);
  });

  it("refuses a code that was never issued", async () => {
    expect(await isInviteUsable(db.pool, hashInviteCode("made-up"))).toBe(false);
    expect(await claim("made-up", await newUser())).toBe(false);
  });

  it("leaves the invite unused if the surrounding transaction rolls back", async () => {
    const { code } = await createInvite(db.pool, { note: "", expiresAt: inAnHour() });
    const userId = await newUser();
    const client = await db.pool.connect();
    await client.query("BEGIN");
    expect(await claimInvite(client, hashInviteCode(code), userId)).toBe(true);
    await client.query("ROLLBACK");
    client.release();
    expect(await isInviteUsable(db.pool, hashInviteCode(code))).toBe(true);
  });
});

describe("listInvites", () => {
  it("shows each invite's state without revealing codes", async () => {
    const used = await createInvite(db.pool, { note: "used one", expiresAt: inAnHour() });
    const userId = await newUser();
    await claim(used.code, userId);
    const expired = await createInvite(db.pool, { note: "old one", expiresAt: inAnHour() });
    await db.pool.query("UPDATE invites SET expires_at = now() - interval '1 second' WHERE code_hash = $1", [
      hashInviteCode(expired.code),
    ]);
    const open = await createInvite(db.pool, { note: "open one", expiresAt: inAnHour() });

    const list = await listInvites(db.pool);
    const byNote = new Map(list.map((invite) => [invite.note, invite]));
    expect(byNote.get("used one")).toMatchObject({ state: "used", usedBy: userId });
    expect(byNote.get("old one")).toMatchObject({ state: "expired", usedBy: null });
    expect(byNote.get("open one")).toMatchObject({ state: "unused", usedBy: null });
    expect(byNote.get("open one")!.id).toBe(hashInviteCode(open.code).toString("hex").slice(0, 12));
    for (const code of [used.code, expired.code, open.code]) {
      expect(JSON.stringify(list)).not.toContain(code);
    }
  });
});

describe("revokeInvite", () => {
  it("deletes an unused invite so its code stops working", async () => {
    const { code } = await createInvite(db.pool, { note: "", expiresAt: inAnHour() });
    const id = hashInviteCode(code).toString("hex").slice(0, 12);
    expect(await revokeInvite(db.pool, id)).toBe("revoked");
    expect(await claim(code, await newUser())).toBe(false);
  });

  it("reports an id that matches nothing", async () => {
    expect(await revokeInvite(db.pool, "abcdef012345")).toBe("not_found");
  });

  it("does not delete the record of a used invite", async () => {
    const { code } = await createInvite(db.pool, { note: "", expiresAt: inAnHour() });
    await claim(code, await newUser());
    const id = hashInviteCode(code).toString("hex").slice(0, 12);
    expect(await revokeInvite(db.pool, id)).toBe("already_used");
    expect((await db.pool.query("SELECT count(*)::int AS n FROM invites")).rows[0].n).toBe(1);
  });

  it.each([["abc"], ["not-hex-chars"], [""], ["%"], ["ab_"]])("refuses the malformed id %j", async (id) => {
    await createInvite(db.pool, { note: "", expiresAt: inAnHour() });
    await expect(revokeInvite(db.pool, id)).rejects.toThrow(/at least 8/);
    expect((await db.pool.query("SELECT count(*)::int AS n FROM invites")).rows[0].n).toBe(1);
  });
});

describe("removeUser", () => {
  it("deletes the account and every message to or from it", async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    await insertUser(db.pool, alice);
    await insertUser(db.pool, bob);
    for (const [from, to] of [
      [alice, bob],
      [bob, alice],
    ] as const) {
      await db.pool.query(
        "INSERT INTO messages (from_user_id, to_user_id, msg_type, ciphertext) VALUES ($1, $2, $3, $4)",
        [from.userId, to.userId, 1, Buffer.alloc(16)],
      );
    }

    expect(await removeUser(db.pool, alice.userId)).toBe(true);
    expect((await db.pool.query("SELECT user_id FROM users")).rows).toEqual([{ user_id: bob.userId }]);
    expect((await db.pool.query("SELECT count(*)::int AS n FROM messages")).rows[0].n).toBe(0);
  });

  it("keeps the invite record but clears who used it", async () => {
    const { code } = await createInvite(db.pool, { note: "for alice", expiresAt: inAnHour() });
    const userId = await newUser();
    await claim(code, userId);

    await removeUser(db.pool, userId);
    const row = (await db.pool.query("SELECT used_at, used_by FROM invites")).rows[0];
    expect(row.used_by).toBeNull();
    // Still marked used: removing someone does not hand their invite back.
    expect(row.used_at).toBeInstanceOf(Date);
    expect(await claim(code, await newUser())).toBe(false);
  });

  it("reports a user that does not exist", async () => {
    expect(await removeUser(db.pool, makeIdentity().userId)).toBe(false);
  });
});
