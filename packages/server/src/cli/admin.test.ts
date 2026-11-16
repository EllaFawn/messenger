import * as crypto from "@messager/crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { migrate } from "../db/migrate.js";
import { createTestDatabase, type TestDatabase } from "../db/test-db.js";
import { hashInviteCode, isInviteUsable } from "../invites.js";
import { insertUser, makeIdentity } from "../test-client.js";
import { parseDuration, runAdmin } from "./admin.js";

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
  await db.pool.query("TRUNCATE invites, messages, auth_nonces, users");
});

/** Runs a command the way the npm script does and captures what it prints. */
async function run(...args: string[]): Promise<{ code: number; text: string }> {
  const lines: string[] = [];
  const code = await runAdmin(args, db.pool, (line) => lines.push(line));
  return { code, text: lines.join("\n") };
}

function codeFrom(text: string): string {
  const match = /^ {2}([A-Za-z0-9_-]{43})$/m.exec(text);
  if (match === null) throw new Error(`no invite code in output:\n${text}`);
  return match[1]!;
}

async function inviteCount(): Promise<number> {
  return (await db.pool.query("SELECT count(*)::int AS n FROM invites")).rows[0].n;
}

describe("parseDuration", () => {
  it.each([
    ["7d", 7 * 86_400_000],
    ["1d", 86_400_000],
    ["12h", 12 * 3_600_000],
    ["90d", 90 * 86_400_000],
  ])("reads %s", (text, ms) => {
    expect(parseDuration(text)).toBe(ms);
  });

  it.each([["0d"], ["91d"], ["-1d"], ["7"], ["d"], ["1w"], ["1.5d"], [""], ["7 d"]])("refuses %j", (text) => {
    expect(() => parseDuration(text)).toThrow(/between 1h and 90d/);
  });
});

describe("invite create", () => {
  it("prints a working code once, with its id and expiry", async () => {
    const { code, text } = await run("invite", "create", "--note", "for Sam");
    expect(code).toBe(0);
    const inviteCode = codeFrom(text);
    expect(await isInviteUsable(db.pool, hashInviteCode(inviteCode))).toBe(true);
    expect(text).toContain(hashInviteCode(inviteCode).toString("hex").slice(0, 12));
    expect(text).toMatch(/will not be shown again/);

    const row = (await db.pool.query("SELECT note, expires_at FROM invites")).rows[0];
    expect(row.note).toBe("for Sam");
    const days = (row.expires_at.getTime() - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(6.9);
    expect(days).toBeLessThan(7.1);
  });

  it("honours --expires", async () => {
    await run("invite", "create", "--expires", "2h");
    const row = (await db.pool.query("SELECT expires_at FROM invites")).rows[0];
    const hours = (row.expires_at.getTime() - Date.now()) / 3_600_000;
    expect(hours).toBeGreaterThan(1.9);
    expect(hours).toBeLessThan(2.1);
  });

  it.each([
    [["invite", "create", "--expires", "forever"]],
    [["invite", "create", "--note"]],
    [["invite", "create", "--surprise", "x"]],
    [["invite", "create", "stray"]],
  ])("refuses %j and creates nothing", async (args) => {
    const { code, text } = await run(...args);
    expect(code).toBe(1);
    expect(text).not.toBe("");
    expect(await inviteCount()).toBe(0);
  });
});

describe("invite list", () => {
  it("says so when there are none", async () => {
    const { code, text } = await run("invite", "list");
    expect(code).toBe(0);
    expect(text).toMatch(/No invites/);
  });

  it("shows id, state and note for each invite, and never a code", async () => {
    const first = codeFrom((await run("invite", "create", "--note", "for Sam")).text);
    const second = codeFrom((await run("invite", "create", "--note", "for Ada")).text);
    const user = makeIdentity();
    await insertUser(db.pool, user);
    await db.pool.query("UPDATE invites SET used_at = now(), used_by = $1 WHERE code_hash = $2", [
      user.userId,
      hashInviteCode(first),
    ]);

    const { text } = await run("invite", "list");
    expect(text).toContain("for Sam");
    expect(text).toContain("for Ada");
    expect(text).toMatch(/used/);
    expect(text).toMatch(/unused/);
    expect(text).toContain(user.userId);
    expect(text).not.toContain(first);
    expect(text).not.toContain(second);
  });
});

describe("invite revoke", () => {
  it("revokes an unused invite by its id", async () => {
    const inviteCode = codeFrom((await run("invite", "create")).text);
    const id = hashInviteCode(inviteCode).toString("hex").slice(0, 12);
    const { code, text } = await run("invite", "revoke", id);
    expect(code).toBe(0);
    expect(text).toMatch(/Revoked/);
    expect(await isInviteUsable(db.pool, hashInviteCode(inviteCode))).toBe(false);
  });

  it("fails clearly for an unknown id, a used invite, or no id", async () => {
    expect((await run("invite", "revoke", "abcdef012345")).code).toBe(1);
    expect((await run("invite", "revoke")).code).toBe(1);
    expect((await run("invite", "revoke", "xyz")).code).toBe(1);
  });
});

describe("user list and remove", () => {
  it("lists accounts", async () => {
    const user = makeIdentity();
    await insertUser(db.pool, user);
    const { code, text } = await run("user", "list");
    expect(code).toBe(0);
    expect(text).toContain(user.userId);
  });

  it("only describes the removal unless --yes is given", async () => {
    const user = makeIdentity();
    await insertUser(db.pool, user);
    const { code, text } = await run("user", "remove", user.userId);
    expect(code).toBe(1);
    expect(text).toMatch(/--yes/);
    expect((await db.pool.query("SELECT count(*)::int AS n FROM users")).rows[0].n).toBe(1);
  });

  it("removes the account with --yes", async () => {
    const user = makeIdentity();
    await insertUser(db.pool, user);
    const { code, text } = await run("user", "remove", user.userId, "--yes");
    expect(code).toBe(0);
    expect(text).toMatch(/Removed/);
    expect((await db.pool.query("SELECT count(*)::int AS n FROM users")).rows[0].n).toBe(0);
  });

  it("fails for an unknown or malformed user ID", async () => {
    expect((await run("user", "remove", makeIdentity().userId, "--yes")).code).toBe(1);
    expect((await run("user", "remove", "not-an-id", "--yes")).code).toBe(1);
    expect((await run("user", "remove")).code).toBe(1);
  });
});

describe("usage", () => {
  it.each([[[]], [["invite"]], [["invite", "destroy"]], [["nonsense"]], [["user", "promote"]]])(
    "prints help and fails for %j",
    async (args) => {
      const { code, text } = await run(...(args as string[]));
      expect(code).toBe(1);
      expect(text).toMatch(/invite create/);
    },
  );
});
