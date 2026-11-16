/**
 * The real web-client code talking to the real server over HTTP and
 * WebSocket, with a real Postgres database. Only the browser itself is
 * replaced: IndexedDB by fake-indexeddb, and the page by direct calls into
 * the same modules the screens use.
 *
 * This is the only place allowed to import both packages; neither imports
 * the other.
 */
import * as crypto from "@messager/crypto";
import { computeSafetyNumber } from "@messager/protocol";
import { IDBFactory } from "fake-indexeddb";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { migrate } from "../packages/server/src/db/migrate.js";
import { createTestDatabase, type TestDatabase } from "../packages/server/src/db/test-db.js";
import { startServer, type RunningServer } from "../packages/server/src/server.js";
import { ApiError, createApiClient, type ApiClient } from "../packages/web/src/api/client.js";
import { receiveMessages, sendChatMessage } from "../packages/web/src/chat.js";
import { addContact, canSendTo, refreshContactKeys } from "../packages/web/src/contacts.js";
import type { StoredIdentity } from "../packages/web/src/identity.js";
import { connectPush } from "../packages/web/src/push.js";
import { isRejectedByServer, loadSession, registerAgain, signUp } from "../packages/web/src/session.js";
import { getContact } from "../packages/web/src/storage/contact-store.js";
import { openDatabase } from "../packages/web/src/storage/db.js";
import { listMessages } from "../packages/web/src/storage/message-store.js";

const INVITE = "e2e-invite-code-0123456789";

let db: TestDatabase;
let server: RunningServer;
let client: ApiClient;
let stops: (() => void)[];

/** One person's browser: its own storage and, once signed up, its identity. */
interface Browser {
  storage: IDBDatabase;
  me: StoredIdentity;
}

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
  server = await startServer({ pool: db.pool, inviteCode: INVITE, host: "127.0.0.1", port: 0 });
  // Through the /api prefix, exactly as the page reaches the server.
  client = createApiClient({ baseUrl: `${server.url}/api` });
  stops = [];
});

afterEach(async () => {
  for (const stop of stops) stop();
  await server.close();
});

async function newBrowser(): Promise<Browser> {
  const storage = await openDatabase(new IDBFactory());
  const session = await signUp({ db: storage, client, inviteCode: INVITE });
  if (session.status !== "registered") throw new Error("sign-up did not complete");
  return { storage, me: session.identity };
}

async function befriend(a: Browser, b: Browser): Promise<void> {
  await addContact({ db: a.storage, client, me: a.me, userId: b.me.userId });
  await addContact({ db: b.storage, client, me: b.me, userId: a.me.userId });
}

const say = (from: Browser, to: Browser, text: string) =>
  sendChatMessage({ db: from.storage, client, me: from.me, contactId: to.me.userId, text });
const check = (who: Browser) => receiveMessages({ db: who.storage, client, me: who.me });
const conversation = async (who: Browser, withWhom: Browser) =>
  (await listMessages(who.storage, withWhom.me.userId)).map((m) => `${m.direction}:${m.text}`);

async function waitFor(condition: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 300; i++) {
    if (condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`timed out waiting for ${what}`);
}

async function serverCount(table: "users" | "messages"): Promise<number> {
  return (await db.pool.query(`SELECT count(*)::int AS n FROM ${table}`)).rows[0].n;
}

describe("two people, end to end", () => {
  it("sign up, add each other, see the same safety number and talk both ways", async () => {
    const alice = await newBrowser();
    const bob = await newBrowser();
    expect(await serverCount("users")).toBe(2);
    await befriend(alice, bob);

    const bobAsSeenByAlice = (await getContact(alice.storage, bob.me.userId))!;
    const aliceAsSeenByBob = (await getContact(bob.storage, alice.me.userId))!;
    expect(computeSafetyNumber(alice.me, bobAsSeenByAlice)).toBe(computeSafetyNumber(bob.me, aliceAsSeenByBob));

    await say(alice, bob, "hello bob");
    await say(alice, bob, "are you there?");
    expect(await check(bob)).toMatchObject({ stored: 2, dropped: 0 });
    await say(bob, alice, "yes!");
    expect(await check(alice)).toMatchObject({ stored: 1, dropped: 0 });

    expect(await conversation(alice, bob)).toEqual(["out:hello bob", "out:are you there?", "in:yes!"]);
    expect(await conversation(bob, alice)).toEqual(["in:hello bob", "in:are you there?", "out:yes!"]);
    // Delivered and acknowledged: the server keeps nothing.
    expect(await serverCount("messages")).toBe(0);
  });

  it("stores only ciphertext on the server", async () => {
    const alice = await newBrowser();
    const bob = await newBrowser();
    await befriend(alice, bob);
    await say(alice, bob, "the launch code is 0000");

    const rows = await db.pool.query<{ ciphertext: Buffer }>("SELECT ciphertext FROM messages");
    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0]!.ciphertext.includes(Buffer.from("launch code"))).toBe(false);
  });

  it("nudges the recipient over the push connection the moment a message is sent", async () => {
    const alice = await newBrowser();
    const bob = await newBrowser();
    await befriend(alice, bob);

    let connected = 0;
    let nudges = 0;
    stops.push(
      connectPush({
        me: bob.me,
        baseUrl: `${server.url.replace(/^http/, "ws")}/api`,
        onConnected: () => (connected += 1),
        onNewMessage: () => (nudges += 1),
      }),
    );
    await waitFor(() => connected === 1, "the push connection");

    await say(alice, bob, "instant");
    await waitFor(() => nudges === 1, "the nudge");
    expect((await check(bob)).stored).toBe(1);
  });

  it("holds a message from a stranger until they are added as a contact", async () => {
    const alice = await newBrowser();
    const bob = await newBrowser();
    await addContact({ db: alice.storage, client, me: alice.me, userId: bob.me.userId });
    await say(alice, bob, "you don't know me yet");

    expect(await check(bob)).toMatchObject({ stored: 0, unknownSenders: [alice.me.userId] });
    expect(await serverCount("messages")).toBe(1);

    await addContact({ db: bob.storage, client, me: bob.me, userId: alice.me.userId });
    expect((await check(bob)).stored).toBe(1);
    expect(await conversation(bob, alice)).toEqual(["in:you don't know me yet"]);
  });
});

describe("a misbehaving server", () => {
  it("cannot replay a delivered message", async () => {
    const alice = await newBrowser();
    const bob = await newBrowser();
    await befriend(alice, bob);
    await say(alice, bob, "transfer 10");

    const copy = (await db.pool.query("SELECT from_user_id, to_user_id, nonce, ciphertext FROM messages")).rows[0];
    await check(bob);
    // The server puts the same ciphertext back in Bob's inbox.
    await db.pool.query(
      "INSERT INTO messages (from_user_id, to_user_id, nonce, ciphertext) VALUES ($1, $2, $3, $4)",
      [copy.from_user_id, copy.to_user_id, copy.nonce, copy.ciphertext],
    );

    expect(await check(bob)).toMatchObject({ stored: 0, dropped: 1 });
    expect(await conversation(bob, alice)).toEqual(["in:transfer 10"]);
  });

  it("cannot pass off one person's message as another's", async () => {
    const alice = await newBrowser();
    const bob = await newBrowser();
    const carol = await newBrowser();
    await befriend(alice, bob);
    await befriend(carol, bob);
    await say(alice, bob, "from alice");
    await db.pool.query("UPDATE messages SET from_user_id = $1", [carol.me.userId]);

    expect(await check(bob)).toMatchObject({ stored: 0, dropped: 1 });
    expect(await conversation(bob, carol)).toEqual([]);
    expect(await conversation(bob, alice)).toEqual([]);
  });

  it("cannot hand out its own encryption key for a new contact", async () => {
    const alice = await newBrowser();
    const bob = await newBrowser();
    const attackerKey = Buffer.from(crypto.generateExchangeKeyPair().publicKey);
    await db.pool.query("UPDATE users SET exchange_pubkey = $1 WHERE user_id = $2", [attackerKey, bob.me.userId]);

    const error = await addContact({ db: alice.storage, client, me: alice.me, userId: bob.me.userId }).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).code).toBe("invalid_response");
    expect(await getContact(alice.storage, bob.me.userId)).toBeNull();
  });

  it("cannot swap the key of an existing contact", async () => {
    const alice = await newBrowser();
    const bob = await newBrowser();
    await befriend(alice, bob);
    const attackerKey = Buffer.from(crypto.generateExchangeKeyPair().publicKey);
    await db.pool.query("UPDATE users SET exchange_pubkey = $1 WHERE user_id = $2", [attackerKey, bob.me.userId]);

    await expect(refreshContactKeys(alice.storage, client, alice.me, bob.me.userId)).rejects.toThrow();
    const pinned = (await getContact(alice.storage, bob.me.userId))!;
    expect(crypto.toHex(pinned.exchangePublicKey)).toBe(crypto.toHex(bob.me.exchangePublicKey));
    expect(canSendTo(pinned)).toBe(true);
  });
});

describe("signing up", () => {
  it("refuses a wrong invite code, keeps the keys, and succeeds on retry", async () => {
    const storage = await openDatabase(new IDBFactory());
    const error = await signUp({ db: storage, client, inviteCode: "not-the-invite-code-000000" }).catch(
      (e: unknown) => e,
    );
    expect((error as ApiError).code).toBe("invalid_invite");
    expect(await serverCount("users")).toBe(0);

    const pending = await loadSession(storage);
    expect(pending.status).toBe("unregistered");
    const session = await signUp({ db: storage, client, inviteCode: INVITE });
    expect(session.status).toBe("registered");
    expect(session.status === "registered" && pending.status === "unregistered" && session.identity.userId).toBe(
      pending.status === "unregistered" && pending.identity.userId,
    );
    expect(await serverCount("users")).toBe(1);
  });

  it("recovers the same identity after the server loses its accounts", async () => {
    const alice = await newBrowser();
    const bob = await newBrowser();
    await befriend(alice, bob);
    await db.pool.query("TRUNCATE invites, messages, auth_nonces, users");

    const refused = await check(alice).catch((e: unknown) => e);
    expect(isRejectedByServer(refused)).toBe(true);

    expect(await registerAgain({ db: alice.storage, client, inviteCode: INVITE })).toBe("registered");
    expect(await registerAgain({ db: bob.storage, client, inviteCode: INVITE })).toBe("registered");
    // Same keys as before, so the contacts they pinned for each other still work.
    await say(alice, bob, "still me");
    expect((await check(bob)).stored).toBe(1);
  });
});
