import * as crypto from "@messager/crypto";
import { decryptMessage, encryptMessage, type Envelope } from "@messager/protocol";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "./app.js";
import { migrate } from "./db/migrate.js";
import { createTestDatabase, type TestDatabase } from "./db/test-db.js";
import { makeIdentity, signedFetch, type TestIdentity } from "./test-client.js";
import { startTestServer, type TestServer } from "./test-http.js";

const INVITE_CODE = "test-invite-code-0123456789";

let db: TestDatabase;
let server: TestServer;

beforeAll(async () => {
  await crypto.ready;
  db = await createTestDatabase();
  await migrate(db.pool);
  // Real clock: this test goes through every route the way a client would.
  server = await startTestServer(createApp({ pool: db.pool, inviteCode: INVITE_CODE }));
});

afterAll(async () => {
  await server.close();
  await db.drop();
});

function call(who: TestIdentity, method: string, path: string, body?: unknown): Promise<Response> {
  return signedFetch(server.url, who, path, {
    method,
    body: body === undefined ? undefined : JSON.stringify(body),
    timestamp: Date.now(),
  });
}

async function register(who: TestIdentity): Promise<void> {
  const res = await call(who, "POST", "/register", {
    userID: who.userId,
    identity_pubkey: crypto.toBase64(who.identity.publicKey),
    exchange_pubkey: crypto.toBase64(who.exchange.publicKey),
    exchange_sig: crypto.toBase64(who.exchangeSig),
    inviteCode: INVITE_CODE,
  });
  expect(res.status).toBe(201);
}

/** Looks up a contact by userID only, as a client that was given just the ID would. */
async function fetchExchangeKey(who: TestIdentity, contactId: string): Promise<Uint8Array> {
  const res = await call(who, "GET", `/users/${contactId}/pubkeys`);
  expect(res.status).toBe(200);
  const keys = (await res.json()) as { exchange_pubkey: string };
  return crypto.fromBase64(keys.exchange_pubkey);
}

describe("two clients through a real server", () => {
  it("register, exchange a message both ways, and leave nothing behind after ack", async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    await register(alice);
    await register(bob);

    const bobKeyAsSeenByAlice = await fetchExchangeKey(alice, bob.userId);
    const aliceKeyAsSeenByBob = await fetchExchangeKey(bob, alice.userId);

    // Alice -> Bob
    const hello = { counter: 1, text: "hello bob", sentAt: Date.now() };
    const sent = await call(
      alice,
      "POST",
      "/messages",
      encryptMessage({
        message: hello,
        fromUserId: alice.userId,
        toUserId: bob.userId,
        myExchangePrivateKey: alice.exchange.privateKey,
        theirExchangePublicKey: bobKeyAsSeenByAlice,
      }),
    );
    expect(sent.status).toBe(201);

    const bobInbox = (await (await call(bob, "GET", "/messages/inbox")).json()) as {
      message_id: string;
      from: string;
      nonce: string;
      ciphertext: string;
    }[];
    expect(bobInbox).toHaveLength(1);
    const item = bobInbox[0]!;
    expect(item.from).toBe(alice.userId);

    const received: Envelope = { v: 1, to: bob.userId, nonce: item.nonce, ciphertext: item.ciphertext };
    expect(
      decryptMessage({
        envelope: received,
        fromUserId: item.from,
        toUserId: bob.userId,
        myExchangePrivateKey: bob.exchange.privateKey,
        theirExchangePublicKey: aliceKeyAsSeenByBob,
      }),
    ).toEqual(hello);

    // The server stored only ciphertext: the plaintext appears nowhere in the row.
    const stored = await db.pool.query<{ ciphertext: Buffer }>("SELECT ciphertext FROM messages");
    expect(stored.rows[0]!.ciphertext.includes(Buffer.from("hello bob"))).toBe(false);

    expect((await call(bob, "POST", `/messages/${item.message_id}/ack`)).status).toBe(204);
    expect(await (await call(bob, "GET", "/messages/inbox")).json()).toEqual([]);

    // Bob -> Alice
    const reply = { counter: 1, text: "hi alice", sentAt: Date.now() };
    const replied = await call(
      bob,
      "POST",
      "/messages",
      encryptMessage({
        message: reply,
        fromUserId: bob.userId,
        toUserId: alice.userId,
        myExchangePrivateKey: bob.exchange.privateKey,
        theirExchangePublicKey: aliceKeyAsSeenByBob,
      }),
    );
    expect(replied.status).toBe(201);

    const aliceInbox = (await (await call(alice, "GET", "/messages/inbox")).json()) as typeof bobInbox;
    expect(aliceInbox).toHaveLength(1);
    const back = aliceInbox[0]!;
    expect(
      decryptMessage({
        envelope: { v: 1, to: alice.userId, nonce: back.nonce, ciphertext: back.ciphertext },
        fromUserId: back.from,
        toUserId: alice.userId,
        myExchangePrivateKey: alice.exchange.privateKey,
        theirExchangePublicKey: bobKeyAsSeenByAlice,
      }),
    ).toEqual(reply);
    expect((await call(alice, "POST", `/messages/${back.message_id}/ack`)).status).toBe(204);

    const left = await db.pool.query("SELECT count(*)::int AS n FROM messages");
    expect(left.rows[0].n).toBe(0);
  });

  it("a message re-routed by the server to a different recipient does not decrypt", async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const carol = makeIdentity();
    await register(alice);
    await register(bob);
    await register(carol);

    await call(
      alice,
      "POST",
      "/messages",
      encryptMessage({
        message: { counter: 1, text: "for bob only", sentAt: Date.now() },
        fromUserId: alice.userId,
        toUserId: bob.userId,
        myExchangePrivateKey: alice.exchange.privateKey,
        theirExchangePublicKey: bob.exchange.publicKey,
      }),
    );
    // Simulate a malicious server moving the row into Carol's inbox.
    await db.pool.query("UPDATE messages SET to_user_id = $1 WHERE to_user_id = $2", [carol.userId, bob.userId]);

    const carolInbox = (await (await call(carol, "GET", "/messages/inbox")).json()) as {
      from: string;
      nonce: string;
      ciphertext: string;
    }[];
    expect(carolInbox).toHaveLength(1);
    const moved = carolInbox[0]!;
    expect(() =>
      decryptMessage({
        envelope: { v: 1, to: carol.userId, nonce: moved.nonce, ciphertext: moved.ciphertext },
        fromUserId: moved.from,
        toUserId: carol.userId,
        myExchangePrivateKey: carol.exchange.privateKey,
        theirExchangePublicKey: alice.exchange.publicKey,
      }),
    ).toThrow();
  });
});
