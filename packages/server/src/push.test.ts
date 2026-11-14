import * as crypto from "@messager/crypto";
import { encodeEnvelope } from "@messager/protocol";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { migrate } from "./db/migrate.js";
import { createTestDatabase, type TestDatabase } from "./db/test-db.js";
import { MAX_PUSH_CONNECTIONS_PER_USER } from "./push.js";
import { startServer, type RunningServer } from "./server.js";
import { insertUser, makeIdentity, signedFetch, signedWsUrl, type TestIdentity } from "./test-client.js";

let db: TestDatabase;
let server: RunningServer;
let alice: TestIdentity;
let bob: TestIdentity;
let sockets: WebSocket[];

beforeAll(async () => {
  await crypto.ready;
  db = await createTestDatabase();
  await migrate(db.pool);
});

afterAll(async () => {
  await db.drop();
});

beforeEach(async () => {
  await db.pool.query("TRUNCATE messages, auth_nonces, users");
  server = await startServer({
    pool: db.pool,
    inviteCode: "test-invite-code-0123456789",
    host: "127.0.0.1",
    port: 0,
  });
  alice = makeIdentity();
  bob = makeIdentity();
  await insertUser(db.pool, alice);
  await insertUser(db.pool, bob);
  sockets = [];
});

afterEach(async () => {
  for (const socket of sockets) socket.close();
  await server.close();
});

type Outcome = { opened: true; socket: WebSocket } | { opened: false };

/** Tries to open a push connection and reports whether the server accepted it. */
function connect(url: string): Promise<Outcome> {
  return new Promise((resolve) => {
    const socket = new WebSocket(url);
    sockets.push(socket);
    socket.addEventListener("open", () => resolve({ opened: true, socket }));
    socket.addEventListener("error", () => resolve({ opened: false }));
    socket.addEventListener("close", () => resolve({ opened: false }));
  });
}

async function open(who: TestIdentity): Promise<WebSocket> {
  const outcome = await connect(signedWsUrl(server.url, who));
  if (!outcome.opened) throw new Error("expected the push connection to open");
  return outcome.socket;
}

/** Collects every event a socket receives. */
function record(socket: WebSocket): string[] {
  const events: string[] = [];
  socket.addEventListener("message", (event) => events.push(String(event.data)));
  return events;
}

function closed(socket: WebSocket): Promise<number> {
  return new Promise((resolve) => socket.addEventListener("close", (event) => resolve(event.code)));
}

const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(condition: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 100; i++) {
    if (condition()) return;
    await pause(10);
  }
  throw new Error(`timed out waiting for ${what}`);
}

function send(from: TestIdentity, to: TestIdentity): Promise<Response> {
  return signedFetch(server.url, from, "/messages", {
    method: "POST",
    body: JSON.stringify(encodeEnvelope(to.userId, crypto.randomBytes(24), crypto.randomBytes(48))),
    timestamp: Date.now(),
  });
}

describe("push connection", () => {
  it("accepts a correctly signed connection", async () => {
    const socket = await open(bob);
    expect(socket.readyState).toBe(WebSocket.OPEN);
    expect(server.pushConnectionCount()).toBe(1);
  });

  it("tells the recipient when a message arrives for them", async () => {
    const events = record(await open(bob));
    expect((await send(alice, bob)).status).toBe(201);
    await waitFor(() => events.length === 1, "the new-message event");
    expect(JSON.parse(events[0]!)).toEqual({ type: "new_message" });
  });

  it("says only that something arrived: no sender, id or content", async () => {
    const events = record(await open(bob));
    await send(alice, bob);
    await waitFor(() => events.length === 1, "the new-message event");
    expect(events[0]).toBe('{"type":"new_message"}');
  });

  it("does not tell the sender or anyone else", async () => {
    const carol = makeIdentity();
    await insertUser(db.pool, carol);
    const aliceEvents = record(await open(alice));
    const carolEvents = record(await open(carol));
    const bobEvents = record(await open(bob));

    await send(alice, bob);
    await waitFor(() => bobEvents.length === 1, "bob's event");
    await pause(50);
    expect(aliceEvents).toEqual([]);
    expect(carolEvents).toEqual([]);
  });

  it("tells every open connection of the recipient", async () => {
    const first = record(await open(bob));
    const second = record(await open(bob));
    await send(alice, bob);
    await waitFor(() => first.length === 1 && second.length === 1, "both events");
  });

  it("does not notify when the send is rejected", async () => {
    const events = record(await open(bob));
    const res = await signedFetch(server.url, alice, "/messages", {
      method: "POST",
      body: JSON.stringify({ v: 1, to: bob.userId, nonce: "bad", ciphertext: "bad" }),
      timestamp: Date.now(),
    });
    expect(res.status).toBe(400);
    await pause(50);
    expect(events).toEqual([]);
  });

  it("still delivers by inbox when the recipient has no connection open", async () => {
    expect((await send(alice, bob)).status).toBe(201);
    const inbox = await signedFetch(server.url, bob, "/messages/inbox", { timestamp: Date.now() });
    expect(((await inbox.json()) as unknown[]).length).toBe(1);
  });

  it("forgets a connection once it closes", async () => {
    const socket = await open(bob);
    socket.close();
    await waitFor(() => server.pushConnectionCount() === 0, "the connection to be forgotten");
    expect((await send(alice, bob)).status).toBe(201);
  });

  it("closes a connection that sends anything, since clients only listen", async () => {
    const socket = await open(bob);
    const code = closed(socket);
    socket.send("hello");
    expect(await code).toBe(1008);
    await waitFor(() => server.pushConnectionCount() === 0, "the connection to be forgotten");
  });

  it("closes open connections when the server stops", async () => {
    const socket = await open(bob);
    const code = closed(socket);
    await server.close();
    await code;
    expect(socket.readyState).toBe(WebSocket.CLOSED);
    // afterEach closes the server again; make that a no-op.
    server = { ...server, close: async () => undefined };
  });
});

describe("push connection authentication", () => {
  async function expectRefused(url: string): Promise<void> {
    expect((await connect(url)).opened).toBe(false);
    expect(server.pushConnectionCount()).toBe(0);
  }

  it("refuses a connection with no signature", async () => {
    await expectRefused(`${server.url.replace(/^http/, "ws")}/ws`);
  });

  it.each([["user"], ["ts"], ["nonce"], ["sig"]])("refuses a connection missing %s", async (name) => {
    await expectRefused(signedWsUrl(server.url, bob, { params: { [name]: undefined } }));
  });

  it("refuses a signature made by a different key", async () => {
    const mallory = makeIdentity();
    await expectRefused(signedWsUrl(server.url, mallory, { params: { user: bob.userId } }));
  });

  it("refuses a user who is not registered", async () => {
    await expectRefused(signedWsUrl(server.url, makeIdentity()));
  });

  it("refuses a signature made for a different path", async () => {
    // A signed inbox request must not double as a push connection.
    await expectRefused(signedWsUrl(server.url, bob, { signPath: "/messages/inbox" }));
  });

  it("refuses a stale timestamp", async () => {
    await expectRefused(signedWsUrl(server.url, bob, { timestamp: Date.now() - 120_000 }));
  });

  it("refuses a timestamp from the future", async () => {
    await expectRefused(signedWsUrl(server.url, bob, { timestamp: Date.now() + 120_000 }));
  });

  it("refuses a connection URL that is used a second time", async () => {
    const url = signedWsUrl(server.url, bob);
    expect((await connect(url)).opened).toBe(true);
    expect((await connect(url)).opened).toBe(false);
    expect(server.pushConnectionCount()).toBe(1);
  });

  it("refuses malformed values without touching the database", async () => {
    await expectRefused(signedWsUrl(server.url, bob, { params: { ts: "now" } }));
    await expectRefused(signedWsUrl(server.url, bob, { params: { nonce: "short" } }));
    await expectRefused(signedWsUrl(server.url, bob, { params: { sig: "AAAA" } }));
    await expectRefused(signedWsUrl(server.url, bob, { params: { user: "not-an-id" } }));
    expect((await db.pool.query("SELECT count(*)::int AS n FROM auth_nonces")).rows[0].n).toBe(0);
  });

  it("does not store a nonce for a connection it refuses", async () => {
    const mallory = makeIdentity();
    await expectRefused(signedWsUrl(server.url, mallory, { params: { user: bob.userId } }));
    expect((await db.pool.query("SELECT count(*)::int AS n FROM auth_nonces")).rows[0].n).toBe(0);
  });

  it("refuses a WebSocket on any other path", async () => {
    await expectRefused(signedWsUrl(server.url, bob, { path: "/messages/inbox", signPath: "/messages/inbox" }));
    await expectRefused(signedWsUrl(server.url, bob, { path: "/ws/extra" }));
  });

  it("limits how many connections one user can hold open", async () => {
    for (let i = 0; i < MAX_PUSH_CONNECTIONS_PER_USER; i++) {
      await open(bob);
    }
    expect((await connect(signedWsUrl(server.url, bob))).opened).toBe(false);
    expect(server.pushConnectionCount()).toBe(MAX_PUSH_CONNECTIONS_PER_USER);
    // Another user is unaffected.
    await open(alice);
  });

  it("leaves ordinary requests working", async () => {
    await open(bob);
    expect((await fetch(server.url + "/health")).status).toBe(200);
  });
});
