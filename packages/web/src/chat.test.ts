import * as crypto from "@messager/crypto";
import { encryptMessage, type Envelope } from "@messager/protocol";
import { IDBFactory } from "fake-indexeddb";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ApiError, type ApiClient, type InboxItem } from "./api/client.js";
import { MAX_TEXT_BYTES, receiveMessages, sendChatMessage } from "./chat.js";
import { acceptChangedKey, addContact, recordFetchedKeys } from "./contacts.js";
import { createIdentity, type StoredIdentity } from "./identity.js";
import { openDatabase } from "./storage/db.js";
import { listMessages } from "./storage/message-store.js";

const NOW = 1_800_000_000_000;

/** A stand-in for the server: holds each user's waiting messages, exactly as the real one does. */
class FakeServer {
  users = new Map<string, StoredIdentity>();
  inboxes = new Map<string, InboxItem[]>();
  acked: string[] = [];
  failSend = false;
  failAck = false;
  private nextId = 1;

  register(who: StoredIdentity): void {
    this.users.set(who.userId, who);
    this.inboxes.set(who.userId, []);
  }

  /** Puts an envelope in the recipient's inbox as if `from` had sent it. */
  deliver(from: string, envelope: Envelope): string {
    const messageId = `00000000-0000-4000-8000-${String(this.nextId++).padStart(12, "0")}`;
    this.inboxes.get(envelope.to)!.push({
      messageId,
      from,
      nonce: envelope.nonce,
      ciphertext: envelope.ciphertext,
      createdAt: new Date(NOW).toISOString(),
    });
    return messageId;
  }

  client(): ApiClient {
    return {
      request: async () => undefined,
      register: async () => undefined,
      getPubkeys: async (_me, userId) => {
        const user = this.users.get(userId);
        if (user === undefined) throw new ApiError(404, "not_found");
        return {
          userId,
          identityPublicKey: user.identityPublicKey,
          exchangePublicKey: user.exchangePublicKey,
        };
      },
      sendMessage: async (me, envelope) => {
        if (this.failSend) throw new ApiError(0, "network_error");
        return { messageId: this.deliver(me.userId, envelope) };
      },
      fetchInbox: async (me) => [...this.inboxes.get(me.userId)!],
      ackMessage: async (me, messageId) => {
        if (this.failAck) throw new ApiError(0, "network_error");
        this.acked.push(messageId);
        const inbox = this.inboxes.get(me.userId)!;
        this.inboxes.set(
          me.userId,
          inbox.filter((item) => item.messageId !== messageId),
        );
      },
    };
  }
}

let server: FakeServer;
let client: ApiClient;
let alice: StoredIdentity;
let bob: StoredIdentity;
let aliceDb: IDBDatabase;
let bobDb: IDBDatabase;

beforeAll(async () => {
  await crypto.ready;
});

beforeEach(async () => {
  server = new FakeServer();
  client = server.client();
  alice = createIdentity(NOW);
  bob = createIdentity(NOW);
  server.register(alice);
  server.register(bob);
  aliceDb = await openDatabase(new IDBFactory());
  bobDb = await openDatabase(new IDBFactory());
  await addContact({ db: aliceDb, client, me: alice, userId: bob.userId, name: "Bob" });
  await addContact({ db: bobDb, client, me: bob, userId: alice.userId, name: "Alice" });
});

const aliceSends = (text: string) =>
  sendChatMessage({ db: aliceDb, client, me: alice, contactId: bob.userId, text, now: () => NOW });
const bobReceives = () => receiveMessages({ db: bobDb, client, me: bob });
const bobHistory = async () => (await listMessages(bobDb, alice.userId)).map((m) => m.text);
const bobInbox = () => server.inboxes.get(bob.userId)!;

/** An envelope encrypted by Alice for Bob with a chosen counter, bypassing her local counter. */
function forgedFromAlice(counter: number, text: string, overrides: Partial<{ key: Uint8Array }> = {}): Envelope {
  return encryptMessage({
    message: { counter, text, sentAt: NOW },
    fromUserId: alice.userId,
    toUserId: bob.userId,
    myExchangePrivateKey: alice.exchangePrivateKey,
    theirExchangePublicKey: overrides.key ?? bob.exchangePublicKey,
  });
}

describe("sending", () => {
  it("delivers a message the recipient can read, and keeps a copy in the sender's history", async () => {
    const sent = await aliceSends("hello bob");
    expect(sent).toMatchObject({ direction: "out", text: "hello bob", counter: 1, sentAt: NOW });
    expect((await listMessages(aliceDb, bob.userId)).map((m) => m.text)).toEqual(["hello bob"]);

    expect(await bobReceives()).toEqual({ stored: 1, dropped: 0, unknownSenders: [], heldForKeyChange: 0 });
    const received = await listMessages(bobDb, alice.userId);
    expect(received).toHaveLength(1);
    expect(received[0]).toMatchObject({ direction: "in", text: "hello bob", counter: 1, sentAt: NOW });
  });

  it("never puts the readable text on the server", async () => {
    await aliceSends("a very secret plan");
    const waiting = JSON.stringify(bobInbox());
    expect(waiting).not.toContain("secret");
    // Not hidden inside the ciphertext bytes either.
    const bytes = crypto.fromBase64(bobInbox()[0]!.ciphertext);
    expect(crypto.toHex(bytes)).not.toContain(crypto.toHex(crypto.utf8Encode("secret")));
  });

  it("uses a higher counter for every message", async () => {
    const counters = [await aliceSends("one"), await aliceSends("two"), await aliceSends("three")].map(
      (m) => m.counter,
    );
    expect(counters).toEqual([1, 2, 3]);
  });

  it("does not reuse a counter after a failed send, and stores nothing for the failure", async () => {
    server.failSend = true;
    await expect(aliceSends("lost")).rejects.toThrow();
    server.failSend = false;
    const next = await aliceSends("arrives");
    expect(next.counter).toBe(2);
    expect((await listMessages(aliceDb, bob.userId)).map((m) => m.text)).toEqual(["arrives"]);
  });

  it("keeps separate counters per contact", async () => {
    const carol = createIdentity(NOW);
    server.register(carol);
    await addContact({ db: aliceDb, client, me: alice, userId: carol.userId });
    await aliceSends("to bob");
    const toCarol = await sendChatMessage({ db: aliceDb, client, me: alice, contactId: carol.userId, text: "hi" });
    expect(toCarol.counter).toBe(1);
  });

  it.each([[""], ["   \n"]])("refuses the empty message %j", async (text) => {
    await expect(aliceSends(text)).rejects.toThrow(/Type a message/);
    expect(bobInbox()).toHaveLength(0);
  });

  it("refuses a message that is too long, counting bytes not characters", async () => {
    await expect(aliceSends("é".repeat(MAX_TEXT_BYTES / 2 + 1))).rejects.toThrow(/too long/);
    await aliceSends("é".repeat(MAX_TEXT_BYTES / 2));
    expect(bobInbox()).toHaveLength(1);
  });

  it("refuses to send to someone who is not a contact", async () => {
    const stranger = createIdentity(NOW);
    await expect(
      sendChatMessage({ db: aliceDb, client, me: alice, contactId: stranger.userId, text: "hi" }),
    ).rejects.toThrow(/No such contact/);
  });

  it("refuses to send while the contact's key change is unresolved", async () => {
    await recordFetchedKeys(aliceDb, bob.userId, {
      userId: bob.userId,
      identityPublicKey: bob.identityPublicKey,
      exchangePublicKey: createIdentity(NOW).exchangePublicKey,
    });
    await expect(aliceSends("hello")).rejects.toThrow(/blocked/);
    expect(bobInbox()).toHaveLength(0);
  });

  it("keeps punctuation, emoji and markup exactly as typed", async () => {
    const text = `<script>alert("x")</script> 👋 line1\nline2 "quotes" \\ back`;
    await aliceSends(text);
    await bobReceives();
    expect(await bobHistory()).toEqual([text]);
  });
});

describe("receiving", () => {
  it("acknowledges stored messages so the server deletes them", async () => {
    await aliceSends("one");
    await aliceSends("two");
    await bobReceives();
    expect(bobInbox()).toHaveLength(0);
    expect(server.acked).toHaveLength(2);
    expect(await bobHistory()).toEqual(["one", "two"]);
  });

  it("does nothing when the inbox is empty", async () => {
    expect(await bobReceives()).toEqual({ stored: 0, dropped: 0, unknownSenders: [], heldForKeyChange: 0 });
  });

  it("does not show a message twice when the acknowledgement was lost", async () => {
    await aliceSends("only once");
    server.failAck = true;
    expect((await bobReceives()).stored).toBe(1);
    expect(bobInbox()).toHaveLength(1);

    server.failAck = false;
    expect(await bobReceives()).toMatchObject({ stored: 0, dropped: 1 });
    expect(await bobHistory()).toEqual(["only once"]);
    expect(bobInbox()).toHaveLength(0);
  });

  it("rejects a message replayed by the server", async () => {
    await aliceSends("pay 10");
    const original = { ...bobInbox()[0]! };
    await bobReceives();

    // The server puts the very same ciphertext back, under a new id.
    bobInbox().push({ ...original, messageId: "00000000-0000-4000-8000-999999999999" });
    expect(await bobReceives()).toMatchObject({ stored: 0, dropped: 1 });
    expect(await bobHistory()).toEqual(["pay 10"]);
  });

  it("rejects an older message delivered after a newer one", async () => {
    server.deliver(alice.userId, forgedFromAlice(5, "newer"));
    await bobReceives();
    server.deliver(alice.userId, forgedFromAlice(3, "older, held back by the server"));
    expect(await bobReceives()).toMatchObject({ stored: 0, dropped: 1 });
    expect(await bobHistory()).toEqual(["newer"]);
  });

  it("accepts counters with gaps", async () => {
    server.deliver(alice.userId, forgedFromAlice(2, "two"));
    server.deliver(alice.userId, forgedFromAlice(7, "seven"));
    expect((await bobReceives()).stored).toBe(2);
  });

  it("drops a message whose ciphertext was altered", async () => {
    await aliceSends("hello");
    const item = bobInbox()[0]!;
    const bytes = crypto.fromBase64(item.ciphertext);
    bytes[0]! ^= 1;
    item.ciphertext = crypto.toBase64(bytes);

    expect(await bobReceives()).toMatchObject({ stored: 0, dropped: 1 });
    expect(await bobHistory()).toEqual([]);
    expect(bobInbox()).toHaveLength(0);
  });

  it("drops a message the server attributes to the wrong contact", async () => {
    const carol = createIdentity(NOW);
    server.register(carol);
    await addContact({ db: bobDb, client, me: bob, userId: carol.userId, name: "Carol" });
    // Really from Alice, but the server claims Carol sent it.
    server.deliver(carol.userId, forgedFromAlice(1, "I am Carol, honest"));

    expect(await bobReceives()).toMatchObject({ stored: 0, dropped: 1 });
    expect(await listMessages(bobDb, carol.userId)).toEqual([]);
  });

  it("drops a message that was encrypted for somebody else", async () => {
    const carol = createIdentity(NOW);
    server.deliver(alice.userId, { ...forgedFromAlice(1, "for carol", { key: carol.exchangePublicKey }) });
    expect(await bobReceives()).toMatchObject({ stored: 0, dropped: 1 });
  });

  it.each([
    ["a counter of zero", 0],
    ["a negative counter", -4],
    ["a fractional counter", 1.5],
    ["a counter too large to count safely", 2 ** 60],
  ])("drops a message with %s", async (_name, counter) => {
    server.deliver(alice.userId, forgedFromAlice(counter, "bad counter"));
    expect(await bobReceives()).toMatchObject({ stored: 0, dropped: 1 });
    // A bad counter must not poison the real sequence.
    server.deliver(alice.userId, forgedFromAlice(1, "fine"));
    expect((await bobReceives()).stored).toBe(1);
  });

  it("leaves messages from unknown senders on the server and reports who they are from", async () => {
    const stranger = createIdentity(NOW);
    server.register(stranger);
    await sendChatMessage({
      db: await (async () => {
        const db = await openDatabase(new IDBFactory());
        await addContact({ db, client, me: stranger, userId: bob.userId });
        return db;
      })(),
      client,
      me: stranger,
      contactId: bob.userId,
      text: "hello from a stranger",
    });

    expect(await bobReceives()).toEqual({
      stored: 0,
      dropped: 0,
      unknownSenders: [stranger.userId],
      heldForKeyChange: 0,
    });
    expect(bobInbox()).toHaveLength(1);

    // Once Bob adds them, the waiting message arrives.
    await addContact({ db: bobDb, client, me: bob, userId: stranger.userId });
    expect((await bobReceives()).stored).toBe(1);
    expect((await listMessages(bobDb, stranger.userId)).map((m) => m.text)).toEqual(["hello from a stranger"]);
  });

  it("holds an undecryptable message while a key change is unresolved, then reads it once accepted", async () => {
    const newKeys = crypto.generateExchangeKeyPair();
    // Alice now encrypts with her new key; Bob still has the old one pinned.
    server.deliver(
      alice.userId,
      encryptMessage({
        message: { counter: 1, text: "sent with my new key", sentAt: NOW },
        fromUserId: alice.userId,
        toUserId: bob.userId,
        myExchangePrivateKey: newKeys.privateKey,
        theirExchangePublicKey: bob.exchangePublicKey,
      }),
    );
    await recordFetchedKeys(bobDb, alice.userId, {
      userId: alice.userId,
      identityPublicKey: alice.identityPublicKey,
      exchangePublicKey: newKeys.publicKey,
    });

    expect(await bobReceives()).toMatchObject({ stored: 0, dropped: 0, heldForKeyChange: 1 });
    expect(bobInbox()).toHaveLength(1);

    await acceptChangedKey(bobDb, alice.userId);
    expect((await bobReceives()).stored).toBe(1);
    expect(await bobHistory()).toEqual(["sent with my new key"]);
  });

  it("keeps the two directions of a conversation in order", async () => {
    await aliceSends("hi bob");
    await bobReceives();
    await sendChatMessage({ db: bobDb, client, me: bob, contactId: alice.userId, text: "hi alice", now: () => NOW });
    await receiveMessages({ db: aliceDb, client, me: alice });

    expect((await listMessages(bobDb, alice.userId)).map((m) => [m.direction, m.text])).toEqual([
      ["in", "hi bob"],
      ["out", "hi alice"],
    ]);
    expect((await listMessages(aliceDb, bob.userId)).map((m) => [m.direction, m.text])).toEqual([
      ["out", "hi bob"],
      ["in", "hi alice"],
    ]);
  });

  it("does not store a message twice when two tabs receive at the same moment", async () => {
    await aliceSends("once");
    const [a, b] = await Promise.all([bobReceives(), bobReceives()]);
    expect(a.stored + b.stored).toBe(1);
    expect(await bobHistory()).toEqual(["once"]);
  });
});
