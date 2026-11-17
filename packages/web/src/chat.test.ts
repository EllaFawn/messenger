import * as crypto from "@messager/crypto";
import { encodeEnvelope, encodeMessagePlaintext } from "@messager/protocol";
import { MESSAGE_TYPE_NORMAL, MESSAGE_TYPE_PREKEY, preKeyMessageSessionId, RatchetSession } from "@messager/ratchet";
import { IDBFactory } from "fake-indexeddb";
import { beforeEach, describe, expect, it } from "vitest";
import type { ApiClient } from "./api/client.js";
import { MAX_TEXT_BYTES, receiveMessages, sendChatMessage } from "./chat.js";
import { acceptChangedKey, addContact, recordFetchedKeys, refreshContactKeys } from "./contacts.js";
import { createRatchetAccount } from "./identity.js";
import { getContact } from "./storage/contact-store.js";
import { openDatabase } from "./storage/db.js";
import { saveNewIdentity } from "./storage/identity-store.js";
import { listMessages } from "./storage/message-store.js";
import { listSessions, saveSession } from "./storage/ratchet-store.js";
import { FakeServer, newBrowser, NOW, type Browser } from "./test-fake-server.js";

let server: FakeServer;
let client: ApiClient;
let alice: Browser;
let bob: Browser;

beforeEach(async () => {
  server = new FakeServer();
  client = server.client();
  alice = await newBrowser(server);
  bob = await newBrowser(server);
  await befriend(alice, bob);
});

async function befriend(a: Browser, b: Browser): Promise<void> {
  await addContact({ db: a.db, client, me: a.me, userId: b.me.userId, name: "B" });
  await addContact({ db: b.db, client, me: b.me, userId: a.me.userId, name: "A" });
}

const send = (from: Browser, to: Browser, text: string) =>
  sendChatMessage({ db: from.db, client, me: from.me, contactId: to.me.userId, text, now: () => NOW });
const receive = (who: Browser) => receiveMessages({ db: who.db, client, me: who.me });
const history = async (who: Browser, withWhom: Browser) =>
  (await listMessages(who.db, withWhom.me.userId)).map((m) => `${m.direction}:${m.text}`);
const inbox = (who: Browser) => server.inboxes.get(who.me.userId)!;
const keysLeft = (who: Browser) => server.oneTimeKeys.get(who.me.userId)!.length;

/** Encrypts arbitrary bytes on Alice's current session with Bob, as her app would but without its checks. */
async function aliceEncryptsRaw(plaintext: Uint8Array) {
  const [record] = await listSessions(alice.db, bob.me.userId);
  const session = RatchetSession.restore(record!.pickle, alice.me.pickleKey);
  const encrypted = session.encrypt(plaintext);
  await saveSession(alice.db, { ...record!, pickle: session.save(alice.me.pickleKey) });
  return encodeEnvelope(bob.me.userId, encrypted);
}

describe("sending", () => {
  it("delivers a message the recipient can read, and keeps a copy in the sender's history", async () => {
    const sent = await send(alice, bob, "hello bob");
    expect(sent).toMatchObject({ direction: "out", text: "hello bob", sentAt: NOW });
    expect(await history(alice, bob)).toEqual(["out:hello bob"]);

    expect(await receive(bob)).toEqual({ stored: 1, dropped: 0, unknownSenders: [], heldForKeyChange: 0 });
    const received = await listMessages(bob.db, alice.me.userId);
    expect(received).toHaveLength(1);
    expect(received[0]).toMatchObject({ direction: "in", text: "hello bob", sentAt: NOW });
  });

  it("claims one of the recipient's one-time keys for the first message only", async () => {
    expect(keysLeft(bob)).toBe(50);
    await send(alice, bob, "one");
    await send(alice, bob, "two");
    expect(server.claims).toBe(1);
    expect(keysLeft(bob)).toBe(49);
    expect(await listSessions(alice.db, bob.me.userId)).toHaveLength(1);
  });

  it("sends pre-key messages until the other side replies, then normal ones", async () => {
    await send(alice, bob, "one");
    await send(alice, bob, "two");
    expect(inbox(bob).map((item) => item.type)).toEqual([MESSAGE_TYPE_PREKEY, MESSAGE_TYPE_PREKEY]);
    // Both belong to the same session.
    const ids = inbox(bob).map((item) => preKeyMessageSessionId(crypto.fromBase64(item.ciphertext)));
    expect(ids[0]).toBe(ids[1]);

    await receive(bob);
    await send(bob, alice, "got them");
    expect(inbox(alice)[0]!.type).toBe(MESSAGE_TYPE_NORMAL);
    await receive(alice);
    await send(alice, bob, "three");
    expect(inbox(bob)[0]!.type).toBe(MESSAGE_TYPE_NORMAL);
    expect((await receive(bob)).stored).toBe(1);
    expect(await history(bob, alice)).toEqual(["in:one", "in:two", "out:got them", "in:three"]);
  });

  it("encrypts every message differently, even the same text", async () => {
    await send(alice, bob, "same");
    await send(alice, bob, "same");
    expect(inbox(bob)[0]!.ciphertext).not.toBe(inbox(bob)[1]!.ciphertext);
  });

  it("never puts the readable text on the server", async () => {
    await send(alice, bob, "a very secret plan");
    const waiting = JSON.stringify(inbox(bob));
    expect(waiting).not.toContain("secret");
    // Not hidden inside the ciphertext bytes either.
    const bytes = crypto.fromBase64(inbox(bob)[0]!.ciphertext);
    expect(crypto.toHex(bytes)).not.toContain(crypto.toHex(crypto.utf8Encode("secret")));
  });

  it("stores nothing for a failed send, and the next message still gets through", async () => {
    server.failSend = true;
    await expect(send(alice, bob, "lost")).rejects.toThrow();
    expect(await history(alice, bob)).toEqual([]);

    server.failSend = false;
    await send(alice, bob, "next");
    expect(await receive(bob)).toMatchObject({ stored: 1, dropped: 0 });
    expect(await history(bob, alice)).toEqual(["in:next"]);
  });

  it("uses the fallback key once the one-time keys have run out", async () => {
    server.oneTimeKeys.set(bob.me.userId, []);
    await send(alice, bob, "via the fallback");
    expect(await receive(bob)).toMatchObject({ stored: 1 });
  });

  it("explains when the recipient has published no keys at all", async () => {
    server.oneTimeKeys.set(bob.me.userId, []);
    server.fallbacks.delete(bob.me.userId);
    await expect(send(alice, bob, "hello")).rejects.toMatchObject({ code: "no_one_time_keys" });
    expect(await history(alice, bob)).toEqual([]);
  });

  it("refuses to start a session on a ratchet key other than the pinned one, and records the change", async () => {
    // The server now vouches for a different key (validly signed, as far as the fake is concerned).
    const swapped = createRatchetAccount().ratchetPublicKey;
    server.users.set(bob.me.userId, { ...bob.me, ratchetPublicKey: swapped });

    await expect(send(alice, bob, "hello")).rejects.toThrow(/key has changed/);
    expect(inbox(bob)).toHaveLength(0);
    const contact = (await getContact(alice.db, bob.me.userId))!;
    expect(crypto.toHex(contact.changedRatchetPublicKey!)).toBe(crypto.toHex(swapped));
    expect(crypto.toHex(contact.ratchetPublicKey)).toBe(crypto.toHex(bob.me.ratchetPublicKey));
  });

  it.each([[""], ["   \n"]])("refuses the empty message %j", async (text) => {
    await expect(send(alice, bob, text)).rejects.toThrow(/type a message/i);
    expect(inbox(bob)).toHaveLength(0);
  });

  it("refuses a message that is too long, counting bytes not characters", async () => {
    await expect(send(alice, bob, "é".repeat(MAX_TEXT_BYTES / 2 + 1))).rejects.toThrow(/too long/);
    await send(alice, bob, "é".repeat(MAX_TEXT_BYTES / 2));
    expect((await receive(bob)).stored).toBe(1);
  });

  it("refuses to send to someone who is not a contact", async () => {
    const carol = await newBrowser(server);
    await expect(send(alice, carol, "hi")).rejects.toThrow(/no such contact/i);
    expect(server.claims).toBe(0);
  });

  it("refuses to send while the contact's key change is unresolved", async () => {
    await recordFetchedKeys(alice.db, bob.me.userId, {
      userId: bob.me.userId,
      identityPublicKey: bob.me.identityPublicKey,
      ratchetPublicKey: createRatchetAccount().ratchetPublicKey,
      keyEpoch: 2,
    });
    await expect(send(alice, bob, "hi")).rejects.toThrow(/blocked/);
    expect(inbox(bob)).toHaveLength(0);
  });

  it("keeps punctuation, emoji and markup exactly as typed", async () => {
    const text = `<b>"quotes"</b> & 'apostrophes' — 🙂 \n new line \u0000`;
    await send(alice, bob, text);
    await receive(bob);
    expect((await listMessages(bob.db, alice.me.userId))[0]!.text).toBe(text);
  });

  it("starts only one session when two tabs send the first message at once", async () => {
    await Promise.all([send(alice, bob, "tab one"), send(alice, bob, "tab two")]);
    expect(server.claims).toBe(1);
    expect(await listSessions(alice.db, bob.me.userId)).toHaveLength(1);
    expect((await receive(bob)).stored).toBe(2);
  });
});

describe("receiving", () => {
  it("acknowledges stored messages so the server deletes them", async () => {
    await send(alice, bob, "one");
    await send(alice, bob, "two");
    await receive(bob);
    expect(server.acked).toHaveLength(2);
    expect(inbox(bob)).toEqual([]);
  });

  it("does nothing when the inbox is empty", async () => {
    expect(await receive(bob)).toEqual({ stored: 0, dropped: 0, unknownSenders: [], heldForKeyChange: 0 });
  });

  it("does not show a message twice when the acknowledgement was lost", async () => {
    await send(alice, bob, "once");
    server.failAck = true;
    expect((await receive(bob)).stored).toBe(1);
    expect(inbox(bob)).toHaveLength(1);

    server.failAck = false;
    // Its key is gone, so the repeat no longer decrypts and is dropped.
    expect(await receive(bob)).toMatchObject({ stored: 0, dropped: 1 });
    expect(await history(bob, alice)).toEqual(["in:once"]);
    expect(inbox(bob)).toEqual([]);
  });

  it("rejects a message replayed by the server", async () => {
    await send(alice, bob, "transfer 10");
    const copy = { ...inbox(bob)[0]! };
    await receive(bob);
    server.deliver(alice.me.userId, { v: 2, to: bob.me.userId, type: copy.type, ciphertext: copy.ciphertext });
    expect(await receive(bob)).toMatchObject({ stored: 0, dropped: 1 });
    expect(await history(bob, alice)).toEqual(["in:transfer 10"]);
  });

  it("reads repeated pre-key messages on the one session they belong to", async () => {
    for (const text of ["one", "two", "three"]) await send(alice, bob, text);
    expect((await receive(bob)).stored).toBe(3);
    expect(await listSessions(bob.db, alice.me.userId)).toHaveLength(1);
  });

  it("reads messages that arrive out of order", async () => {
    await send(alice, bob, "start");
    await receive(bob);
    await send(bob, alice, "ok");
    await receive(alice);
    await send(alice, bob, "first");
    await send(alice, bob, "second");
    inbox(bob).reverse();
    expect((await receive(bob)).stored).toBe(2);
    expect(await history(bob, alice)).toEqual(["in:start", "out:ok", "in:second", "in:first"]);
  });

  it("drops a message whose ciphertext was altered, and still reads the next one", async () => {
    await send(alice, bob, "original");
    const item = inbox(bob)[0]!;
    const bytes = crypto.fromBase64(item.ciphertext);
    bytes[bytes.length - 1]! ^= 1;
    item.ciphertext = crypto.toBase64(bytes);

    expect(await receive(bob)).toMatchObject({ stored: 0, dropped: 1 });
    await send(alice, bob, "next");
    expect((await receive(bob)).stored).toBe(1);
    expect(await history(bob, alice)).toEqual(["in:next"]);
  });

  it("drops a message the server attributes to the wrong contact", async () => {
    const carol = await newBrowser(server);
    await befriend(carol, bob);
    await send(alice, bob, "from alice");
    inbox(bob)[0]!.from = carol.me.userId;

    expect(await receive(bob)).toMatchObject({ stored: 0, dropped: 1 });
    expect(await history(bob, carol)).toEqual([]);
    expect(await history(bob, alice)).toEqual([]);
  });

  it("drops a message that was encrypted for somebody else", async () => {
    const carol = await newBrowser(server);
    await befriend(alice, carol);
    await befriend(carol, bob);
    await send(alice, carol, "for carol");
    // The server moves it into Bob's inbox.
    const moved = server.inboxes.get(carol.me.userId)!.pop()!;
    inbox(bob).push(moved);
    expect(await receive(bob)).toMatchObject({ stored: 0, dropped: 1 });
  });

  it.each([
    ["is not JSON", () => crypto.utf8Encode("not json")],
    ["has no text", () => crypto.utf8Encode(JSON.stringify({ sentAt: NOW }))],
    ["is too long", () => encodeMessagePlaintext({ text: "x".repeat(MAX_TEXT_BYTES + 1), sentAt: NOW })],
  ])("drops a message whose decrypted content %s, but stays in step with the sender", async (_name, content) => {
    await send(alice, bob, "hello");
    inbox(bob).length = 0;
    server.deliver(alice.me.userId, await aliceEncryptsRaw(content()));
    expect(await receive(bob)).toMatchObject({ stored: 0, dropped: 1 });

    await send(alice, bob, "after");
    expect((await receive(bob)).stored).toBe(1);
    expect(await history(bob, alice)).toEqual(["in:after"]);
  });

  it("leaves messages from unknown senders on the server and reports who they are from", async () => {
    const carol = await newBrowser(server);
    await addContact({ db: carol.db, client, me: carol.me, userId: bob.me.userId });
    await sendChatMessage({ db: carol.db, client, me: carol.me, contactId: bob.me.userId, text: "hi", now: () => NOW });
    await sendChatMessage({ db: carol.db, client, me: carol.me, contactId: bob.me.userId, text: "hi?", now: () => NOW });

    expect(await receive(bob)).toEqual({ stored: 0, dropped: 0, unknownSenders: [carol.me.userId], heldForKeyChange: 0 });
    expect(inbox(bob)).toHaveLength(2);

    await addContact({ db: bob.db, client, me: bob.me, userId: carol.me.userId });
    expect((await receive(bob)).stored).toBe(2);
  });

  it("tops up its one-time keys after someone starts a conversation", async () => {
    await send(alice, bob, "hi");
    expect(keysLeft(bob)).toBe(49);
    await receive(bob);
    // Above the top-up threshold, so nothing is uploaded yet...
    expect(keysLeft(bob)).toBe(49);

    // ...but once the supply runs low it is refilled.
    server.oneTimeKeys.get(bob.me.userId)!.splice(0, 30);
    const carol = await newBrowser(server);
    await befriend(carol, bob);
    await sendChatMessage({ db: carol.db, client, me: carol.me, contactId: bob.me.userId, text: "hey", now: () => NOW });
    await receive(bob);
    expect(keysLeft(bob)).toBe(50);
  });

  it("holds a message from a contact's new key until the user accepts it, then reads it", async () => {
    // Alice's browser data is lost; she restores her identity key but has a new ratchet account.
    const restoredDb = await openDatabase(new IDBFactory());
    const fresh = createRatchetAccount();
    const restored = { ...alice.me, ratchetPublicKey: fresh.ratchetPublicKey, pickleKey: fresh.pickleKey };
    await saveNewIdentity(restoredDb, restored, fresh.accountPickle);
    server.users.set(alice.me.userId, restored);
    await addContact({ db: restoredDb, client, me: restored, userId: bob.me.userId });
    await sendChatMessage({ db: restoredDb, client, me: restored, contactId: bob.me.userId, text: "it's me", now: () => NOW });

    // Bob's app notices the new key; until he decides, the message cannot be read and is kept on the server.
    await refreshContactKeys(bob.db, client, bob.me, alice.me.userId);
    expect(await receive(bob)).toMatchObject({ stored: 0, heldForKeyChange: 1 });
    expect(inbox(bob)).toHaveLength(1);

    await acceptChangedKey(bob.db, alice.me.userId);
    expect(await receive(bob)).toMatchObject({ stored: 1, heldForKeyChange: 0 });
    expect(await history(bob, alice)).toEqual(["in:it's me"]);
  });

  it("keeps the two directions of a conversation in order", async () => {
    await send(alice, bob, "1");
    await receive(bob);
    await send(bob, alice, "2");
    await receive(alice);
    await send(alice, bob, "3");
    await receive(bob);
    expect(await history(alice, bob)).toEqual(["out:1", "in:2", "out:3"]);
    expect(await history(bob, alice)).toEqual(["in:1", "out:2", "in:3"]);
  });

  it("works when both people start a conversation at the same moment", async () => {
    await send(alice, bob, "hi bob");
    await send(bob, alice, "hi alice");
    expect((await receive(alice)).stored).toBe(1);
    expect((await receive(bob)).stored).toBe(1);

    for (let round = 0; round < 3; round++) {
      await send(alice, bob, `a${round}`);
      await send(bob, alice, `b${round}`);
      expect((await receive(alice)).stored).toBe(1);
      expect((await receive(bob)).stored).toBe(1);
    }
    expect(await history(bob, alice)).toEqual([
      "out:hi alice",
      "in:hi bob",
      // Each round Bob sends before he checks his inbox.
      "out:b0",
      "in:a0",
      "out:b1",
      "in:a1",
      "out:b2",
      "in:a2",
    ]);
  });

  it("does not store a message twice when two tabs receive at the same moment", async () => {
    await send(alice, bob, "once");
    const results = await Promise.all([receive(bob), receive(bob)]);
    expect(results[0]!.stored + results[1]!.stored).toBe(1);
    expect(await history(bob, alice)).toEqual(["in:once"]);
  });
});

describe("paging through the inbox", () => {
  it("collects every waiting message, however many pages it takes", async () => {
    server.pageSize = 2;
    for (let i = 1; i <= 5; i++) await send(alice, bob, `m${i}`);
    expect((await receive(bob)).stored).toBe(5);
    expect(await history(bob, alice)).toEqual(["in:m1", "in:m2", "in:m3", "in:m4", "in:m5"]);
  });

  it("is not held up by a page full of messages it has to leave on the server", async () => {
    server.pageSize = 3;
    const stranger = await newBrowser(server);
    await addContact({ db: stranger.db, client, me: stranger.me, userId: bob.me.userId });
    for (let i = 0; i < 4; i++) {
      await sendChatMessage({ db: stranger.db, client, me: stranger.me, contactId: bob.me.userId, text: `s${i}`, now: () => NOW });
    }
    await send(alice, bob, "behind the queue");

    expect(await receive(bob)).toMatchObject({ stored: 1, unknownSenders: [stranger.me.userId] });
    expect(await history(bob, alice)).toEqual(["in:behind the queue"]);
    expect(inbox(bob)).toHaveLength(4);
  });

  it("stops after a bounded number of pages if a server never runs out", async () => {
    const endless: ApiClient = {
      ...client,
      fetchInbox: async () => {
        server.inboxFetches += 1;
        return [
          {
            messageId: "00000000-0000-4000-8000-000000000001",
            from: "x".repeat(43),
            type: 1,
            ciphertext: "AAAA",
            createdAt: new Date(NOW).toISOString(),
            cursor: "1_00000000-0000-4000-8000-000000000001",
          },
        ];
      },
    };
    await receiveMessages({ db: bob.db, client: endless, me: bob.me });
    expect(server.inboxFetches).toBe(200);
  });
});
