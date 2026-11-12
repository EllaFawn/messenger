import * as crypto from "@messager/crypto";
import { IDBFactory } from "fake-indexeddb";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ApiError, type ApiClient, type PublicKeys } from "./api/client.js";
import {
  acceptChangedKey,
  addContact,
  canSendTo,
  refreshContactKeys,
  rejectChangedKey,
} from "./contacts.js";
import { createIdentity, type StoredIdentity } from "./identity.js";
import { getContact, listContacts } from "./storage/contact-store.js";
import { openDatabase } from "./storage/db.js";
import { loadIdentity, saveNewIdentity } from "./storage/identity-store.js";

const NOW = 1_800_000_000_000;

let factory: IDBFactory;
let db: IDBDatabase;
let me: StoredIdentity;
let bob: StoredIdentity;
/** What the fake server says each user's keys are. */
let directory: Map<string, PublicKeys>;
let lookups: string[];
let client: ApiClient;

function publicKeysOf(who: StoredIdentity): PublicKeys {
  return { userId: who.userId, identityPublicKey: who.identityPublicKey, exchangePublicKey: who.exchangePublicKey };
}

beforeAll(async () => {
  await crypto.ready;
});

beforeEach(async () => {
  factory = new IDBFactory();
  db = await openDatabase(factory);
  me = createIdentity(NOW);
  bob = createIdentity(NOW);
  directory = new Map([[bob.userId, publicKeysOf(bob)]]);
  lookups = [];
  client = {
    request: async () => undefined,
    sendMessage: async () => {
      throw new Error("not used");
    },
    fetchInbox: async () => [],
    ackMessage: async () => undefined,
    register: async () => undefined,
    getPubkeys: async (_identity, userId) => {
      lookups.push(userId);
      const keys = directory.get(userId);
      if (keys === undefined) throw new ApiError(404, "not_found");
      return keys;
    },
  };
});

const hex = (bytes: Uint8Array | null) => (bytes === null ? null : crypto.toHex(bytes));

describe("addContact", () => {
  it("fetches the keys, pins them and stores the contact", async () => {
    const contact = await addContact({ db, client, me, userId: bob.userId, name: "Bob", now: () => NOW });
    expect(contact.name).toBe("Bob");
    expect(contact.addedAt).toBe(NOW);
    expect(canSendTo(contact)).toBe(true);

    const stored = await getContact(db, bob.userId);
    expect(hex(stored!.identityPublicKey)).toBe(hex(bob.identityPublicKey));
    expect(hex(stored!.exchangePublicKey)).toBe(hex(bob.exchangePublicKey));
    expect(stored!.changedExchangePublicKey).toBeNull();
  });

  it("trims spaces around a pasted ID and name", async () => {
    const contact = await addContact({ db, client, me, userId: `  ${bob.userId}\n`, name: "  Bob " });
    expect(contact.userId).toBe(bob.userId);
    expect(contact.name).toBe("Bob");
  });

  it("allows a contact with no name", async () => {
    expect((await addContact({ db, client, me, userId: bob.userId })).name).toBe("");
  });

  it.each([["too-short"], [""], ["a".repeat(44)], ["a".repeat(42) + "!"]])(
    "rejects the malformed ID %j without asking the server",
    async (userId) => {
      await expect(addContact({ db, client, me, userId })).rejects.toThrow(/not a valid user ID/);
      expect(lookups).toHaveLength(0);
    },
  );

  it("rejects the user's own ID", async () => {
    await expect(addContact({ db, client, me, userId: me.userId })).rejects.toThrow(/your own ID/);
    expect(lookups).toHaveLength(0);
  });

  it("rejects a name that is too long", async () => {
    await expect(addContact({ db, client, me, userId: bob.userId, name: "x".repeat(65) })).rejects.toThrow(
      /at most 64/,
    );
  });

  it("refuses to add the same contact twice and keeps the first pinned keys", async () => {
    await addContact({ db, client, me, userId: bob.userId, name: "Bob" });
    directory.set(bob.userId, { ...publicKeysOf(bob), exchangePublicKey: createIdentity(NOW).exchangePublicKey });

    await expect(addContact({ db, client, me, userId: bob.userId, name: "Bob again" })).rejects.toThrow(
      /already been added/,
    );
    const stored = await getContact(db, bob.userId);
    expect(stored!.name).toBe("Bob");
    expect(hex(stored!.exchangePublicKey)).toBe(hex(bob.exchangePublicKey));
  });

  it("stores nothing when the user does not exist", async () => {
    const stranger = createIdentity(NOW);
    const error = await addContact({ db, client, me, userId: stranger.userId }).catch((e: unknown) => e);
    expect((error as ApiError).code).toBe("not_found");
    expect(await listContacts(db)).toEqual([]);
  });
});

describe("listContacts", () => {
  it("lists contacts oldest first and survives reopening the database", async () => {
    const carol = createIdentity(NOW);
    directory.set(carol.userId, publicKeysOf(carol));
    await addContact({ db, client, me, userId: carol.userId, name: "Carol", now: () => NOW + 10 });
    await addContact({ db, client, me, userId: bob.userId, name: "Bob", now: () => NOW });
    db.close();

    const reopened = await openDatabase(factory);
    expect((await listContacts(reopened)).map((c) => c.name)).toEqual(["Bob", "Carol"]);
  });

  it("fails loudly on a damaged contact record", async () => {
    await addContact({ db, client, me, userId: bob.userId });
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction("contacts", "readwrite");
      tx.objectStore("contacts").put({ userId: bob.userId, name: "Bob" });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    await expect(listContacts(db)).rejects.toThrow(/invalid contact/);
  });
});

describe("key pinning", () => {
  let substitute: Uint8Array;

  beforeEach(async () => {
    await addContact({ db, client, me, userId: bob.userId, name: "Bob" });
    substitute = createIdentity(NOW).exchangePublicKey;
  });

  it("changes nothing when the server returns the same keys", async () => {
    const contact = await refreshContactKeys(db, client, me, bob.userId);
    expect(canSendTo(contact)).toBe(true);
    expect(contact.changedExchangePublicKey).toBeNull();
  });

  it("blocks sending when the server returns a different exchange key, and keeps the pinned key", async () => {
    directory.set(bob.userId, { ...publicKeysOf(bob), exchangePublicKey: substitute });
    const contact = await refreshContactKeys(db, client, me, bob.userId);

    expect(canSendTo(contact)).toBe(false);
    expect(hex(contact.exchangePublicKey)).toBe(hex(bob.exchangePublicKey));
    expect(hex(contact.changedExchangePublicKey)).toBe(hex(substitute));

    const stored = await getContact(db, bob.userId);
    expect(canSendTo(stored!)).toBe(false);
    expect(hex(stored!.exchangePublicKey)).toBe(hex(bob.exchangePublicKey));
  });

  it("stays blocked if the server later goes back to the original key", async () => {
    directory.set(bob.userId, { ...publicKeysOf(bob), exchangePublicKey: substitute });
    await refreshContactKeys(db, client, me, bob.userId);
    directory.set(bob.userId, publicKeysOf(bob));
    const contact = await refreshContactKeys(db, client, me, bob.userId);
    expect(canSendTo(contact)).toBe(false);
  });

  it("pins the new key only when the user accepts it", async () => {
    directory.set(bob.userId, { ...publicKeysOf(bob), exchangePublicKey: substitute });
    await refreshContactKeys(db, client, me, bob.userId);

    const contact = await acceptChangedKey(db, bob.userId);
    expect(canSendTo(contact)).toBe(true);
    expect(hex(contact.exchangePublicKey)).toBe(hex(substitute));
    expect(hex((await getContact(db, bob.userId))!.exchangePublicKey)).toBe(hex(substitute));
  });

  it("keeps the original key when the user rejects the new one", async () => {
    directory.set(bob.userId, { ...publicKeysOf(bob), exchangePublicKey: substitute });
    await refreshContactKeys(db, client, me, bob.userId);

    const contact = await rejectChangedKey(db, bob.userId);
    expect(canSendTo(contact)).toBe(true);
    expect(hex(contact.exchangePublicKey)).toBe(hex(bob.exchangePublicKey));
  });

  it("refuses keys that carry a different identity key", async () => {
    const mallory = createIdentity(NOW);
    directory.set(bob.userId, { ...publicKeysOf(mallory), userId: bob.userId });
    await expect(refreshContactKeys(db, client, me, bob.userId)).rejects.toThrow(/do not belong/);
    expect(canSendTo((await getContact(db, bob.userId))!)).toBe(true);
  });

  it("accepting when nothing changed does nothing", async () => {
    const contact = await acceptChangedKey(db, bob.userId);
    expect(hex(contact.exchangePublicKey)).toBe(hex(bob.exchangePublicKey));
  });

  it("fails for a contact that does not exist", async () => {
    const stranger = createIdentity(NOW);
    directory.set(stranger.userId, publicKeysOf(stranger));
    await expect(refreshContactKeys(db, client, me, stranger.userId)).rejects.toThrow(/No such contact/);
    await expect(acceptChangedKey(db, stranger.userId)).rejects.toThrow(/No such contact/);
  });
});

describe("database upgrade", () => {
  it("keeps an identity created before contacts existed", async () => {
    const old = new IDBFactory();
    // Version 1 had only the identity store.
    const v1 = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = old.open("messager", 1);
      request.onupgradeneeded = () => request.result.createObjectStore("identity");
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    await saveNewIdentity(v1, me);
    v1.close();

    const upgraded = await openDatabase(old);
    expect((await loadIdentity(upgraded))!.userId).toBe(me.userId);
    expect(await listContacts(upgraded)).toEqual([]);
  });
});
