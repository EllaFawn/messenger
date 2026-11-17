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
import { createIdentity as createIdentityWithAccount, createRatchetAccount, type StoredIdentity } from "./identity.js";
import { getContact, listContacts } from "./storage/contact-store.js";
import { openDatabase } from "./storage/db.js";

const NOW = 1_800_000_000_000;

const createIdentity = (now: number): StoredIdentity => createIdentityWithAccount(now).identity;

let factory: IDBFactory;
let db: IDBDatabase;
let me: StoredIdentity;
let bob: StoredIdentity;
/** What the fake server says each user's keys are. */
let directory: Map<string, PublicKeys>;
let lookups: string[];
let client: ApiClient;

function publicKeysOf(who: StoredIdentity): PublicKeys {
  return { userId: who.userId, identityPublicKey: who.identityPublicKey, ratchetPublicKey: who.ratchetPublicKey, keyEpoch: 1 };
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
    claimOneTimeKey: async () => {
      throw new Error("not used");
    },
    countOneTimeKeys: async () => ({ count: 50, hasFallback: true }),
    uploadOneTimeKeys: async () => ({ count: 50, hasFallback: true }),
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
    expect(hex(stored!.ratchetPublicKey)).toBe(hex(bob.ratchetPublicKey));
    expect(stored!.changedRatchetPublicKey).toBeNull();
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
    directory.set(bob.userId, { ...publicKeysOf(bob), ratchetPublicKey: createRatchetAccount().ratchetPublicKey });

    await expect(addContact({ db, client, me, userId: bob.userId, name: "Bob again" })).rejects.toThrow(
      /already been added/,
    );
    const stored = await getContact(db, bob.userId);
    expect(stored!.name).toBe("Bob");
    expect(hex(stored!.ratchetPublicKey)).toBe(hex(bob.ratchetPublicKey));
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
    substitute = createRatchetAccount().ratchetPublicKey;
  });

  it("changes nothing when the server returns the same keys", async () => {
    const contact = await refreshContactKeys(db, client, me, bob.userId);
    expect(canSendTo(contact)).toBe(true);
    expect(contact.changedRatchetPublicKey).toBeNull();
  });

  it("blocks sending when the server returns a different ratchet key, and keeps the pinned key", async () => {
    directory.set(bob.userId, { ...publicKeysOf(bob), ratchetPublicKey: substitute });
    const contact = await refreshContactKeys(db, client, me, bob.userId);

    expect(canSendTo(contact)).toBe(false);
    expect(hex(contact.ratchetPublicKey)).toBe(hex(bob.ratchetPublicKey));
    expect(hex(contact.changedRatchetPublicKey)).toBe(hex(substitute));

    const stored = await getContact(db, bob.userId);
    expect(canSendTo(stored!)).toBe(false);
    expect(hex(stored!.ratchetPublicKey)).toBe(hex(bob.ratchetPublicKey));
  });

  it("stays blocked if the server later goes back to the original key", async () => {
    directory.set(bob.userId, { ...publicKeysOf(bob), ratchetPublicKey: substitute });
    await refreshContactKeys(db, client, me, bob.userId);
    directory.set(bob.userId, publicKeysOf(bob));
    const contact = await refreshContactKeys(db, client, me, bob.userId);
    expect(canSendTo(contact)).toBe(false);
  });

  it("pins the new key only when the user accepts it", async () => {
    directory.set(bob.userId, { ...publicKeysOf(bob), ratchetPublicKey: substitute });
    await refreshContactKeys(db, client, me, bob.userId);

    const contact = await acceptChangedKey(db, bob.userId);
    expect(canSendTo(contact)).toBe(true);
    expect(hex(contact.ratchetPublicKey)).toBe(hex(substitute));
    expect(hex((await getContact(db, bob.userId))!.ratchetPublicKey)).toBe(hex(substitute));
  });

  it("keeps the original key when the user rejects the new one", async () => {
    directory.set(bob.userId, { ...publicKeysOf(bob), ratchetPublicKey: substitute });
    await refreshContactKeys(db, client, me, bob.userId);

    const contact = await rejectChangedKey(db, bob.userId);
    expect(canSendTo(contact)).toBe(true);
    expect(hex(contact.ratchetPublicKey)).toBe(hex(bob.ratchetPublicKey));
  });

  it("refuses keys that carry a different identity key", async () => {
    const mallory = createIdentity(NOW);
    directory.set(bob.userId, { ...publicKeysOf(mallory), userId: bob.userId });
    await expect(refreshContactKeys(db, client, me, bob.userId)).rejects.toThrow(/do not belong/);
    expect(canSendTo((await getContact(db, bob.userId))!)).toBe(true);
  });

  it("accepting when nothing changed does nothing", async () => {
    const contact = await acceptChangedKey(db, bob.userId);
    expect(hex(contact.ratchetPublicKey)).toBe(hex(bob.ratchetPublicKey));
  });

  it("fails for a contact that does not exist", async () => {
    const stranger = createIdentity(NOW);
    directory.set(stranger.userId, publicKeysOf(stranger));
    await expect(refreshContactKeys(db, client, me, stranger.userId)).rejects.toThrow(/No such contact/);
    await expect(acceptChangedKey(db, stranger.userId)).rejects.toThrow(/No such contact/);
  });
});
