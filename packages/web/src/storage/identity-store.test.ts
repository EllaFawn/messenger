import * as crypto from "@messager/crypto";
import { deriveUserId } from "@messager/protocol";
import { RatchetAccount } from "@messager/ratchet";
import { IDBFactory } from "fake-indexeddb";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createIdentity as createIdentityWithAccount, type StoredIdentity } from "../identity.js";
import { loadSession } from "../session.js";
import { listContacts } from "./contact-store.js";
import { openDatabase, openDatabaseAt, requestResult, transactionDone } from "./db.js";
import { ensureRatchetAccount, loadIdentity, markRegistered, saveNewIdentity } from "./identity-store.js";
import { listMessages } from "./message-store.js";
import { loadAccount } from "./ratchet-store.js";

let factory: IDBFactory;

const createIdentity = (now: number): StoredIdentity => createIdentityWithAccount(now).identity;

async function saveFresh(db: IDBDatabase, now = 1): Promise<StoredIdentity> {
  const { identity, accountPickle } = createIdentityWithAccount(now);
  await saveNewIdentity(db, identity, accountPickle);
  return identity;
}

beforeAll(async () => {
  await crypto.ready;
});

beforeEach(() => {
  // A fresh, empty browser database for every test.
  factory = new IDBFactory();
});

describe("createIdentity", () => {
  it("makes an identity keypair, a ratchet account, and derives the userID from the identity key", () => {
    const { identity, accountPickle } = createIdentityWithAccount(1_800_000_000_000);
    expect(identity.identityPublicKey).toHaveLength(32);
    expect(identity.identityPrivateKey).toHaveLength(64);
    expect(identity.ratchetPublicKey).toHaveLength(32);
    expect(identity.pickleKey).toHaveLength(32);
    expect(identity.userId).toBe(deriveUserId(identity.identityPublicKey));
    expect(identity.createdAt).toBe(1_800_000_000_000);
    expect(identity.registeredAt).toBeNull();
    // The saved account is the one whose key the identity records.
    const account = RatchetAccount.restore(accountPickle, identity.pickleKey);
    expect(crypto.toHex(account.identityKey)).toBe(crypto.toHex(identity.ratchetPublicKey));
  });

  it("makes different keys every time", () => {
    const a = createIdentity(1);
    const b = createIdentity(1);
    expect(a.userId).not.toBe(b.userId);
    expect(crypto.toHex(a.ratchetPublicKey)).not.toBe(crypto.toHex(b.ratchetPublicKey));
    expect(crypto.toHex(a.pickleKey)).not.toBe(crypto.toHex(b.pickleKey));
  });

  it("makes a signing key that matches its public key", () => {
    const identity = createIdentity(1);
    const message = crypto.utf8Encode("check");
    const signature = crypto.sign(identity.identityPrivateKey, message);
    expect(crypto.verify(identity.identityPublicKey, message, signature)).toBe(true);
  });
});

describe("identity store", () => {
  it("returns null when no identity has been created", async () => {
    const db = await openDatabase(factory);
    expect(await loadIdentity(db)).toBeNull();
  });

  it("saves an identity with its ratchet account and loads back exactly the same keys", async () => {
    const db = await openDatabase(factory);
    const identity = await saveFresh(db, 123);

    const loaded = await loadIdentity(db);
    expect(loaded).not.toBeNull();
    expect(loaded!.userId).toBe(identity.userId);
    expect(loaded!.createdAt).toBe(123);
    expect(loaded!.registeredAt).toBeNull();
    for (const key of ["identityPublicKey", "identityPrivateKey", "ratchetPublicKey", "pickleKey"] as const) {
      expect(loaded![key]).toBeInstanceOf(Uint8Array);
      expect(crypto.toHex(loaded![key])).toBe(crypto.toHex(identity[key]));
    }
    const account = await loadAccount(db, loaded!.pickleKey);
    expect(crypto.toHex(account.identityKey)).toBe(crypto.toHex(identity.ratchetPublicKey));
  });

  it("keeps the identity after the database is closed and reopened", async () => {
    const first = await openDatabase(factory);
    const identity = await saveFresh(first);
    first.close();

    const second = await openDatabase(factory);
    expect((await loadIdentity(second))!.userId).toBe(identity.userId);
  });

  it("refuses to replace an existing identity or its account", async () => {
    const db = await openDatabase(factory);
    const original = await saveFresh(db);

    const other = createIdentityWithAccount(2);
    await expect(saveNewIdentity(db, other.identity, other.accountPickle)).rejects.toThrow(/already exists/);
    const loaded = await loadIdentity(db);
    expect(loaded!.userId).toBe(original.userId);
    expect(crypto.toHex(loaded!.identityPrivateKey)).toBe(crypto.toHex(original.identityPrivateKey));
    const account = await loadAccount(db, original.pickleKey);
    expect(crypto.toHex(account.identityKey)).toBe(crypto.toHex(original.ratchetPublicKey));
  });

  it("refuses to save an identity whose userID does not match its key", async () => {
    const db = await openDatabase(factory);
    const { identity, accountPickle } = createIdentityWithAccount(1);
    await expect(saveNewIdentity(db, { ...identity, userId: createIdentity(1).userId }, accountPickle)).rejects.toThrow(
      /invalid identity/,
    );
    expect(await loadIdentity(db)).toBeNull();
  });

  it.each(["ratchetPublicKey", "pickleKey"] as const)("refuses to save a %s of the wrong length", async (field) => {
    const db = await openDatabase(factory);
    const { identity, accountPickle } = createIdentityWithAccount(1);
    await expect(saveNewIdentity(db, { ...identity, [field]: new Uint8Array(31) }, accountPickle)).rejects.toThrow(
      /invalid identity/,
    );
  });

  it("records when the identity was registered", async () => {
    const db = await openDatabase(factory);
    const identity = await saveFresh(db);

    await markRegistered(db, 999);
    const loaded = await loadIdentity(db);
    expect(loaded!.registeredAt).toBe(999);
    expect(crypto.toHex(loaded!.identityPrivateKey)).toBe(crypto.toHex(identity.identityPrivateKey));
  });

  it("cannot mark as registered when there is no identity", async () => {
    const db = await openDatabase(factory);
    await expect(markRegistered(db, 999)).rejects.toThrow(/no identity/);
  });

  it("fails loudly on a stored identity that has been damaged", async () => {
    const db = await openDatabase(factory);
    await saveFresh(db);
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction("identity", "readwrite");
      tx.objectStore("identity").put({ userId: "broken" }, "self");
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    await ensureRatchetAccount(db);
    await expect(loadIdentity(db)).rejects.toThrow(/invalid identity/);
  });

  it("keeps separate databases apart by name", async () => {
    const a = await openDatabase(factory, "one");
    const b = await openDatabase(factory, "two");
    await saveFresh(a);
    expect(await loadIdentity(b)).toBeNull();
  });

  it("leaves an identity that already has a ratchet account alone", async () => {
    const db = await openDatabase(factory);
    const identity = await saveFresh(db);
    await markRegistered(db, 5);
    await ensureRatchetAccount(db);
    const loaded = await loadIdentity(db);
    expect(crypto.toHex(loaded!.ratchetPublicKey)).toBe(crypto.toHex(identity.ratchetPublicKey));
    expect(loaded!.registeredAt).toBe(5);
  });
});

describe("upgrading a browser from before forward secrecy", () => {
  /** A database as version 3 of the app left it: a registered static-key identity, a contact, history and counters. */
  async function legacyBrowser(): Promise<{ identityKeys: crypto.KeyPair; userId: string; contactId: string }> {
    const v3 = await openDatabaseAt(factory, "messager", 3);
    const identityKeys = crypto.generateIdentityKeyPair();
    const userId = deriveUserId(identityKeys.publicKey);
    const contactId = deriveUserId(crypto.generateIdentityKeyPair().publicKey);
    const tx = v3.transaction(["identity", "contacts", "history", "counters"], "readwrite");
    const done = transactionDone(tx);
    tx.objectStore("identity").put(
      {
        userId,
        identityPublicKey: identityKeys.publicKey,
        identityPrivateKey: identityKeys.privateKey,
        exchangePublicKey: crypto.randomBytes(32),
        exchangePrivateKey: crypto.randomBytes(32),
        createdAt: 7,
        registeredAt: 8,
      },
      "self",
    );
    tx.objectStore("contacts").put({
      userId: contactId,
      name: "Old friend",
      identityPublicKey: crypto.randomBytes(32),
      exchangePublicKey: crypto.randomBytes(32),
      addedAt: 1,
      changedExchangePublicKey: null,
    });
    tx.objectStore("history").add({ contactId, direction: "in", text: "from before", sentAt: 1, counter: 1 });
    tx.objectStore("counters").put({ contactId, nextSend: 2, lastReceived: 1 });
    await done;
    v3.close();
    return { identityKeys, userId, contactId };
  }

  it("keeps the identity key and userID, adds a ratchet account, and asks to register again", async () => {
    const { identityKeys, userId } = await legacyBrowser();
    const db = await openDatabase(factory);

    const session = await loadSession(db);
    expect(session.status).toBe("unregistered");
    const identity = await loadIdentity(db);
    expect(identity!.userId).toBe(userId);
    expect(crypto.toHex(identity!.identityPrivateKey)).toBe(crypto.toHex(identityKeys.privateKey));
    expect(identity!.createdAt).toBe(7);
    expect(identity).not.toHaveProperty("exchangePrivateKey");
    const account = await loadAccount(db, identity!.pickleKey);
    expect(crypto.toHex(account.identityKey)).toBe(crypto.toHex(identity!.ratchetPublicKey));

    // Doing it again changes nothing.
    await loadSession(db);
    expect(crypto.toHex((await loadIdentity(db))!.ratchetPublicKey)).toBe(crypto.toHex(identity!.ratchetPublicKey));
  });

  it("removes contacts pinned to static keys and the counters, but keeps the history", async () => {
    const { contactId } = await legacyBrowser();
    const db = await openDatabase(factory);
    expect(await listContacts(db)).toEqual([]);
    expect([...db.objectStoreNames]).not.toContain("counters");
    expect((await listMessages(db, contactId)).map((m) => m.text)).toEqual(["from before"]);
  });

  it("opens a version 1 database (identity only) as well", async () => {
    const v1 = await openDatabaseAt(factory, "messager", 1);
    v1.close();
    const db = await openDatabase(factory);
    expect([...db.objectStoreNames].sort()).toEqual(["contacts", "history", "identity", "ratchetAccount", "sessions"]);
    expect(await requestResult(db.transaction("identity").objectStore("identity").count())).toBe(0);
  });
});
