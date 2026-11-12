import * as crypto from "@messager/crypto";
import { deriveUserId } from "@messager/protocol";
import { IDBFactory } from "fake-indexeddb";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createIdentity } from "../identity.js";
import { openDatabase } from "./db.js";
import { loadIdentity, markRegistered, saveNewIdentity } from "./identity-store.js";

let factory: IDBFactory;

beforeAll(async () => {
  await crypto.ready;
});

beforeEach(() => {
  // A fresh, empty browser database for every test.
  factory = new IDBFactory();
});

describe("createIdentity", () => {
  it("makes both keypairs and derives the userID from the identity key", () => {
    const identity = createIdentity(1_800_000_000_000);
    expect(identity.identityPublicKey).toHaveLength(32);
    expect(identity.identityPrivateKey).toHaveLength(64);
    expect(identity.exchangePublicKey).toHaveLength(32);
    expect(identity.exchangePrivateKey).toHaveLength(32);
    expect(identity.userId).toBe(deriveUserId(identity.identityPublicKey));
    expect(identity.createdAt).toBe(1_800_000_000_000);
    expect(identity.registeredAt).toBeNull();
  });

  it("makes different keys every time", () => {
    const a = createIdentity(1);
    const b = createIdentity(1);
    expect(a.userId).not.toBe(b.userId);
    expect(crypto.toHex(a.exchangePrivateKey)).not.toBe(crypto.toHex(b.exchangePrivateKey));
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

  it("saves an identity and loads back exactly the same keys", async () => {
    const db = await openDatabase(factory);
    const identity = createIdentity(123);
    await saveNewIdentity(db, identity);

    const loaded = await loadIdentity(db);
    expect(loaded).not.toBeNull();
    expect(loaded!.userId).toBe(identity.userId);
    expect(loaded!.createdAt).toBe(123);
    expect(loaded!.registeredAt).toBeNull();
    for (const key of [
      "identityPublicKey",
      "identityPrivateKey",
      "exchangePublicKey",
      "exchangePrivateKey",
    ] as const) {
      expect(loaded![key]).toBeInstanceOf(Uint8Array);
      expect(crypto.toHex(loaded![key])).toBe(crypto.toHex(identity[key]));
    }
  });

  it("keeps the identity after the database is closed and reopened", async () => {
    const identity = createIdentity(1);
    const first = await openDatabase(factory);
    await saveNewIdentity(first, identity);
    first.close();

    const second = await openDatabase(factory);
    expect((await loadIdentity(second))!.userId).toBe(identity.userId);
  });

  it("refuses to replace an existing identity", async () => {
    const db = await openDatabase(factory);
    const original = createIdentity(1);
    await saveNewIdentity(db, original);

    await expect(saveNewIdentity(db, createIdentity(2))).rejects.toThrow(/already exists/);
    const loaded = await loadIdentity(db);
    expect(loaded!.userId).toBe(original.userId);
    expect(crypto.toHex(loaded!.identityPrivateKey)).toBe(crypto.toHex(original.identityPrivateKey));
  });

  it("refuses to save an identity whose userID does not match its key", async () => {
    const db = await openDatabase(factory);
    const identity = { ...createIdentity(1), userId: createIdentity(1).userId };
    await expect(saveNewIdentity(db, identity)).rejects.toThrow(/invalid identity/);
    expect(await loadIdentity(db)).toBeNull();
  });

  it("refuses to save a key of the wrong length", async () => {
    const db = await openDatabase(factory);
    const identity = { ...createIdentity(1), exchangePrivateKey: new Uint8Array(31) };
    await expect(saveNewIdentity(db, identity)).rejects.toThrow(/invalid identity/);
  });

  it("records when the identity was registered", async () => {
    const db = await openDatabase(factory);
    const identity = createIdentity(1);
    await saveNewIdentity(db, identity);

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
    await saveNewIdentity(db, createIdentity(1));
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction("identity", "readwrite");
      tx.objectStore("identity").put({ userId: "broken" }, "self");
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    await expect(loadIdentity(db)).rejects.toThrow(/invalid identity/);
  });

  it("keeps separate databases apart by name", async () => {
    const a = await openDatabase(factory, "one");
    const b = await openDatabase(factory, "two");
    await saveNewIdentity(a, createIdentity(1));
    expect(await loadIdentity(b)).toBeNull();
  });
});
