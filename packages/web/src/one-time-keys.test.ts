import { beforeEach, describe, expect, it } from "vitest";
import { ONE_TIME_KEY_LOW, ONE_TIME_KEY_TARGET, topUpOneTimeKeys } from "./one-time-keys.js";
import { loadAccount } from "./storage/ratchet-store.js";
import { FakeServer, newBrowser, type Browser } from "./test-fake-server.js";

let server: FakeServer;
let bob: Browser;

beforeEach(async () => {
  server = new FakeServer();
  // newBrowser publishes the first batch.
  bob = await newBrowser(server);
});

const topUp = () => topUpOneTimeKeys({ db: bob.db, client: server.client(), me: bob.me });
const held = () => server.oneTimeKeys.get(bob.me.userId)!;

describe("topUpOneTimeKeys", () => {
  it("publishes a full supply and a fallback key for a new account", () => {
    expect(held()).toHaveLength(ONE_TIME_KEY_TARGET);
    expect(server.fallbacks.has(bob.me.userId)).toBe(true);
    expect(new Set(held().map((k) => k.id)).size).toBe(ONE_TIME_KEY_TARGET);
  });

  it("does nothing while the server holds enough", async () => {
    held().splice(0, ONE_TIME_KEY_TARGET - ONE_TIME_KEY_LOW);
    expect(await topUp()).toBe(0);
    expect(held()).toHaveLength(ONE_TIME_KEY_LOW);
  });

  it("refills to the target once the supply is low", async () => {
    held().splice(0, ONE_TIME_KEY_TARGET - ONE_TIME_KEY_LOW + 1);
    expect(await topUp()).toBe(ONE_TIME_KEY_TARGET - ONE_TIME_KEY_LOW + 1);
    expect(held()).toHaveLength(ONE_TIME_KEY_TARGET);
  });

  it("replaces a missing fallback key without uploading one-time keys", async () => {
    server.fallbacks.delete(bob.me.userId);
    expect(await topUp()).toBe(0);
    expect(server.fallbacks.has(bob.me.userId)).toBe(true);
    expect(held()).toHaveLength(ONE_TIME_KEY_TARGET);
  });

  it("keeps keys whose upload failed and sends the same ones next time", async () => {
    held().length = 0;
    server.failUpload = true;
    await expect(topUp()).rejects.toThrow();
    const account = await loadAccount(bob.db, bob.me.pickleKey);
    const pending = account.unpublishedOneTimeKeys().map((k) => k.id);
    expect(pending).toHaveLength(ONE_TIME_KEY_TARGET);

    server.failUpload = false;
    expect(await topUp()).toBe(ONE_TIME_KEY_TARGET);
    expect(held().map((k) => k.id)).toEqual(pending);
    expect((await loadAccount(bob.db, bob.me.pickleKey)).unpublishedOneTimeKeys()).toEqual([]);
  });

  it("saves the account before uploading, so every published key can be used", async () => {
    held().length = 0;
    let savedBeforeUpload: string[] = [];
    const client = server.client();
    const watching = {
      ...client,
      uploadOneTimeKeys: async (...args: Parameters<typeof client.uploadOneTimeKeys>) => {
        savedBeforeUpload = (await loadAccount(bob.db, bob.me.pickleKey)).unpublishedOneTimeKeys().map((k) => k.id);
        return client.uploadOneTimeKeys(...args);
      },
    };
    await topUpOneTimeKeys({ db: bob.db, client: watching, me: bob.me });
    expect(savedBeforeUpload).toEqual(held().map((k) => k.id));
  });
});
