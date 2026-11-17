/**
 * Test helper: an in-memory stand-in for the server, behaving as the real
 * one does for the routes the web client uses. Never part of the app.
 */
import * as crypto from "@messager/crypto";
import type { Envelope } from "@messager/protocol";
import { IDBFactory } from "fake-indexeddb";
import { ApiError, type ApiClient, type InboxItem } from "./api/client.js";
import { createIdentity, type StoredIdentity } from "./identity.js";
import { topUpOneTimeKeys } from "./one-time-keys.js";
import { openDatabase } from "./storage/db.js";
import { saveNewIdentity } from "./storage/identity-store.js";

export const NOW = 1_800_000_000_000;

interface HeldKey {
  id: string;
  key: Uint8Array;
}

export class FakeServer {
  users = new Map<string, StoredIdentity>();
  inboxes = new Map<string, InboxItem[]>();
  oneTimeKeys = new Map<string, HeldKey[]>();
  fallbacks = new Map<string, HeldKey>();
  acked: string[] = [];
  claims = 0;
  uploads = 0;
  failSend = false;
  failAck = false;
  failUpload = false;
  pageSize = 100;
  inboxFetches = 0;
  private nextId = 1;

  register(who: StoredIdentity): void {
    this.users.set(who.userId, who);
    this.inboxes.set(who.userId, []);
    this.oneTimeKeys.set(who.userId, []);
  }

  /** Puts an envelope in the recipient's inbox as if `from` had sent it. */
  deliver(from: string, envelope: Envelope): string {
    const messageId = `00000000-0000-4000-8000-${String(this.nextId).padStart(12, "0")}`;
    this.inboxes.get(envelope.to)!.push({
      messageId,
      from,
      type: envelope.type,
      ciphertext: envelope.ciphertext,
      createdAt: new Date(NOW).toISOString(),
      cursor: `${this.nextId}_${messageId}`,
    });
    this.nextId += 1;
    return messageId;
  }

  private keysOf(userId: string) {
    const user = this.users.get(userId);
    if (user === undefined) throw new ApiError(404, "not_found");
    return { userId, identityPublicKey: user.identityPublicKey, ratchetPublicKey: user.ratchetPublicKey, keyEpoch: 1 };
  }

  private count(userId: string) {
    return { count: this.oneTimeKeys.get(userId)!.length, hasFallback: this.fallbacks.has(userId) };
  }

  client(): ApiClient {
    return {
      request: async () => undefined,
      register: async () => undefined,
      getPubkeys: async (_me, userId) => this.keysOf(userId),
      claimOneTimeKey: async (_me, userId) => {
        const keys = this.keysOf(userId);
        this.claims += 1;
        const held = this.oneTimeKeys.get(userId)!;
        const taken = held.shift();
        if (taken !== undefined) return { ...keys, oneTimeKey: taken.key, fallback: false };
        const fallback = this.fallbacks.get(userId);
        if (fallback === undefined) throw new ApiError(409, "no_one_time_keys");
        return { ...keys, oneTimeKey: fallback.key, fallback: true };
      },
      countOneTimeKeys: async (me) => this.count(me.userId),
      uploadOneTimeKeys: async (me, keys, fallback) => {
        if (this.failUpload) throw new ApiError(0, "network_error");
        if (keys.length > 50) throw new ApiError(400, "invalid_request");
        // Signing happens inside the real API client (tested there); the keys handed to it must be well formed.
        if (![...keys, ...(fallback === undefined ? [] : [fallback])].every((k) => k.key.length === 32)) {
          throw new ApiError(400, "invalid_request");
        }
        // The real server keeps one set of ids per user and refuses a repeat within an upload.
        // The real client prefixes the fallback id (see FALLBACK_ID_PREFIX); the fake gets them raw.
        const ids = keys.map((k) => k.id);
        if (new Set(ids).size !== ids.length) throw new ApiError(400, "invalid_request");
        this.uploads += 1;
        const held = this.oneTimeKeys.get(me.userId)!;
        for (const key of keys) {
          if (!held.some((h) => h.id === key.id) && held.length < 100) held.push(key);
        }
        if (fallback !== undefined) this.fallbacks.set(me.userId, fallback);
        return this.count(me.userId);
      },
      sendMessage: async (me, envelope) => {
        if (this.failSend) throw new ApiError(0, "network_error");
        return { messageId: this.deliver(me.userId, envelope) };
      },
      fetchInbox: async (me, after) => {
        this.inboxFetches += 1;
        // Pages, like the real server: the items after the cursor, a few at a time.
        const inbox = this.inboxes.get(me.userId)!;
        const position = (item: InboxItem) => Number(item.cursor.split("_")[0]);
        const from = after === undefined ? -1 : Number(after.split("_")[0]);
        return inbox.filter((item) => position(item) > from).slice(0, this.pageSize);
      },
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

/** One person's browser: its own storage and its identity, registered with the fake server and with keys published. */
export interface Browser {
  db: IDBDatabase;
  me: StoredIdentity;
}

export async function newBrowser(server: FakeServer): Promise<Browser> {
  await crypto.ready;
  const db = await openDatabase(new IDBFactory());
  const { identity, accountPickle } = createIdentity(NOW);
  await saveNewIdentity(db, identity, accountPickle);
  server.register(identity);
  await topUpOneTimeKeys({ db, client: server.client(), me: identity });
  return { db, me: identity };
}
