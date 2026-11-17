import * as crypto from "@messager/crypto";
import { decodeMessagePlaintext, encodeEnvelope, encodeMessagePlaintext, type MessagePlaintext } from "@messager/protocol";
import { MESSAGE_TYPE_PREKEY, preKeyMessageSessionId, RatchetSession } from "@messager/ratchet";
import type { ApiClient, InboxItem } from "./api/client.js";
import { canSendTo, recordFetchedKeys, sameBytes, type Contact } from "./contacts.js";
import type { StoredIdentity } from "./identity.js";
import { topUpOneTimeKeys } from "./one-time-keys.js";
import { withRatchetLock } from "./ratchet-lock.js";
import { getContact } from "./storage/contact-store.js";
import { HISTORY_STORE, RATCHET_ACCOUNT_STORE, SESSIONS_STORE, transactionDone } from "./storage/db.js";
import { ACCOUNT_KEY } from "./storage/identity-store.js";
import { addHistoryInTransaction, storeOutgoing, type HistoryMessage } from "./storage/message-store.js";
import {
  listSessions,
  loadAccount,
  putSessionInTransaction,
  saveSession,
  type SessionRecord,
} from "./storage/ratchet-store.js";

/** A bound on one check, in case a server keeps returning pages for ever. */
const MAX_INBOX_PAGES = 200;

/** Keeps the encrypted, base64-encoded request comfortably under the server's 16 KB body limit. */
export const MAX_TEXT_BYTES = 8000;

export interface SendParams {
  db: IDBDatabase;
  client: ApiClient;
  me: StoredIdentity;
  contactId: string;
  text: string;
  now?: () => number;
}

/**
 * Encrypts a message to a contact, sends it, and adds it to the local
 * history. The first message to someone claims one of their one-time keys
 * from the server and starts a session; later ones continue it.
 */
export async function sendChatMessage(params: SendParams): Promise<HistoryMessage> {
  const { db, client, me, contactId, text } = params;
  const now = params.now ?? Date.now;
  if (text.trim() === "") {
    throw new Error("Type a message first.");
  }
  if (crypto.utf8Encode(text).length > MAX_TEXT_BYTES) {
    throw new Error("That message is too long.");
  }

  return withRatchetLock(async () => {
    const contact = await getContact(db, contactId);
    if (contact === null) {
      throw new Error("No such contact.");
    }
    if (!canSendTo(contact)) {
      throw new Error("Sending is blocked until you accept or reject this contact's changed key.");
    }

    const [newest] = await listSessions(db, contactId);
    const session =
      newest !== undefined ? RatchetSession.restore(newest.pickle, me.pickleKey) : await startSession(params, contact);

    const sentAt = now();
    const encrypted = session.encrypt(encodeMessagePlaintext({ text, sentAt }));
    // Saved before sending: if this tab crashed after sending, the restored
    // session would encrypt the next message with the same key.
    await saveSession(db, { contactId, sessionId: session.id, pickle: session.save(me.pickleKey), lastUsedAt: now() });
    await client.sendMessage(me, encodeEnvelope(contactId, encrypted));
    return storeOutgoing(db, { contactId, direction: "out", text, sentAt });
  });
}

/** Claims one of the contact's one-time keys and starts a session on it. */
async function startSession(params: SendParams, contact: Contact): Promise<RatchetSession> {
  const { db, client, me } = params;
  const claimed = await client.claimOneTimeKey(me, contact.userId);
  if (!sameBytes(claimed.ratchetPublicKey, contact.ratchetPublicKey)) {
    // The claim is signed for a different ratchet key than the pinned one.
    await recordFetchedKeys(db, contact.userId, claimed);
    throw new Error("This contact's key has changed. Sending is blocked until you accept or reject it.");
  }
  const account = await loadAccount(db, me.pickleKey);
  return account.startSession(contact.ratchetPublicKey, claimed.oneTimeKey);
}

export interface ReceiveResult {
  /** New messages added to the history. */
  stored: number;
  /** Removed from the server without being shown: undecryptable, malformed or already read. */
  dropped: number;
  /** Senders who are not contacts. Their messages stay on the server until they are added. */
  unknownSenders: string[];
  /** Left on the server because the sender's key change has not been resolved yet. */
  heldForKeyChange: number;
}

function isUsablePlaintext(message: MessagePlaintext): boolean {
  return Number.isFinite(message.sentAt) && crypto.utf8Encode(message.text).length <= MAX_TEXT_BYTES;
}

interface Decrypted {
  plaintext: Uint8Array;
  session: RatchetSession;
  /** Set when a new session was accepted: the account, saved, without the one-time key it used. */
  accountPickle: string | null;
}

/**
 * Decrypts in memory, changing nothing stored. Returns null if the message
 * cannot be decrypted by any session with this contact, or start a new one.
 */
async function tryDecrypt(
  db: IDBDatabase,
  me: StoredIdentity,
  contact: Contact,
  item: InboxItem,
): Promise<Decrypted | null> {
  let body: Uint8Array;
  try {
    body = crypto.fromBase64(item.ciphertext);
  } catch {
    return null;
  }
  const sessions = await listSessions(db, contact.userId);

  if (item.type === MESSAGE_TYPE_PREKEY) {
    // A sender repeats pre-key messages until it hears back, so this may
    // belong to a session that already exists.
    let sessionId: string;
    try {
      sessionId = preKeyMessageSessionId(body);
    } catch {
      return null;
    }
    const existing = sessions.find((s) => s.sessionId === sessionId);
    if (existing !== undefined) {
      return decryptWith(existing, me, item, body);
    }
    try {
      const account = await loadAccount(db, me.pickleKey);
      // Only succeeds if the message was made by the holder of the pinned ratchet key.
      const accepted = account.acceptSession(contact.ratchetPublicKey, body);
      return { ...accepted, accountPickle: account.save(me.pickleKey) };
    } catch {
      return null;
    }
  }

  for (const record of sessions) {
    const decrypted = decryptWith(record, me, item, body);
    if (decrypted !== null) return decrypted;
  }
  return null;
}

function decryptWith(record: SessionRecord, me: StoredIdentity, item: InboxItem, body: Uint8Array): Decrypted | null {
  try {
    const session = RatchetSession.restore(record.pickle, me.pickleKey);
    return { plaintext: session.decrypt({ type: item.type, body }), session, accountPickle: null };
  } catch {
    return null;
  }
}

type Outcome = "stored" | "dropped" | "unknown_sender" | "held";

/**
 * Handles one waiting message. Decrypting advances the ratchet and destroys
 * the message's key, so the text and the new session state are written in
 * ONE transaction: after a crash, either both are saved or neither is and
 * the message is still on the server.
 */
async function processItem(
  params: { db: IDBDatabase; me: StoredIdentity; now: () => number },
  item: InboxItem,
): Promise<{ outcome: Outcome; newSession: boolean }> {
  const { db, me, now } = params;
  const contact = await getContact(db, item.from);
  if (contact === null) {
    return { outcome: "unknown_sender", newSession: false };
  }

  const decrypted = await tryDecrypt(db, me, contact, item);
  if (decrypted === null) {
    // It may come from the key the user has not decided about yet.
    return { outcome: contact.changedRatchetPublicKey !== null ? "held" : "dropped", newSession: false };
  }

  let message: MessagePlaintext | null = null;
  try {
    message = decodeMessagePlaintext(decrypted.plaintext);
  } catch {
    message = null;
  }
  const usable = message !== null && isUsablePlaintext(message);

  const tx = db.transaction([HISTORY_STORE, SESSIONS_STORE, RATCHET_ACCOUNT_STORE], "readwrite");
  const done = transactionDone(tx);
  // The session is saved even for an unusable message, so it stays in step with the sender.
  putSessionInTransaction(tx, {
    contactId: contact.userId,
    sessionId: decrypted.session.id,
    pickle: decrypted.session.save(me.pickleKey),
    lastUsedAt: now(),
  });
  if (decrypted.accountPickle !== null) {
    tx.objectStore(RATCHET_ACCOUNT_STORE).put(decrypted.accountPickle, ACCOUNT_KEY);
  }
  if (usable) {
    addHistoryInTransaction(tx, {
      contactId: contact.userId,
      direction: "in",
      text: message!.text,
      sentAt: message!.sentAt,
    });
  }
  await done;
  return { outcome: usable ? "stored" : "dropped", newSession: decrypted.accountPickle !== null };
}

/**
 * Fetches waiting messages, decrypts them, stores the new ones and
 * acknowledges them so the server deletes its copies.
 *
 * A message is acknowledged only after it is safely stored (or definitely
 * unusable). If the acknowledgement is lost, the server delivers it again;
 * its key is gone by then, so it no longer decrypts and is dropped.
 */
export async function receiveMessages(params: {
  db: IDBDatabase;
  client: ApiClient;
  me: StoredIdentity;
  now?: () => number;
}): Promise<ReceiveResult> {
  const { db, client, me } = params;
  const now = params.now ?? Date.now;
  const result: ReceiveResult = { stored: 0, dropped: 0, unknownSenders: [], heldForKeyChange: 0 };
  let newSessions = 0;

  // Walk the whole inbox a page at a time. Messages left on the server
  // (unknown sender, unresolved key change) are stepped past, so they never
  // hold up the ones behind them.
  let after: string | undefined;
  for (let pageNumber = 0; pageNumber < MAX_INBOX_PAGES; pageNumber++) {
    const page = await client.fetchInbox(me, after);
    if (page.length === 0) break;
    after = page[page.length - 1]!.cursor;

    for (const item of page) {
      const { outcome, newSession } = await withRatchetLock(() => processItem({ db, me, now }, item));
      if (newSession) newSessions += 1;
      if (outcome === "unknown_sender") {
        if (!result.unknownSenders.includes(item.from)) result.unknownSenders.push(item.from);
        continue;
      }
      if (outcome === "held") {
        result.heldForKeyChange += 1;
        continue;
      }
      result[outcome] += 1;
      try {
        await client.ackMessage(me, item.messageId);
      } catch {
        // The server will offer it again; it no longer decrypts, so the repeat is dropped.
      }
    }
  }

  if (newSessions > 0) {
    // Each new conversation used up one of our one-time keys.
    try {
      await topUpOneTimeKeys({ db, client, me });
    } catch {
      // Tried again at the next start or the next new conversation.
    }
  }
  return result;
}
