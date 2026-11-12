import * as crypto from "@messager/crypto";
import { decryptMessage, encryptMessage, type MessagePlaintext } from "@messager/protocol";
import type { ApiClient, InboxItem } from "./api/client.js";
import { canSendTo, type Contact } from "./contacts.js";
import type { StoredIdentity } from "./identity.js";
import { getContact } from "./storage/contact-store.js";
import {
  reserveSendCounter,
  storeIncomingIfNew,
  storeOutgoing,
  type HistoryMessage,
} from "./storage/message-store.js";

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

/** Encrypts a message to a contact's pinned key, sends it, and adds it to the local history. */
export async function sendChatMessage(params: SendParams): Promise<HistoryMessage> {
  const { db, client, me, contactId, text } = params;
  if (text.trim() === "") {
    throw new Error("Type a message first.");
  }
  if (crypto.utf8Encode(text).length > MAX_TEXT_BYTES) {
    throw new Error("That message is too long.");
  }
  const contact = await getContact(db, contactId);
  if (contact === null) {
    throw new Error("No such contact.");
  }
  if (!canSendTo(contact)) {
    throw new Error("Sending is blocked until you accept or reject this contact's changed key.");
  }

  const counter = await reserveSendCounter(db, contactId);
  const sentAt = (params.now ?? Date.now)();
  const envelope = encryptMessage({
    message: { counter, text, sentAt },
    fromUserId: me.userId,
    toUserId: contactId,
    myExchangePrivateKey: me.exchangePrivateKey,
    theirExchangePublicKey: contact.exchangePublicKey,
  });
  await client.sendMessage(me, envelope);
  return storeOutgoing(db, { contactId, direction: "out", text, sentAt, counter });
}

export interface ReceiveResult {
  /** New messages added to the history. */
  stored: number;
  /** Removed from the server without being shown: undecryptable, malformed, replayed or duplicate. */
  dropped: number;
  /** Senders who are not contacts. Their messages stay on the server until they are added. */
  unknownSenders: string[];
  /** Left on the server because the sender's key change has not been resolved yet. */
  heldForKeyChange: number;
}

function isUsablePlaintext(message: MessagePlaintext): boolean {
  return (
    Number.isSafeInteger(message.counter) &&
    message.counter >= 1 &&
    Number.isFinite(message.sentAt) &&
    crypto.utf8Encode(message.text).length <= MAX_TEXT_BYTES
  );
}

function tryDecrypt(me: StoredIdentity, contact: Contact, item: InboxItem): MessagePlaintext | null {
  try {
    // The associated data binds sender and recipient, so this only succeeds
    // if the message really was encrypted by this contact for this user.
    return decryptMessage({
      envelope: { v: 1, to: me.userId, nonce: item.nonce, ciphertext: item.ciphertext },
      fromUserId: contact.userId,
      toUserId: me.userId,
      myExchangePrivateKey: me.exchangePrivateKey,
      theirExchangePublicKey: contact.exchangePublicKey,
    });
  } catch {
    return null;
  }
}

/**
 * Fetches waiting messages, decrypts them, stores the new ones and
 * acknowledges them so the server deletes its copies.
 *
 * A message is acknowledged only after it is safely stored (or definitely
 * unusable). If the acknowledgement is lost, the server delivers it again
 * and the counter check discards the repeat.
 */
export async function receiveMessages(params: {
  db: IDBDatabase;
  client: ApiClient;
  me: StoredIdentity;
}): Promise<ReceiveResult> {
  const { db, client, me } = params;
  const result: ReceiveResult = { stored: 0, dropped: 0, unknownSenders: [], heldForKeyChange: 0 };

  for (const item of await client.fetchInbox(me)) {
    const contact = await getContact(db, item.from);
    if (contact === null) {
      if (!result.unknownSenders.includes(item.from)) {
        result.unknownSenders.push(item.from);
      }
      continue;
    }

    const plaintext = tryDecrypt(me, contact, item);
    if (plaintext === null && contact.changedExchangePublicKey !== null) {
      // It may be encrypted with the key the user has not decided about yet.
      result.heldForKeyChange += 1;
      continue;
    }

    let stored = false;
    if (plaintext !== null && isUsablePlaintext(plaintext)) {
      stored = await storeIncomingIfNew(db, {
        contactId: contact.userId,
        direction: "in",
        text: plaintext.text,
        sentAt: plaintext.sentAt,
        counter: plaintext.counter,
      });
    }
    if (stored) {
      result.stored += 1;
    } else {
      result.dropped += 1;
    }

    try {
      await client.ackMessage(me, item.messageId);
    } catch {
      // The server will offer it again; the counter check makes that harmless.
    }
  }
  return result;
}
