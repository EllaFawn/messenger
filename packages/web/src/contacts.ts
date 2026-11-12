import * as crypto from "@messager/crypto";
import { deriveUserId } from "@messager/protocol";
import type { ApiClient, PublicKeys } from "./api/client.js";
import type { StoredIdentity } from "./identity.js";
import { getContact, putContact, putNewContact } from "./storage/contact-store.js";

/** base64url of a 32-byte SHA-256 hash, no padding. */
export const USER_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;
export const MAX_CONTACT_NAME_LENGTH = 64;

/**
 * Someone the user talks to. Their keys are pinned when first added (trust on
 * first use) and are only ever replaced by an explicit decision of the user.
 */
export interface Contact {
  userId: string;
  /** A label chosen by the user; never sent to the server. */
  name: string;
  identityPublicKey: Uint8Array;
  /** The pinned key that messages are encrypted to. */
  exchangePublicKey: Uint8Array;
  /** Unix ms. */
  addedAt: number;
  /**
   * Set when the server has offered a different exchange key from the pinned
   * one. While this is set, sending to the contact is blocked.
   */
  changedExchangePublicKey: Uint8Array | null;
}

function isBytes(value: unknown, length: number): value is Uint8Array {
  return value instanceof Uint8Array && value.length === length;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

export function isValidContact(value: unknown): value is Contact {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    typeof v.userId === "string" &&
    typeof v.name === "string" &&
    v.name.length <= MAX_CONTACT_NAME_LENGTH &&
    isBytes(v.identityPublicKey, crypto.IDENTITY_PUBLIC_KEY_BYTES) &&
    isBytes(v.exchangePublicKey, crypto.EXCHANGE_KEY_BYTES) &&
    typeof v.addedAt === "number" &&
    (v.changedExchangePublicKey === null || isBytes(v.changedExchangePublicKey, crypto.EXCHANGE_KEY_BYTES)) &&
    deriveUserId(v.identityPublicKey) === v.userId
  );
}

/** True if messages may be sent to this contact: no unresolved key change. */
export function canSendTo(contact: Contact): boolean {
  return contact.changedExchangePublicKey === null;
}

export interface AddContactParams {
  db: IDBDatabase;
  client: ApiClient;
  me: StoredIdentity;
  userId: string;
  name?: string;
  now?: () => number;
}

/** Adds a contact by userID: fetches their public keys from the server and pins them. */
export async function addContact(params: AddContactParams): Promise<Contact> {
  const userId = params.userId.trim();
  const name = (params.name ?? "").trim();
  if (!USER_ID_PATTERN.test(userId)) {
    throw new Error("That is not a valid user ID. It should be 43 letters, digits, - or _.");
  }
  if (userId === params.me.userId) {
    throw new Error("That is your own ID.");
  }
  if (name.length > MAX_CONTACT_NAME_LENGTH) {
    throw new Error(`Names can be at most ${MAX_CONTACT_NAME_LENGTH} characters.`);
  }
  if ((await getContact(params.db, userId)) !== null) {
    throw new Error("That contact has already been added.");
  }

  const keys = await params.client.getPubkeys(params.me, userId);
  const contact: Contact = {
    userId,
    name,
    identityPublicKey: keys.identityPublicKey,
    exchangePublicKey: keys.exchangePublicKey,
    addedAt: (params.now ?? Date.now)(),
    changedExchangePublicKey: null,
  };
  await putNewContact(params.db, contact);
  return contact;
}

/**
 * Compares freshly fetched keys with the pinned ones. A different exchange
 * key is recorded on the contact, which blocks sending until the user
 * decides; the pinned key itself is never replaced here.
 */
export async function recordFetchedKeys(db: IDBDatabase, userId: string, fetched: PublicKeys): Promise<Contact> {
  const contact = await getContact(db, userId);
  if (contact === null) {
    throw new Error("No such contact.");
  }
  if (fetched.userId !== userId || !sameBytes(fetched.identityPublicKey, contact.identityPublicKey)) {
    // getPubkeys already guarantees this; refuse rather than trust the caller.
    throw new Error("Fetched keys do not belong to this contact.");
  }
  if (sameBytes(fetched.exchangePublicKey, contact.exchangePublicKey)) {
    // An earlier warning is kept: a server that showed a different key once is not cleared by behaving later.
    return contact;
  }
  const updated: Contact = { ...contact, changedExchangePublicKey: fetched.exchangePublicKey };
  await putContact(db, updated);
  return updated;
}

/** Asks the server for a contact's current keys and checks them against the pinned ones. */
export async function refreshContactKeys(
  db: IDBDatabase,
  client: ApiClient,
  me: StoredIdentity,
  userId: string,
): Promise<Contact> {
  return recordFetchedKeys(db, userId, await client.getPubkeys(me, userId));
}

/** The user has chosen to trust the changed key: pin it and unblock sending. */
export async function acceptChangedKey(db: IDBDatabase, userId: string): Promise<Contact> {
  const contact = await getContact(db, userId);
  if (contact === null) {
    throw new Error("No such contact.");
  }
  if (contact.changedExchangePublicKey === null) {
    return contact;
  }
  const updated: Contact = {
    ...contact,
    exchangePublicKey: contact.changedExchangePublicKey,
    changedExchangePublicKey: null,
  };
  await putContact(db, updated);
  return updated;
}

/** The user has chosen to keep the original key: drop the offered one and unblock sending. */
export async function rejectChangedKey(db: IDBDatabase, userId: string): Promise<Contact> {
  const contact = await getContact(db, userId);
  if (contact === null) {
    throw new Error("No such contact.");
  }
  if (contact.changedExchangePublicKey === null) {
    return contact;
  }
  const updated: Contact = { ...contact, changedExchangePublicKey: null };
  await putContact(db, updated);
  return updated;
}
