import { isValidContact, type Contact } from "../contacts.js";
import { CONTACTS_STORE, requestResult, transactionDone } from "./db.js";

function checked(value: unknown): Contact {
  if (!isValidContact(value)) {
    throw new Error("invalid contact in browser storage");
  }
  return value;
}

export async function getContact(db: IDBDatabase, userId: string): Promise<Contact | null> {
  const tx = db.transaction(CONTACTS_STORE, "readonly");
  const value: unknown = await requestResult(tx.objectStore(CONTACTS_STORE).get(userId));
  return value === undefined ? null : checked(value);
}

/** All contacts, oldest first. */
export async function listContacts(db: IDBDatabase): Promise<Contact[]> {
  const tx = db.transaction(CONTACTS_STORE, "readonly");
  const values: unknown[] = await requestResult(tx.objectStore(CONTACTS_STORE).getAll());
  return values.map(checked).sort((a, b) => a.addedAt - b.addedAt || a.userId.localeCompare(b.userId));
}

/** Stores a new contact; fails if one with the same userID exists, so pinned keys are never silently replaced. */
export async function putNewContact(db: IDBDatabase, contact: Contact): Promise<void> {
  const tx = db.transaction(CONTACTS_STORE, "readwrite");
  const done = transactionDone(tx);
  tx.objectStore(CONTACTS_STORE).add(checked(contact));
  try {
    await done;
  } catch {
    throw new Error("That contact has already been added.");
  }
}

/** Replaces an existing contact record. */
export async function putContact(db: IDBDatabase, contact: Contact): Promise<void> {
  const tx = db.transaction(CONTACTS_STORE, "readwrite");
  const store = tx.objectStore(CONTACTS_STORE);
  const done = transactionDone(tx);
  done.catch(() => undefined);
  const existing: unknown = await requestResult(store.get(contact.userId));
  if (existing === undefined) {
    tx.abort();
    throw new Error("No such contact.");
  }
  store.put(checked(contact));
  await done;
}
