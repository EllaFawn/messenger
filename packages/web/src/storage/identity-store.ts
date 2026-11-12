import { isValidIdentity, type StoredIdentity } from "../identity.js";
import { IDENTITY_STORE, requestResult, transactionDone } from "./db.js";

/** There is exactly one identity per browser profile, stored under this key. */
const SELF_KEY = "self";

/** Returns this device's identity, or null if none has been created. Throws if the stored record is damaged. */
export async function loadIdentity(db: IDBDatabase): Promise<StoredIdentity | null> {
  const tx = db.transaction(IDENTITY_STORE, "readonly");
  const value: unknown = await requestResult(tx.objectStore(IDENTITY_STORE).get(SELF_KEY));
  if (value === undefined) {
    return null;
  }
  if (!isValidIdentity(value)) {
    throw new Error("invalid identity in browser storage");
  }
  return value;
}

/**
 * Stores a newly created identity. Never replaces an existing one: losing
 * the old private keys would lock the user out of their account for good.
 */
export async function saveNewIdentity(db: IDBDatabase, identity: StoredIdentity): Promise<void> {
  if (!isValidIdentity(identity)) {
    throw new Error("invalid identity: refusing to store it");
  }
  const tx = db.transaction(IDENTITY_STORE, "readwrite");
  const store = tx.objectStore(IDENTITY_STORE);
  const done = transactionDone(tx);
  // Failures are reported by the awaits below; this stops a duplicate unhandled-rejection warning.
  done.catch(() => undefined);
  // Check and write share one transaction, so two tabs cannot both succeed.
  const existing: unknown = await requestResult(store.get(SELF_KEY));
  if (existing !== undefined) {
    tx.abort();
    await done.catch(() => undefined);
    throw new Error("an identity already exists in this browser");
  }
  store.add(identity, SELF_KEY);
  await done;
}

/** Records that the server accepted this identity's registration. */
export async function markRegistered(db: IDBDatabase, registeredAt: number): Promise<void> {
  const tx = db.transaction(IDENTITY_STORE, "readwrite");
  const store = tx.objectStore(IDENTITY_STORE);
  const done = transactionDone(tx);
  // Failures are reported by the awaits below; this stops a duplicate unhandled-rejection warning.
  done.catch(() => undefined);
  const existing: unknown = await requestResult(store.get(SELF_KEY));
  if (existing === undefined) {
    tx.abort();
    await done.catch(() => undefined);
    throw new Error("no identity to mark as registered");
  }
  if (!isValidIdentity(existing)) {
    tx.abort();
    await done.catch(() => undefined);
    throw new Error("invalid identity in browser storage");
  }
  store.put({ ...existing, registeredAt }, SELF_KEY);
  await done;
}
