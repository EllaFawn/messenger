export const DATABASE_NAME = "messager";
export const IDENTITY_STORE = "identity";
export const CONTACTS_STORE = "contacts";
/** Decrypted message history. Exists only in this browser. */
export const HISTORY_STORE = "history";
export const HISTORY_BY_CONTACT_INDEX = "contactId";
/** The saved ratchet account (private keys and unused one-time keys), under one key. */
export const RATCHET_ACCOUNT_STORE = "ratchetAccount";
/** Saved ratchet sessions, keyed by [contactId, sessionId]. */
export const SESSIONS_STORE = "sessions";
export const SESSIONS_BY_CONTACT_INDEX = "contactId";

/** Removed in version 4: the ratchet rejects repeats itself. */
const LEGACY_COUNTERS_STORE = "counters";

/**
 * Schema version. To change the schema, add a step to `upgrade` and raise
 * this number; never edit a step that has already shipped.
 */
const DATABASE_VERSION = 4;

/** Runs the steps after `oldVersion`, up to and including `newVersion`. */
function upgrade(db: IDBDatabase, tx: IDBTransaction, oldVersion: number, newVersion: number): void {
  const step = (version: number) => oldVersion < version && newVersion >= version;
  if (step(1)) {
    db.createObjectStore(IDENTITY_STORE);
  }
  if (step(2)) {
    db.createObjectStore(CONTACTS_STORE, { keyPath: "userId" });
  }
  if (step(3)) {
    const history = db.createObjectStore(HISTORY_STORE, { keyPath: "id", autoIncrement: true });
    history.createIndex(HISTORY_BY_CONTACT_INDEX, "contactId");
    db.createObjectStore(LEGACY_COUNTERS_STORE, { keyPath: "contactId" });
  }
  if (step(4)) {
    // The move to forward secrecy (a clean break). The server forgot every
    // account, and contacts were pinned to static keys that no longer exist,
    // so contacts are removed; adding someone again with the same ID brings
    // back the history kept here. The identity key is kept, so the userID
    // stays the same; it gets a ratchet account and is registered again
    // (see ensureRatchetAccount).
    db.deleteObjectStore(LEGACY_COUNTERS_STORE);
    db.createObjectStore(RATCHET_ACCOUNT_STORE);
    const sessions = db.createObjectStore(SESSIONS_STORE, { keyPath: ["contactId", "sessionId"] });
    sessions.createIndex(SESSIONS_BY_CONTACT_INDEX, "contactId");
    if (oldVersion >= 2) {
      tx.objectStore(CONTACTS_STORE).clear();
    }
  }
}

/** Opens (and if needed creates) the browser database. The factory is injectable for tests. */
export function openDatabase(factory: IDBFactory = indexedDB, name = DATABASE_NAME): Promise<IDBDatabase> {
  return openDatabaseAt(factory, name, DATABASE_VERSION);
}

/** @internal For tests that need a database as an older version left it. */
export function openDatabaseAt(factory: IDBFactory, name: string, version: number): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = factory.open(name, version);
    request.onupgradeneeded = (event) => {
      upgrade(request.result, request.transaction!, event.oldVersion, event.newVersion ?? version);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("could not open the browser database"));
    request.onblocked = () => reject(new Error("the browser database is in use by another tab"));
  });
}

/** Resolves when the transaction has fully committed; rejects if it aborts. */
export function transactionDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("browser database transaction failed"));
    tx.onabort = () => reject(tx.error ?? new Error("browser database transaction aborted"));
  });
}

export function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("browser database request failed"));
  });
}
