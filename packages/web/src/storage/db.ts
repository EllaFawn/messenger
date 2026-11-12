export const DATABASE_NAME = "messager";
export const IDENTITY_STORE = "identity";

/**
 * Schema version. To change the schema, add a step to `upgrade` and raise
 * this number; never edit a step that has already shipped.
 */
const DATABASE_VERSION = 1;

function upgrade(db: IDBDatabase, oldVersion: number): void {
  if (oldVersion < 1) {
    db.createObjectStore(IDENTITY_STORE);
  }
}

/** Opens (and if needed creates) the browser database. The factory is injectable for tests. */
export function openDatabase(factory: IDBFactory = indexedDB, name = DATABASE_NAME): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = factory.open(name, DATABASE_VERSION);
    request.onupgradeneeded = (event) => {
      upgrade(request.result, event.oldVersion);
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
