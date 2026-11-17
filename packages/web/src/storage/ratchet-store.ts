import { RatchetAccount } from "@messager/ratchet";
import {
  RATCHET_ACCOUNT_STORE,
  requestResult,
  SESSIONS_BY_CONTACT_INDEX,
  SESSIONS_STORE,
  transactionDone,
} from "./db.js";
import { ACCOUNT_KEY } from "./identity-store.js";

/** Sessions kept per contact. Older ones are deleted; a message for one of them can no longer be read. */
export const MAX_SESSIONS_PER_CONTACT = 10;

/** One saved session with a contact. A contact can have several, e.g. if both sides started one at once. */
export interface SessionRecord {
  contactId: string;
  sessionId: string;
  /** The session, encrypted under the identity's pickle key. */
  pickle: string;
  /** Unix ms of the last message sent or received with it. Sending uses the most recent. */
  lastUsedAt: number;
}

function isSessionRecord(value: unknown): value is SessionRecord {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.contactId === "string" &&
    typeof v.sessionId === "string" &&
    typeof v.pickle === "string" &&
    typeof v.lastUsedAt === "number"
  );
}

/** The ratchet account. Throws if there is none or it cannot be decrypted. */
export async function loadAccount(db: IDBDatabase, pickleKey: Uint8Array): Promise<RatchetAccount> {
  const tx = db.transaction(RATCHET_ACCOUNT_STORE, "readonly");
  const value: unknown = await requestResult(tx.objectStore(RATCHET_ACCOUNT_STORE).get(ACCOUNT_KEY));
  if (typeof value !== "string") {
    throw new Error("no ratchet account in browser storage");
  }
  return RatchetAccount.restore(value, pickleKey);
}

export async function saveAccount(db: IDBDatabase, account: RatchetAccount, pickleKey: Uint8Array): Promise<void> {
  const tx = db.transaction(RATCHET_ACCOUNT_STORE, "readwrite");
  const done = transactionDone(tx);
  tx.objectStore(RATCHET_ACCOUNT_STORE).put(account.save(pickleKey), ACCOUNT_KEY);
  await done;
}

/** A contact's sessions, most recently used first. */
export async function listSessions(db: IDBDatabase, contactId: string): Promise<SessionRecord[]> {
  const tx = db.transaction(SESSIONS_STORE, "readonly");
  const values: unknown[] = await requestResult(
    tx.objectStore(SESSIONS_STORE).index(SESSIONS_BY_CONTACT_INDEX).getAll(contactId),
  );
  return values
    .map((value) => {
      if (!isSessionRecord(value)) {
        throw new Error("invalid session in browser storage");
      }
      return value;
    })
    .sort((a, b) => b.lastUsedAt - a.lastUsedAt);
}

/**
 * Within an open transaction: stores a session and deletes the contact's
 * oldest sessions beyond the limit. The caller awaits the transaction.
 */
export function putSessionInTransaction(tx: IDBTransaction, record: SessionRecord): void {
  const store = tx.objectStore(SESSIONS_STORE);
  store.put(record);
  const all = store.index(SESSIONS_BY_CONTACT_INDEX).getAll(record.contactId);
  all.onsuccess = () => {
    const others = (all.result as SessionRecord[])
      .filter((s) => s.sessionId !== record.sessionId)
      .sort((a, b) => b.lastUsedAt - a.lastUsedAt);
    for (const old of others.slice(MAX_SESSIONS_PER_CONTACT - 1)) {
      store.delete([old.contactId, old.sessionId]);
    }
  };
}

export async function saveSession(db: IDBDatabase, record: SessionRecord): Promise<void> {
  const tx = db.transaction(SESSIONS_STORE, "readwrite");
  const done = transactionDone(tx);
  putSessionInTransaction(tx, record);
  await done;
}
