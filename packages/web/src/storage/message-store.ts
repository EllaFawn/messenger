import {
  COUNTERS_STORE,
  HISTORY_BY_CONTACT_INDEX,
  HISTORY_STORE,
  requestResult,
  transactionDone,
} from "./db.js";

/** One decrypted message in the local history. */
export interface HistoryMessage {
  /** Assigned by the browser database; gives a stable display order. */
  id: number;
  contactId: string;
  direction: "in" | "out";
  text: string;
  /** Unix ms, as stated by the sender. */
  sentAt: number;
  /** The sender's counter for this direction. */
  counter: number;
}

export type NewHistoryMessage = Omit<HistoryMessage, "id">;

interface Counters {
  contactId: string;
  /** The counter the next outgoing message will use. */
  nextSend: number;
  /** The highest counter accepted from this contact. */
  lastReceived: number;
}

function isCounters(value: unknown): value is Counters {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.contactId === "string" &&
    Number.isSafeInteger(v.nextSend) &&
    Number.isSafeInteger(v.lastReceived) &&
    (v.nextSend as number) >= 1 &&
    (v.lastReceived as number) >= 0
  );
}

function isHistoryMessage(value: unknown): value is HistoryMessage {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.id === "number" &&
    typeof v.contactId === "string" &&
    (v.direction === "in" || v.direction === "out") &&
    typeof v.text === "string" &&
    typeof v.sentAt === "number" &&
    typeof v.counter === "number"
  );
}

async function readCounters(store: IDBObjectStore, contactId: string): Promise<Counters> {
  const value: unknown = await requestResult(store.get(contactId));
  if (value === undefined) {
    return { contactId, nextSend: 1, lastReceived: 0 };
  }
  if (!isCounters(value)) {
    throw new Error("invalid message counters in browser storage");
  }
  return value;
}

/**
 * Takes the next send counter for a contact and records that it is used, in
 * one transaction. A counter is never handed out twice, even across tabs or
 * if the send then fails; gaps are harmless because the recipient only
 * requires counters to increase.
 */
export async function reserveSendCounter(db: IDBDatabase, contactId: string): Promise<number> {
  const tx = db.transaction(COUNTERS_STORE, "readwrite");
  const store = tx.objectStore(COUNTERS_STORE);
  const done = transactionDone(tx);
  done.catch(() => undefined);
  const counters = await readCounters(store, contactId);
  store.put({ ...counters, nextSend: counters.nextSend + 1 });
  await done;
  return counters.nextSend;
}

export async function storeOutgoing(db: IDBDatabase, message: NewHistoryMessage): Promise<HistoryMessage> {
  const tx = db.transaction(HISTORY_STORE, "readwrite");
  const done = transactionDone(tx);
  done.catch(() => undefined);
  const id = await requestResult(tx.objectStore(HISTORY_STORE).add(message));
  await done;
  return { ...message, id: id as number };
}

/**
 * Stores a received message only if its counter is higher than every counter
 * already accepted from that contact, and records the new high-water mark in
 * the same transaction. Returns false for a replayed, reordered or duplicate
 * message, which is not stored.
 */
export async function storeIncomingIfNew(db: IDBDatabase, message: NewHistoryMessage): Promise<boolean> {
  const tx = db.transaction([HISTORY_STORE, COUNTERS_STORE], "readwrite");
  const countersStore = tx.objectStore(COUNTERS_STORE);
  const done = transactionDone(tx);
  done.catch(() => undefined);
  const counters = await readCounters(countersStore, message.contactId);
  if (message.counter <= counters.lastReceived) {
    await done;
    return false;
  }
  tx.objectStore(HISTORY_STORE).add(message);
  countersStore.put({ ...counters, lastReceived: message.counter });
  await done;
  return true;
}

/** The conversation with one contact, in the order messages were stored. */
export async function listMessages(db: IDBDatabase, contactId: string): Promise<HistoryMessage[]> {
  const tx = db.transaction(HISTORY_STORE, "readonly");
  const values: unknown[] = await requestResult(
    tx.objectStore(HISTORY_STORE).index(HISTORY_BY_CONTACT_INDEX).getAll(contactId),
  );
  return values
    .map((value) => {
      if (!isHistoryMessage(value)) {
        throw new Error("invalid message in browser storage");
      }
      return value;
    })
    .sort((a, b) => a.id - b.id);
}
