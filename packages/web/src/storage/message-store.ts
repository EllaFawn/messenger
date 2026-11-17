import { HISTORY_BY_CONTACT_INDEX, HISTORY_STORE, requestResult, transactionDone } from "./db.js";

/** One decrypted message in the local history. */
export interface HistoryMessage {
  /** Assigned by the browser database; gives a stable display order. */
  id: number;
  contactId: string;
  direction: "in" | "out";
  text: string;
  /** Unix ms, as stated by the sender. */
  sentAt: number;
}

export type NewHistoryMessage = Omit<HistoryMessage, "id">;

function isHistoryMessage(value: unknown): value is HistoryMessage {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.id === "number" &&
    typeof v.contactId === "string" &&
    (v.direction === "in" || v.direction === "out") &&
    typeof v.text === "string" &&
    typeof v.sentAt === "number"
  );
}

export async function storeOutgoing(db: IDBDatabase, message: NewHistoryMessage): Promise<HistoryMessage> {
  const tx = db.transaction(HISTORY_STORE, "readwrite");
  const done = transactionDone(tx);
  done.catch(() => undefined);
  const id = await requestResult(tx.objectStore(HISTORY_STORE).add(message));
  await done;
  return { ...message, id: id as number };
}

/** Within an open transaction: adds a message to the history. The caller awaits the transaction. */
export function addHistoryInTransaction(tx: IDBTransaction, message: NewHistoryMessage): void {
  tx.objectStore(HISTORY_STORE).add(message);
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
