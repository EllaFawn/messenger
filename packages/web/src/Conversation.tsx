import { useEffect, useState, type FormEvent } from "react";
import type { ApiClient } from "./api/client.js";
import { sendChatMessage } from "./chat.js";
import { canSendTo, type Contact } from "./contacts.js";
import type { StoredIdentity } from "./identity.js";
import { describeError } from "./session.js";
import { listMessages, type HistoryMessage } from "./storage/message-store.js";

interface ConversationProps {
  db: IDBDatabase;
  client: ApiClient;
  me: StoredIdentity;
  contact: Contact;
  /** Changes whenever new messages may have arrived, to trigger a reload. */
  inboxTick: number;
}

export function Conversation({ db, client, me, contact, inboxTick }: ConversationProps) {
  const [messages, setMessages] = useState<HistoryMessage[]>([]);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sentTick, setSentTick] = useState(0);

  useEffect(() => {
    let cancelled = false;
    listMessages(db, contact.userId).then(
      (loaded) => {
        if (!cancelled) setMessages(loaded);
      },
      (caught: unknown) => {
        if (!cancelled) setError(describeError(caught));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [db, contact.userId, inboxTick, sentTick]);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      await sendChatMessage({ db, client, me, contactId: contact.userId, text });
      setText("");
      setSentTick((tick) => tick + 1);
    } catch (caught) {
      setError(describeError(caught));
    } finally {
      setBusy(false);
    }
  }

  const blocked = !canSendTo(contact);

  return (
    <div>
      {messages.length === 0 ? (
        <p>No messages yet.</p>
      ) : (
        <ol>
          {messages.map((message) => (
            <li key={message.id}>
              <strong>{message.direction === "out" ? "You" : contact.name || "Them"}</strong>{" "}
              <small>{new Date(message.sentAt).toLocaleString()}</small>
              <br />
              {/* Rendered as a text node only: message content is never treated as HTML. */}
              {message.text}
            </li>
          ))}
        </ol>
      )}
      <form onSubmit={onSubmit}>
        <label>
          Message{" "}
          <input
            name="message"
            autoComplete="off"
            size={60}
            value={text}
            onChange={(event) => setText(event.target.value)}
            disabled={busy || blocked}
            required
          />
        </label>{" "}
        <button type="submit" disabled={busy || blocked}>
          {busy ? "Sending…" : "Send"}
        </button>
      </form>
      {error !== null && <p role="alert">{error}</p>}
    </div>
  );
}
