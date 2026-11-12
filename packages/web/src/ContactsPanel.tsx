import { computeSafetyNumber } from "@messager/protocol";
import { useEffect, useState, type FormEvent } from "react";
import type { ApiClient } from "./api/client.js";
import {
  acceptChangedKey,
  addContact,
  canSendTo,
  MAX_CONTACT_NAME_LENGTH,
  refreshContactKeys,
  rejectChangedKey,
  type Contact,
} from "./contacts.js";
import type { StoredIdentity } from "./identity.js";
import { describeError } from "./session.js";
import { listContacts } from "./storage/contact-store.js";

interface ContactsPanelProps {
  db: IDBDatabase;
  client: ApiClient;
  me: StoredIdentity;
}

export function ContactsPanel({ db, client, me }: ContactsPanelProps) {
  const [contacts, setContacts] = useState<Contact[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function reload() {
    setContacts(await listContacts(db));
  }

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const stored = await listContacts(db);
      if (cancelled) return;
      setContacts(stored);
      // Ask the server for each contact's current keys; a difference from the pinned keys blocks sending.
      for (const contact of stored) {
        try {
          await refreshContactKeys(db, client, me, contact.userId);
        } catch {
          // Offline or server error: keep the pinned keys and carry on.
        }
      }
      if (!cancelled) setContacts(await listContacts(db));
    })().catch((caught: unknown) => {
      if (!cancelled) setError(describeError(caught));
    });
    return () => {
      cancelled = true;
    };
  }, [db, client, me]);

  async function run(action: () => Promise<unknown>) {
    setError(null);
    try {
      await action();
      await reload();
    } catch (caught) {
      setError(describeError(caught));
    }
  }

  return (
    <section>
      <h2>Contacts</h2>
      <AddContactForm
        onAdd={(userId, name) => run(() => addContact({ db, client, me, userId, name }))}
      />
      {error !== null && <p role="alert">{error}</p>}
      {contacts === null && <p>Loading…</p>}
      {contacts !== null && contacts.length === 0 && <p>No contacts yet.</p>}
      {contacts !== null && contacts.length > 0 && (
        <ul>
          {contacts.map((contact) => (
            <li key={contact.userId}>
              <ContactDetails
                contact={contact}
                me={me}
                onAccept={() => run(() => acceptChangedKey(db, contact.userId))}
                onReject={() => run(() => rejectChangedKey(db, contact.userId))}
              />
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function AddContactForm({ onAdd }: { onAdd: (userId: string, name: string) => Promise<void> }) {
  const [userId, setUserId] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    try {
      await onAdd(userId, name);
      setUserId("");
      setName("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={onSubmit}>
      <label>
        Their ID{" "}
        <input
          name="contact-id"
          autoComplete="off"
          spellCheck={false}
          size={46}
          value={userId}
          onChange={(event) => setUserId(event.target.value)}
          disabled={busy}
          required
        />
      </label>{" "}
      <label>
        Name (optional){" "}
        <input
          name="contact-name"
          autoComplete="off"
          maxLength={MAX_CONTACT_NAME_LENGTH}
          value={name}
          onChange={(event) => setName(event.target.value)}
          disabled={busy}
        />
      </label>{" "}
      <button type="submit" disabled={busy}>
        {busy ? "Adding…" : "Add contact"}
      </button>
    </form>
  );
}

interface ContactDetailsProps {
  contact: Contact;
  me: StoredIdentity;
  onAccept: () => void;
  onReject: () => void;
}

function ContactDetails({ contact, me, onAccept, onReject }: ContactDetailsProps) {
  const safetyNumber = computeSafetyNumber(me, contact);
  const changed = contact.changedExchangePublicKey;

  return (
    <>
      <p>
        <strong>{contact.name === "" ? "(no name)" : contact.name}</strong> <code>{contact.userId}</code>
      </p>
      <p>
        Safety number: <code>{safetyNumber}</code>
        <br />
        Compare this with what they see for you, in person or on a call. If it matches, nobody is in the
        middle.
      </p>
      {changed !== null && (
        <div role="alert">
          <p>
            <strong>Warning: the server is offering a different encryption key for this contact.</strong>{" "}
            Sending is blocked. This can mean someone is trying to intercept your messages. Only accept
            if the contact confirms, outside this app, that they changed their key.
          </p>
          <p>
            Safety number with the new key:{" "}
            <code>{computeSafetyNumber(me, { ...contact, exchangePublicKey: changed })}</code>
          </p>
          <button type="button" onClick={onAccept}>
            Accept the new key
          </button>{" "}
          <button type="button" onClick={onReject}>
            Keep the old key
          </button>
        </div>
      )}
      {canSendTo(contact) ? null : <p>Sending to this contact is blocked.</p>}
    </>
  );
}
