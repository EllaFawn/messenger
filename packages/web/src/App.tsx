import * as crypto from "@messager/crypto";
import { useEffect, useState, type FormEvent } from "react";
import { createApiClient } from "./api/client.js";
import { describeError, loadSession, signUp, type Session } from "./session.js";
import { openDatabase } from "./storage/db.js";

const client = createApiClient();

type AppState =
  | { phase: "loading" }
  | { phase: "failed"; message: string }
  | { phase: "ready"; db: IDBDatabase; session: Session };

/** Functional screens only for now; visual design comes at the end of the project. */
export function App() {
  const [state, setState] = useState<AppState>({ phase: "loading" });

  useEffect(() => {
    let cancelled = false;
    let opened: IDBDatabase | undefined;
    (async () => {
      await crypto.ready;
      const db = await openDatabase();
      opened = db;
      const session = await loadSession(db);
      if (cancelled) {
        db.close();
        return;
      }
      setState({ phase: "ready", db, session });
    })().catch((error: unknown) => {
      if (!cancelled) setState({ phase: "failed", message: describeError(error) });
    });
    return () => {
      cancelled = true;
      opened?.close();
    };
  }, []);

  return (
    <main>
      <h1>Messager</h1>
      <p>Prototype. No security review performed. Not for sensitive real-world use.</p>
      {state.phase === "loading" && <p>Loading…</p>}
      {state.phase === "failed" && <p role="alert">Could not start: {state.message}</p>}
      {state.phase === "ready" && state.session.status !== "registered" && (
        <SignUpForm
          db={state.db}
          session={state.session}
          onSession={(session) => setState({ phase: "ready", db: state.db, session })}
        />
      )}
      {state.phase === "ready" && state.session.status === "registered" && (
        <section>
          <h2>Your identity</h2>
          <p>You are registered. Give this ID to the person you want to talk to:</p>
          <p>
            <code>{state.session.identity.userId}</code>
          </p>
          <p>
            Your keys are stored only in this browser. Clearing this site's data deletes them, and they
            cannot be recovered.
          </p>
        </section>
      )}
    </main>
  );
}

interface SignUpFormProps {
  db: IDBDatabase;
  session: Session;
  onSession: (session: Session) => void;
}

function SignUpForm({ db, session, onSession }: SignUpFormProps) {
  const [inviteCode, setInviteCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      onSession(await signUp({ db, client, inviteCode }));
    } catch (caught) {
      setError(describeError(caught));
      // A failed attempt may still have created the keys; show the up-to-date state.
      try {
        onSession(await loadSession(db));
      } catch {
        // Keep the first error on screen.
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h2>{session.status === "none" ? "Create your identity" : "Finish registering"}</h2>
      {session.status === "unregistered" && (
        <p>
          Keys already exist in this browser (ID <code>{session.identity.userId}</code>) but the server
          has not accepted them yet. Enter the invite code to try again.
        </p>
      )}
      <form onSubmit={onSubmit}>
        <label>
          Invite code{" "}
          <input
            type="password"
            name="invite-code"
            autoComplete="off"
            value={inviteCode}
            onChange={(event) => setInviteCode(event.target.value)}
            disabled={busy}
            required
          />
        </label>{" "}
        <button type="submit" disabled={busy}>
          {busy ? "Working…" : session.status === "none" ? "Create identity and register" : "Register"}
        </button>
      </form>
      {error !== null && <p role="alert">{error}</p>}
    </section>
  );
}
