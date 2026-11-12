import { ApiError, type ApiClient } from "./api/client.js";
import { createIdentity, type StoredIdentity } from "./identity.js";
import { loadIdentity, markRegistered, saveNewIdentity } from "./storage/identity-store.js";

/** Where this browser is in the sign-up process. */
export type Session =
  | { status: "none" }
  /** Keys exist in this browser but the server has not accepted them yet. */
  | { status: "unregistered"; identity: StoredIdentity }
  | { status: "registered"; identity: StoredIdentity };

export async function loadSession(db: IDBDatabase): Promise<Session> {
  const identity = await loadIdentity(db);
  if (identity === null) {
    return { status: "none" };
  }
  return { status: identity.registeredAt === null ? "unregistered" : "registered", identity };
}

export interface SignUpParams {
  db: IDBDatabase;
  client: ApiClient;
  inviteCode: string;
  now?: () => number;
}

/**
 * Creates this browser's identity if it has none, then registers it.
 *
 * The keys are saved before the server is contacted, and a failed attempt
 * keeps them, so retrying never produces a second identity.
 */
export async function signUp(params: SignUpParams): Promise<Session> {
  const now = params.now ?? Date.now;
  const inviteCode = params.inviteCode.trim();
  if (inviteCode === "") {
    throw new Error("Enter the invite code.");
  }

  let identity = await loadIdentity(params.db);
  if (identity === null) {
    identity = createIdentity(now());
    await saveNewIdentity(params.db, identity);
  }
  if (identity.registeredAt !== null) {
    return { status: "registered", identity };
  }

  try {
    await params.client.register(identity, inviteCode);
  } catch (error) {
    // The userID is derived from our identity key and the server only stores
    // it after a valid signature from that key, so an existing registration
    // can only be ours (for example, an earlier reply that never arrived).
    if (!(error instanceof ApiError && error.code === "already_registered")) {
      throw error;
    }
  }

  const registeredAt = now();
  await markRegistered(params.db, registeredAt);
  return { status: "registered", identity: { ...identity, registeredAt } };
}

/** A short message for the screen. Never includes raw server output. */
export function describeError(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.code) {
      case "invalid_invite":
        return "That invite code was not accepted.";
      case "network_error":
        return "Could not reach the server. Check it is running and try again.";
      case "unauthorized":
        return "The server rejected the request. Check this device's clock is correct and try again.";
      default:
        return `The server reported a problem (${error.code}).`;
    }
  }
  if (error instanceof Error) {
    return error.message;
  }
  return "Something went wrong.";
}
