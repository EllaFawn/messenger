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

/**
 * True when the server refused a signed request. The server deliberately
 * gives one answer for every such failure, so this can mean it has no record
 * of this identity (for example after its database was reset) or that this
 * device's clock is more than a minute out.
 */
export function isRejectedByServer(error: unknown): boolean {
  return error instanceof ApiError && error.code === "unauthorized";
}

/**
 * Registers this browser's existing identity with the server again, with
 * the same keys, so contacts and history are kept. Used when the server has
 * lost its record of the account.
 *
 * Returns "already_registered" if the server does know the identity - in
 * which case the rejections have another cause, most likely the clock.
 */
export async function registerAgain(params: {
  db: IDBDatabase;
  client: ApiClient;
  inviteCode: string;
}): Promise<"registered" | "already_registered"> {
  const inviteCode = params.inviteCode.trim();
  if (inviteCode === "") {
    throw new Error("Enter the invite code.");
  }
  const identity = await loadIdentity(params.db);
  if (identity === null) {
    throw new Error("There is no identity in this browser to register.");
  }
  try {
    await params.client.register(identity, inviteCode);
    return "registered";
  } catch (error) {
    if (error instanceof ApiError && error.code === "already_registered") {
      return "already_registered";
    }
    throw error;
  }
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
        return "The server rejected the request. Either it does not recognise this identity, or this device's clock is wrong.";
      case "not_found":
        return "The server has no user with that ID.";
      default:
        return `The server reported a problem (${error.code}).`;
    }
  }
  if (error instanceof Error) {
    return error.message;
  }
  return "Something went wrong.";
}
