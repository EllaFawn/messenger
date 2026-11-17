import * as crypto from "@messager/crypto";
import { deriveUserId, signOneTimeKey, signRatchetKey, signRequest } from "@messager/protocol";
import type { Pool } from "./db/pool.js";
import { createInvite } from "./invites.js";

/** A throwaway user for tests: the identity keypair, a ratchet key and the derived userID. */
export interface TestIdentity {
  userId: string;
  identity: crypto.KeyPair;
  /**
   * A stand-in long-term ratchet public key. The server never does ratchet
   * maths, so 32 random bytes with a valid signature are all it can tell apart.
   */
  ratchetKey: Uint8Array;
  ratchetSig: Uint8Array;
}

export interface TestOneTimeKey {
  id: string;
  key: Uint8Array;
  sig: Uint8Array;
}

/** Signed one-time keys for `who`, as their client would upload them. */
export function makeOneTimeKeys(who: TestIdentity, count: number): TestOneTimeKey[] {
  return Array.from({ length: count }, () => {
    const key = crypto.randomBytes(32);
    return {
      id: crypto.toBase64Url(crypto.randomBytes(6)),
      key,
      sig: signOneTimeKey(who.ratchetKey, key, who.identity.privateKey),
    };
  });
}

/** The JSON form of a one-time key in request and response bodies. */
export function oneTimeKeyJson(key: TestOneTimeKey): { id: string; key: string; sig: string } {
  return { id: key.id, key: crypto.toBase64(key.key), sig: crypto.toBase64(key.sig) };
}

export function makeIdentity(): TestIdentity {
  const identity = crypto.generateIdentityKeyPair();
  const ratchetKey = crypto.randomBytes(32);
  return {
    ratchetKey,
    ratchetSig: signRatchetKey(ratchetKey, identity.privateKey),
    userId: deriveUserId(identity.publicKey),
    identity,
  };
}

export async function insertUser(pool: Pool, who: TestIdentity): Promise<void> {
  await pool.query(
    "INSERT INTO users (user_id, identity_pubkey, ratchet_pubkey, ratchet_sig) VALUES ($1, $2, $3, $4)",
    [who.userId, Buffer.from(who.identity.publicKey), Buffer.from(who.ratchetKey), Buffer.from(who.ratchetSig)],
  );
}

/** A fresh single-use invite code, valid for an hour. */
export async function issueInvite(pool: Pool): Promise<string> {
  return (await createInvite(pool, { note: "test", expiresAt: new Date(Date.now() + 3_600_000) })).code;
}

export interface SignedFetchOptions {
  method?: string;
  /** Raw JSON text to send. */
  body?: string;
  /** Unix ms used for X-Timestamp and the signature. */
  timestamp: number;
  /** Overrides for building deliberately bad requests. */
  nonce?: string;
  signAs?: { method?: string; path?: string; body?: string };
  headers?: Record<string, string | undefined>;
}

/** Sends a request signed the way a real client would sign it. */
export function signedFetch(
  baseUrl: string,
  who: TestIdentity,
  path: string,
  options: SignedFetchOptions,
): Promise<Response> {
  const method = options.method ?? "GET";
  const nonce = options.nonce ?? crypto.toBase64(crypto.randomBytes(16));
  const signature = signRequest(
    {
      method: options.signAs?.method ?? method,
      path: options.signAs?.path ?? path,
      rawBody: crypto.utf8Encode(options.signAs?.body ?? options.body ?? ""),
      timestamp: options.timestamp,
      nonce,
    },
    who.identity.privateKey,
  );

  const headers: Record<string, string> = {
    "x-user-id": who.userId,
    "x-timestamp": String(options.timestamp),
    "x-nonce": nonce,
    "x-signature": crypto.toBase64(signature),
  };
  if (options.body !== undefined) {
    headers["content-type"] = "application/json";
  }
  for (const [name, value] of Object.entries(options.headers ?? {})) {
    if (value === undefined) {
      delete headers[name];
    } else {
      headers[name] = value;
    }
  }

  return fetch(baseUrl + path, { method, headers, body: options.body });
}

export interface SignedWsOptions {
  /** Unix ms; defaults to now. */
  timestamp?: number;
  nonce?: string;
  /** Sign a different path than the one connected to. */
  signPath?: string;
  /** Replace or remove (undefined) individual query parameters after signing. */
  params?: Record<string, string | undefined>;
  path?: string;
}

/** Builds the URL a real client would use to open the push connection. */
export function signedWsUrl(baseUrl: string, who: TestIdentity, options: SignedWsOptions = {}): string {
  const timestamp = options.timestamp ?? Date.now();
  const nonce = options.nonce ?? crypto.toBase64(crypto.randomBytes(16));
  const signature = signRequest(
    { method: "GET", path: options.signPath ?? "/ws", rawBody: new Uint8Array(0), timestamp, nonce },
    who.identity.privateKey,
  );
  const params = new URLSearchParams({
    user: who.userId,
    ts: String(timestamp),
    nonce,
    sig: crypto.toBase64(signature),
  });
  for (const [name, value] of Object.entries(options.params ?? {})) {
    if (value === undefined) params.delete(name);
    else params.set(name, value);
  }
  return `${baseUrl.replace(/^http/, "ws")}${options.path ?? "/ws"}?${params.toString()}`;
}
