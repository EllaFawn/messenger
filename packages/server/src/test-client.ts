import * as crypto from "@messager/crypto";
import { deriveUserId, signExchangeKey, signRequest } from "@messager/protocol";
import type { Pool } from "./db/pool.js";

/** A throwaway user for tests: both keypairs plus the derived userID. */
export interface TestIdentity {
  userId: string;
  identity: crypto.KeyPair;
  exchange: crypto.KeyPair;
  /** The identity key's signature over the exchange public key. */
  exchangeSig: Uint8Array;
}

export function makeIdentity(): TestIdentity {
  const identity = crypto.generateIdentityKeyPair();
  const exchange = crypto.generateExchangeKeyPair();
  return {
    userId: deriveUserId(identity.publicKey),
    identity,
    exchange,
    exchangeSig: signExchangeKey(exchange.publicKey, identity.privateKey),
  };
}

export async function insertUser(pool: Pool, who: TestIdentity): Promise<void> {
  await pool.query(
    "INSERT INTO users (user_id, identity_pubkey, exchange_pubkey, exchange_sig) VALUES ($1, $2, $3, $4)",
    [
      who.userId,
      Buffer.from(who.identity.publicKey),
      Buffer.from(who.exchange.publicKey),
      Buffer.from(who.exchangeSig),
    ],
  );
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
