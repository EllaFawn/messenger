import * as crypto from "@messager/crypto";
import { deriveUserId, signRequest } from "@messager/protocol";
import type { Pool } from "./db/pool.js";

/** A throwaway user for tests: both keypairs plus the derived userID. */
export interface TestIdentity {
  userId: string;
  identity: crypto.KeyPair;
  exchange: crypto.KeyPair;
}

export function makeIdentity(): TestIdentity {
  const identity = crypto.generateIdentityKeyPair();
  return {
    userId: deriveUserId(identity.publicKey),
    identity,
    exchange: crypto.generateExchangeKeyPair(),
  };
}

export async function insertUser(pool: Pool, who: TestIdentity): Promise<void> {
  await pool.query("INSERT INTO users (user_id, identity_pubkey, exchange_pubkey) VALUES ($1, $2, $3)", [
    who.userId,
    Buffer.from(who.identity.publicKey),
    Buffer.from(who.exchange.publicKey),
  ]);
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
