import * as crypto from "@messager/crypto";
import { verifyRequest } from "@messager/protocol";
import type { Request, RequestHandler, Response } from "express";
import { getRawBody } from "../raw-body.js";
import type { Pool } from "../db/pool.js";
import { consumeNonce } from "./nonce-store.js";

/** A request is accepted only if its timestamp is within this many ms of the server clock. */
export const TIMESTAMP_WINDOW_MS = 60_000;

/** base64url of a 32-byte SHA-256 hash, no padding. */
export const USER_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const TIMESTAMP_PATTERN = /^\d{1,15}$/;
/** Standard base64 of exactly 16 bytes. */
const NONCE_PATTERN = /^[A-Za-z0-9+/]{22}==$/;
/** Standard base64 of exactly 64 bytes (an Ed25519 signature). */
const SIGNATURE_PATTERN = /^[A-Za-z0-9+/]{86}==$/;

export interface SignedHeaders {
  userId: string;
  /** Unix ms. */
  timestamp: number;
  /** The X-Nonce header value, exactly as sent (it is part of the signed string). */
  nonce: string;
  signature: Uint8Array;
}

export interface AuthDeps {
  pool: Pool;
  /** Clock in unix ms; injectable for tests. */
  now?: () => number;
}

/** Strictly validates the four auth values, wherever they were carried. Returns null if any is missing or malformed. */
export function parseSignedValues(values: {
  userId: string | null | undefined;
  timestamp: string | null | undefined;
  nonce: string | null | undefined;
  signature: string | null | undefined;
}): SignedHeaders | null {
  const { userId, timestamp, nonce, signature } = values;
  if (
    userId == null ||
    timestamp == null ||
    nonce == null ||
    signature == null ||
    !USER_ID_PATTERN.test(userId) ||
    !TIMESTAMP_PATTERN.test(timestamp) ||
    !NONCE_PATTERN.test(nonce) ||
    !SIGNATURE_PATTERN.test(signature)
  ) {
    return null;
  }
  return {
    userId,
    timestamp: Number(timestamp),
    nonce,
    signature: crypto.fromBase64(signature),
  };
}

/** Reads and strictly validates the four auth headers. Returns null if any is missing or malformed. */
export function parseSignedHeaders(req: Request): SignedHeaders | null {
  return parseSignedValues({
    userId: req.get("x-user-id"),
    timestamp: req.get("x-timestamp"),
    nonce: req.get("x-nonce"),
    signature: req.get("x-signature"),
  });
}

/** What was signed, independent of how the request arrived. */
export interface SignedTarget {
  method: string;
  path: string;
  rawBody: Uint8Array;
}

/**
 * Stateless half of the check: timestamp within the window, then the Ed25519
 * signature over the canonical string (method, path + query, body hash,
 * timestamp, nonce). Writes nothing.
 */
export function verifySignature(
  req: Request,
  headers: SignedHeaders,
  identityPublicKey: Uint8Array,
  deps: AuthDeps,
): Promise<boolean> {
  return verifySignatureOver(
    { method: req.method, path: req.originalUrl, rawBody: new Uint8Array(getRawBody(req)) },
    headers,
    identityPublicKey,
    deps,
  );
}

/** The same check for anything that is not an Express request, such as a WebSocket upgrade. */
export async function verifySignatureOver(
  target: SignedTarget,
  headers: SignedHeaders,
  identityPublicKey: Uint8Array,
  deps: AuthDeps,
): Promise<boolean> {
  const now = (deps.now ?? Date.now)();
  if (Math.abs(now - headers.timestamp) > TIMESTAMP_WINDOW_MS) {
    return false;
  }

  await crypto.ready;
  try {
    return verifyRequest(
      {
        ...target,
        timestamp: headers.timestamp,
        nonce: headers.nonce,
      },
      identityPublicKey,
      headers.signature,
    );
  } catch {
    return false;
  }
}

/** Records the request's nonce. Returns false if it was already used (a replay). */
export function recordNonce(headers: SignedHeaders, deps: AuthDeps): Promise<boolean> {
  return consumeNonce(deps.pool, {
    nonce: headers.nonce,
    userId: headers.userId,
    // The request stops being acceptable once its window closes; keep the nonce slightly longer.
    expiresAt: new Date(headers.timestamp + TIMESTAMP_WINDOW_MS + 1000),
  });
}

/**
 * Full check against a known identity public key: timestamp, signature,
 * then nonce. The nonce is stored only after the signature verifies, so a
 * caller without a valid key cannot cause database writes.
 */
export async function verifySignedRequest(
  req: Request,
  headers: SignedHeaders,
  identityPublicKey: Uint8Array,
  deps: AuthDeps,
): Promise<boolean> {
  return (await verifySignature(req, headers, identityPublicKey, deps)) && (await recordNonce(headers, deps));
}

/** The single response for every authentication failure, so callers learn nothing about which check failed. */
export function unauthorized(res: Response): void {
  res.status(401).json({ error: "unauthorized" });
}

/**
 * Express middleware: only lets a request through if it is signed by the
 * registered identity key of the user named in X-User-ID.
 */
export function requireSignedRequest(deps: AuthDeps): RequestHandler {
  return async (req, res, next) => {
    const headers = parseSignedHeaders(req);
    if (headers === null) {
      unauthorized(res);
      return;
    }

    const user = await deps.pool.query<{ identity_pubkey: Buffer }>(
      "SELECT identity_pubkey FROM users WHERE user_id = $1",
      [headers.userId],
    );
    const row = user.rows[0];
    if (row === undefined) {
      unauthorized(res);
      return;
    }

    if (!(await verifySignedRequest(req, headers, new Uint8Array(row.identity_pubkey), deps))) {
      unauthorized(res);
      return;
    }

    res.locals.userId = headers.userId;
    next();
  };
}

/** The verified caller. Only valid in handlers that run after requireSignedRequest. */
export function authenticatedUserId(res: Response): string {
  const userId: unknown = res.locals.userId;
  if (typeof userId !== "string") {
    throw new Error("authenticatedUserId called on a route without requireSignedRequest");
  }
  return userId;
}
