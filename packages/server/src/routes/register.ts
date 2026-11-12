import { createHash, timingSafeEqual } from "node:crypto";
import * as crypto from "@messager/crypto";
import { deriveUserId, verifyExchangeKey } from "@messager/protocol";
import { Router } from "express";
import {
  parseSignedHeaders,
  recordNonce,
  unauthorized,
  USER_ID_PATTERN,
  verifySignature,
  type AuthDeps,
} from "../auth/signed-request.js";

export interface RegisterDeps extends AuthDeps {
  /** M1: single static invite code. */
  inviteCode: string;
}

/** Standard base64 of exactly 32 bytes. */
const KEY_PATTERN = /^[A-Za-z0-9+/]{43}=$/;
/** Standard base64 of exactly 64 bytes (an Ed25519 signature). */
const SIGNATURE_PATTERN = /^[A-Za-z0-9+/]{86}==$/;
const MAX_INVITE_CODE_LENGTH = 256;

interface RegistrationBody {
  userID: string;
  identity_pubkey: string;
  exchange_pubkey: string;
  exchange_sig: string;
  inviteCode: string;
}

function parseRegistrationBody(body: unknown): RegistrationBody | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return null;
  }
  const { userID, identity_pubkey, exchange_pubkey, exchange_sig, inviteCode } = body as Record<string, unknown>;
  if (
    typeof userID !== "string" ||
    typeof identity_pubkey !== "string" ||
    typeof exchange_pubkey !== "string" ||
    typeof exchange_sig !== "string" ||
    typeof inviteCode !== "string" ||
    !USER_ID_PATTERN.test(userID) ||
    !KEY_PATTERN.test(identity_pubkey) ||
    !KEY_PATTERN.test(exchange_pubkey) ||
    !SIGNATURE_PATTERN.test(exchange_sig) ||
    inviteCode.length === 0 ||
    inviteCode.length > MAX_INVITE_CODE_LENGTH
  ) {
    return null;
  }
  return { userID, identity_pubkey, exchange_pubkey, exchange_sig, inviteCode };
}

/** Compares hashes in constant time so response timing does not reveal how much of the code matched. */
function inviteCodeMatches(given: string, expected: string): boolean {
  const a = createHash("sha256").update(given).digest();
  const b = createHash("sha256").update(expected).digest();
  return timingSafeEqual(a, b);
}

export function registerRouter(deps: RegisterDeps): Router {
  const router = Router();

  router.post("/register", async (req, res) => {
    const body = parseRegistrationBody(req.body);
    if (body === null) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }

    await crypto.ready;
    const identityPublicKey = crypto.fromBase64(body.identity_pubkey);
    const exchangePublicKey = crypto.fromBase64(body.exchange_pubkey);
    const exchangeSignature = crypto.fromBase64(body.exchange_sig);

    // 1. The userID must be derived from the identity key being registered,
    //    and that identity key must vouch for the exchange key. Other clients
    //    check the same signature, so a bad one is refused rather than stored.
    if (
      deriveUserId(identityPublicKey) !== body.userID ||
      !verifyExchangeKey(exchangePublicKey, exchangeSignature, identityPublicKey)
    ) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }

    // 2. Proof of possession: the request must be signed by that same key.
    const headers = parseSignedHeaders(req);
    if (
      headers === null ||
      headers.userId !== body.userID ||
      !(await verifySignature(req, headers, identityPublicKey, deps))
    ) {
      unauthorized(res);
      return;
    }

    // 3. Invite code. Checked before anything is written, because anyone can
    //    make a key and sign with it - only the invite code is scarce.
    if (!inviteCodeMatches(body.inviteCode, deps.inviteCode)) {
      res.status(403).json({ error: "invalid_invite" });
      return;
    }

    // 4. Replay check.
    if (!(await recordNonce(headers, deps))) {
      unauthorized(res);
      return;
    }

    // Existing users are never overwritten, so stored keys cannot be replaced.
    const inserted = await deps.pool.query(
      `INSERT INTO users (user_id, identity_pubkey, exchange_pubkey, exchange_sig)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id) DO NOTHING`,
      [
        body.userID,
        Buffer.from(identityPublicKey),
        Buffer.from(exchangePublicKey),
        Buffer.from(exchangeSignature),
      ],
    );
    if (inserted.rowCount !== 1) {
      res.status(409).json({ error: "already_registered" });
      return;
    }

    res.status(201).json({ userID: body.userID });
  });

  return router;
}
