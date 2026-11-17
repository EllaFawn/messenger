import * as crypto from "@messager/crypto";
import { deriveUserId, verifyExchangeKey, verifyRatchetKey } from "@messager/protocol";
import { Router } from "express";
import {
  parseSignedHeaders,
  recordNonce,
  unauthorized,
  USER_ID_PATTERN,
  verifySignature,
  type AuthDeps,
} from "../auth/signed-request.js";
import { limitByIp } from "../limits.js";
import { claimInvite, hashInviteCode, isInviteUsable } from "../invites.js";


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
  /** Optional until the static exchange key is retired: the long-term ratchet key and its signature. */
  ratchet_pubkey: string | null;
  ratchet_sig: string | null;
  inviteCode: string;
}

function parseRegistrationBody(body: unknown): RegistrationBody | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return null;
  }
  const { userID, identity_pubkey, exchange_pubkey, exchange_sig, ratchet_pubkey, ratchet_sig, inviteCode } =
    body as Record<string, unknown>;
  // Both or neither.
  const hasRatchet = ratchet_pubkey !== undefined || ratchet_sig !== undefined;
  if (
    hasRatchet &&
    (typeof ratchet_pubkey !== "string" ||
      typeof ratchet_sig !== "string" ||
      !KEY_PATTERN.test(ratchet_pubkey) ||
      !SIGNATURE_PATTERN.test(ratchet_sig))
  ) {
    return null;
  }
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
  return {
    userID,
    identity_pubkey,
    exchange_pubkey,
    exchange_sig,
    ratchet_pubkey: hasRatchet ? (ratchet_pubkey as string) : null,
    ratchet_sig: hasRatchet ? (ratchet_sig as string) : null,
    inviteCode,
  };
}

export function registerRouter(deps: AuthDeps): Router {
  const router = Router();

  router.post("/register", limitByIp((l) => l.register, deps), async (req, res) => {
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
    const ratchetPublicKey = body.ratchet_pubkey === null ? null : crypto.fromBase64(body.ratchet_pubkey);
    const ratchetSignature = body.ratchet_sig === null ? null : crypto.fromBase64(body.ratchet_sig);
    if (
      deriveUserId(identityPublicKey) !== body.userID ||
      !verifyExchangeKey(exchangePublicKey, exchangeSignature, identityPublicKey) ||
      (ratchetPublicKey !== null &&
        ratchetSignature !== null &&
        !verifyRatchetKey(ratchetPublicKey, ratchetSignature, identityPublicKey))
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

    // 3. Invite code. Checked (read-only) before anything is written, because
    //    anyone can make a key and sign with it - only an invite is scarce.
    //    Unknown, used and expired codes are indistinguishable to the caller.
    const inviteHash = hashInviteCode(body.inviteCode);
    if (!(await isInviteUsable(deps.pool, inviteHash))) {
      res.status(403).json({ error: "invalid_invite" });
      return;
    }

    // 4. Replay check.
    if (!(await recordNonce(headers, deps))) {
      unauthorized(res);
      return;
    }

    // 5. Create the account and use up the invite together: either both
    //    happen or neither does.
    const client = await deps.pool.connect();
    try {
      await client.query("BEGIN");

      // Existing users are never overwritten, so stored keys cannot be replaced.
      const inserted = await client.query(
        `INSERT INTO users (user_id, identity_pubkey, exchange_pubkey, exchange_sig, ratchet_pubkey, ratchet_sig)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (user_id) DO NOTHING`,
        [
          body.userID,
          Buffer.from(identityPublicKey),
          Buffer.from(exchangePublicKey),
          Buffer.from(exchangeSignature),
          ratchetPublicKey === null ? null : Buffer.from(ratchetPublicKey),
          ratchetSignature === null ? null : Buffer.from(ratchetSignature),
        ],
      );
      if (inserted.rowCount !== 1) {
        await client.query("ROLLBACK");
        res.status(409).json({ error: "already_registered" });
        return;
      }

      // Someone else may have used the invite since the check above. The
      // claim is a single atomic UPDATE, so only one registration can win.
      if (!(await claimInvite(client, inviteHash, body.userID))) {
        await client.query("ROLLBACK");
        res.status(403).json({ error: "invalid_invite" });
        return;
      }

      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }

    res.status(201).json({ userID: body.userID });
  });

  return router;
}
