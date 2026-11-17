import { Router } from "express";
import { limitByCaller } from "../limits.js";
import { requireSignedRequest, USER_ID_PATTERN, type AuthDeps } from "../auth/signed-request.js";

export function usersRouter(deps: AuthDeps): Router {
  const router = Router();

  // Public data only. Callers verify the keys against the userID, pin them, and warn if they ever change.
  router.get(
    "/users/:userID/pubkeys",
    requireSignedRequest(deps),
    limitByCaller((l) => l.keyLookup, deps),
    async (req, res) => {
    const userId = req.params.userID;
    if (typeof userId !== "string" || !USER_ID_PATTERN.test(userId)) {
      res.status(404).json({ error: "not_found" });
      return;
    }

    const result = await deps.pool.query<{
      identity_pubkey: Buffer;
      exchange_pubkey: Buffer;
      exchange_sig: Buffer;
      ratchet_pubkey: Buffer | null;
      ratchet_sig: Buffer | null;
      key_epoch: number;
    }>(
      `SELECT identity_pubkey, exchange_pubkey, exchange_sig, ratchet_pubkey, ratchet_sig, key_epoch
       FROM users WHERE user_id = $1`,
      [userId],
    );
    const row = result.rows[0];
    if (row === undefined) {
      res.status(404).json({ error: "not_found" });
      return;
    }

    res.json({
      userID: userId,
      identity_pubkey: row.identity_pubkey.toString("base64"),
      exchange_pubkey: row.exchange_pubkey.toString("base64"),
      // The identity key's signature over the exchange key; callers verify it.
      exchange_sig: row.exchange_sig.toString("base64"),
      // The long-term ratchet key and the identity key's signature over it, or
      // null for an account that has not set one. Reading these spends no one-time key.
      ratchet_pubkey: row.ratchet_pubkey?.toString("base64") ?? null,
      ratchet_sig: row.ratchet_sig?.toString("base64") ?? null,
      key_epoch: row.key_epoch,
    });
    },
  );

  return router;
}
