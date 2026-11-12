import { Router } from "express";
import { requireSignedRequest, USER_ID_PATTERN, type AuthDeps } from "../auth/signed-request.js";

export function usersRouter(deps: AuthDeps): Router {
  const router = Router();

  // Public keys only. Callers pin these client-side and warn if they ever change.
  router.get("/users/:userID/pubkeys", requireSignedRequest(deps), async (req, res) => {
    const userId = req.params.userID;
    if (typeof userId !== "string" || !USER_ID_PATTERN.test(userId)) {
      res.status(404).json({ error: "not_found" });
      return;
    }

    const result = await deps.pool.query<{ identity_pubkey: Buffer; exchange_pubkey: Buffer }>(
      "SELECT identity_pubkey, exchange_pubkey FROM users WHERE user_id = $1",
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
    });
  });

  return router;
}
