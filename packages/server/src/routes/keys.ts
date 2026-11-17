import { verifyOneTimeKey } from "@messager/protocol";
import { Router } from "express";
import {
  authenticatedUserId,
  requireSignedRequest,
  USER_ID_PATTERN,
  type AuthDeps,
} from "../auth/signed-request.js";
import { limitByCaller, tooManyRequests } from "../limits.js";

/** One-time keys the server will hold for one user, not counting the fallback key. */
export const MAX_ONE_TIME_KEYS_PER_USER = 100;
/** Keys accepted in one upload. A full supply therefore takes two requests, each well inside the body size limit. */
export const MAX_ONE_TIME_KEYS_PER_UPLOAD = 50;

/** Standard base64 of exactly 32 bytes. */
const KEY_PATTERN = /^[A-Za-z0-9+/]{43}=$/;
/** Standard base64 of exactly 64 bytes. */
const SIGNATURE_PATTERN = /^[A-Za-z0-9+/]{86}==$/;
/** Ids are chosen by the client's ratchet library; kept short and URL-safe here. */
const KEY_ID_PATTERN = /^[A-Za-z0-9_+/=-]{1,64}$/;

interface UploadedKey {
  id: string;
  key: Buffer;
  sig: Buffer;
}

function parseKey(value: unknown): UploadedKey | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const { id, key, sig } = value as Record<string, unknown>;
  if (
    typeof id !== "string" ||
    typeof key !== "string" ||
    typeof sig !== "string" ||
    !KEY_ID_PATTERN.test(id) ||
    !KEY_PATTERN.test(key) ||
    !SIGNATURE_PATTERN.test(sig)
  ) {
    return null;
  }
  return { id, key: Buffer.from(key, "base64"), sig: Buffer.from(sig, "base64") };
}

function parseUpload(body: unknown): { keys: UploadedKey[]; fallback: UploadedKey | null } | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
  const { keys, fallback } = body as Record<string, unknown>;
  if (keys !== undefined && !Array.isArray(keys)) return null;
  const list = (keys ?? []) as unknown[];
  if (list.length > MAX_ONE_TIME_KEYS_PER_UPLOAD) return null;

  const parsed: UploadedKey[] = [];
  const seen = new Set<string>();
  for (const entry of list) {
    const key = parseKey(entry);
    if (key === null || seen.has(key.id)) return null;
    seen.add(key.id);
    parsed.push(key);
  }

  let parsedFallback: UploadedKey | null = null;
  if (fallback !== undefined) {
    parsedFallback = parseKey(fallback);
    if (parsedFallback === null || seen.has(parsedFallback.id)) return null;
  }
  if (parsed.length === 0 && parsedFallback === null) return null;
  return { keys: parsed, fallback: parsedFallback };
}

async function counts(pool: AuthDeps["pool"], userId: string): Promise<{ count: number; has_fallback: boolean }> {
  const result = await pool.query<{ count: number; has_fallback: boolean }>(
    `SELECT count(*) FILTER (WHERE NOT is_fallback)::int AS count,
            coalesce(bool_or(is_fallback), false) AS has_fallback
     FROM one_time_keys WHERE user_id = $1`,
    [userId],
  );
  return result.rows[0]!;
}

function keyJson(row: { key_id: string; pubkey: Buffer; sig: Buffer }) {
  return { id: row.key_id, key: row.pubkey.toString("base64"), sig: row.sig.toString("base64") };
}

/**
 * One-time keys let someone start a forward-secret conversation with a user
 * who is offline. The server only stores and hands out public keys; every
 * key is signed by its owner's identity key, and the server refuses to
 * store one that does not verify, since clients would reject it anyway.
 */
export function keysRouter(deps: AuthDeps): Router {
  const router = Router();

  // Upload a batch of one-time keys and, optionally, a replacement fallback key.
  router.post(
    "/keys/one-time",
    requireSignedRequest(deps),
    limitByCaller((l) => l.signed, deps),
    async (req, res) => {
      const upload = parseUpload(req.body);
      if (upload === null) {
        res.status(400).json({ error: "invalid_request" });
        return;
      }
      const caller = authenticatedUserId(res);

      const owner = await deps.pool.query<{ identity_pubkey: Buffer; ratchet_pubkey: Buffer }>(
        "SELECT identity_pubkey, ratchet_pubkey FROM users WHERE user_id = $1",
        [caller],
      );
      const user = owner.rows[0];
      if (user === undefined) {
        // The account was removed after the signature was checked.
        res.status(401).json({ error: "unauthorized" });
        return;
      }

      const identityKey = new Uint8Array(user.identity_pubkey);
      const ratchetKey = new Uint8Array(user.ratchet_pubkey);
      const all = upload.fallback === null ? upload.keys : [...upload.keys, upload.fallback];
      for (const key of all) {
        if (!verifyOneTimeKey(ratchetKey, new Uint8Array(key.key), new Uint8Array(key.sig), identityKey)) {
          res.status(400).json({ error: "invalid_request" });
          return;
        }
      }

      const client = await deps.pool.connect();
      try {
        await client.query("BEGIN");
        // Serialises uploads by the same user so the cap cannot be overshot.
        await client.query("SELECT 1 FROM users WHERE user_id = $1 FOR UPDATE", [caller]);

        const held = await client.query<{ n: number }>(
          "SELECT count(*)::int AS n FROM one_time_keys WHERE user_id = $1 AND NOT is_fallback",
          [caller],
        );
        // Keys beyond the cap are simply not stored; the client learns the count from the reply.
        const room = Math.max(0, MAX_ONE_TIME_KEYS_PER_USER - held.rows[0]!.n);
        for (const key of upload.keys.slice(0, room)) {
          await client.query(
            `INSERT INTO one_time_keys (user_id, key_id, pubkey, sig) VALUES ($1, $2, $3, $4)
             ON CONFLICT (user_id, key_id) DO NOTHING`,
            [caller, key.id, key.key, key.sig],
          );
        }
        if (upload.fallback !== null) {
          await client.query("DELETE FROM one_time_keys WHERE user_id = $1 AND (is_fallback OR key_id = $2)", [
            caller,
            upload.fallback.id,
          ]);
          await client.query(
            "INSERT INTO one_time_keys (user_id, key_id, pubkey, sig, is_fallback) VALUES ($1, $2, $3, $4, true)",
            [caller, upload.fallback.id, upload.fallback.key, upload.fallback.sig],
          );
        }
        await client.query("COMMIT");
      } catch (err) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw err;
      } finally {
        client.release();
      }

      res.json(await counts(deps.pool, caller));
    },
  );

  // How many of the caller's own keys are left, so the client knows when to top up.
  router.get("/keys/count", requireSignedRequest(deps), limitByCaller((l) => l.signed, deps), async (_req, res) => {
    res.json(await counts(deps.pool, authenticatedUserId(res)));
  });

  // Take one of a user's one-time keys in order to start a conversation with them.
  router.post(
    "/users/:userID/keys/claim",
    requireSignedRequest(deps),
    limitByCaller((l) => l.keyLookup, deps),
    async (req, res) => {
      const target = req.params.userID;
      if (typeof target !== "string" || !USER_ID_PATTERN.test(target)) {
        res.status(404).json({ error: "not_found" });
        return;
      }
      const caller = authenticatedUserId(res);

      const found = await deps.pool.query<{
        identity_pubkey: Buffer;
        ratchet_pubkey: Buffer;
        ratchet_sig: Buffer;
        key_epoch: number;
      }>("SELECT identity_pubkey, ratchet_pubkey, ratchet_sig, key_epoch FROM users WHERE user_id = $1", [target]);
      const user = found.rows[0];
      if (user === undefined) {
        res.status(404).json({ error: "not_found" });
        return;
      }

      // Counted only for a real target, and before a key is spent.
      const pairLimit = deps.limiters?.keyClaim.take(`${caller}>${target}`);
      if (pairLimit !== undefined && !pairLimit.allowed) {
        tooManyRequests(res, pairLimit);
        return;
      }

      // Delete-and-return in one statement: two simultaneous claims cannot get the same key.
      const claimed = await deps.pool.query<{ key_id: string; pubkey: Buffer; sig: Buffer }>(
        `DELETE FROM one_time_keys
         WHERE (user_id, key_id) = (
           SELECT user_id, key_id FROM one_time_keys
           WHERE user_id = $1 AND NOT is_fallback
           ORDER BY created_at, key_id
           LIMIT 1
           FOR UPDATE SKIP LOCKED
         )
         RETURNING key_id, pubkey, sig`,
        [target],
      );
      let key = claimed.rows[0];
      let fallback = false;
      if (key === undefined) {
        // Out of one-time keys: hand out the fallback key, which is kept.
        const kept = await deps.pool.query<{ key_id: string; pubkey: Buffer; sig: Buffer }>(
          "SELECT key_id, pubkey, sig FROM one_time_keys WHERE user_id = $1 AND is_fallback",
          [target],
        );
        key = kept.rows[0];
        fallback = true;
      }
      if (key === undefined) {
        res.status(409).json({ error: "no_one_time_keys" });
        return;
      }

      res.json({
        userID: target,
        identity_pubkey: user.identity_pubkey.toString("base64"),
        ratchet_pubkey: user.ratchet_pubkey.toString("base64"),
        ratchet_sig: user.ratchet_sig.toString("base64"),
        key_epoch: user.key_epoch,
        one_time_key: { ...keyJson(key), fallback },
      });
    },
  );

  return router;
}
