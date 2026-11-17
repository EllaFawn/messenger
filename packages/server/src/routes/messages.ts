import { Router } from "express";
import { limitByCaller } from "../limits.js";
import {
  authenticatedUserId,
  requireSignedRequest,
  USER_ID_PATTERN,
  type AuthDeps,
} from "../auth/signed-request.js";

const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
/** Even an empty ratchet message is longer than this, so nothing shorter can be genuine. */
const MIN_CIPHERTEXT_BYTES = 16;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Most messages returned by one inbox fetch. Acknowledging them brings the next ones into view. */
export const INBOX_PAGE_SIZE = 100;

/** A ratchet message: a pre-key message (0), which can create the session, or a normal one (1). */
interface IncomingEnvelope {
  to: string;
  type: 0 | 1;
  ciphertext: Buffer;
}

/** Decodes standard base64, accepting only the one canonical spelling of the bytes. */
function decodeStrictBase64(text: string): Buffer | null {
  if (!BASE64_PATTERN.test(text)) {
    return null;
  }
  const bytes = Buffer.from(text, "base64");
  return bytes.toString("base64") === text ? bytes : null;
}

/** Checks shape only. The server never decrypts, so the ciphertext stays an opaque blob. */
function parseEnvelope(body: unknown): IncomingEnvelope | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return null;
  }
  const { v, to, type, ciphertext } = body as Record<string, unknown>;
  // Version 2 only. Version 1 (static keys, with a separate nonce) is retired.
  if (
    v !== 2 ||
    (type !== 0 && type !== 1) ||
    typeof to !== "string" ||
    typeof ciphertext !== "string" ||
    !USER_ID_PATTERN.test(to)
  ) {
    return null;
  }
  const ciphertextBytes = decodeStrictBase64(ciphertext);
  if (ciphertextBytes === null || ciphertextBytes.length < MIN_CIPHERTEXT_BYTES) {
    return null;
  }
  return { to, type, ciphertext: ciphertextBytes };
}

/** How many undelivered messages the server will hold. */
export interface QueueLimits {
  /** From one sender to one recipient. */
  perPair: number;
  /** For one recipient, from everyone. */
  perRecipient: number;
}

export const DEFAULT_QUEUE_LIMITS: QueueLimits = { perPair: 500, perRecipient: 5000 };

/** An undelivered message is deleted after this long. */
export const MESSAGE_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

/** Deletes messages nobody collected in time. Returns how many were removed. */
export async function sweepExpiredMessages(
  pool: AuthDeps["pool"],
  now: Date,
  maxAgeMs: number = MESSAGE_MAX_AGE_MS,
): Promise<number> {
  const result = await pool.query("DELETE FROM messages WHERE created_at < $1", [
    new Date(now.getTime() - maxAgeMs),
  ]);
  return result.rowCount ?? 0;
}

/**
 * A position in an inbox: the message's creation time in microseconds, then
 * its id. Opaque to clients, which only ever hand back one they were given.
 */
const CURSOR_PATTERN = /^(\d{1,18})_([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

function parseCursor(value: unknown): { micros: string; messageId: string } | null {
  if (typeof value !== "string") return null;
  const match = CURSOR_PATTERN.exec(value);
  return match === null ? null : { micros: match[1]!, messageId: match[2]! };
}

export interface MessagesDeps extends AuthDeps {
  queueLimits?: QueueLimits;
  /** Messages per inbox page. Overridable for tests. */
  inboxPageSize?: number;
  /** Called after a message is stored, with the recipient's userID, so they can be told at once. */
  onMessageStored?: (toUserId: string) => void;
}

export function messagesRouter(deps: MessagesDeps): Router {
  const router = Router();
  const queueLimits = deps.queueLimits ?? DEFAULT_QUEUE_LIMITS;
  const pageSize = deps.inboxPageSize ?? INBOX_PAGE_SIZE;

  router.post("/messages", requireSignedRequest(deps), limitByCaller((l) => l.sendMessage, deps), async (req, res) => {
    const envelope = parseEnvelope(req.body);
    if (envelope === null) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }

    // The sender is whoever signed the request; a "from" in the body is never read.
    const from = authenticatedUserId(res);

    // The queue checks are part of the insert. Two simultaneous sends can
    // both pass and overshoot by one; the limits are a bound on abuse, not
    // an exact quota.
    const inserted = await deps.pool.query<{ message_id: string; created_at: Date }>(
      `INSERT INTO messages (from_user_id, to_user_id, ciphertext, v, msg_type)
       SELECT $1, $2, $3, 2, $6
       WHERE EXISTS (SELECT 1 FROM users WHERE user_id = $2)
         AND (SELECT count(*) FROM messages WHERE to_user_id = $2 AND from_user_id = $1) < $4
         AND (SELECT count(*) FROM messages WHERE to_user_id = $2) < $5
       RETURNING message_id, created_at`,
      [from, envelope.to, envelope.ciphertext, queueLimits.perPair, queueLimits.perRecipient, envelope.type],
    );
    const row = inserted.rows[0];
    if (row === undefined) {
      const recipient = await deps.pool.query("SELECT 1 FROM users WHERE user_id = $1", [envelope.to]);
      if (recipient.rowCount === 0) {
        res.status(404).json({ error: "recipient_not_found" });
      } else {
        res.status(429).json({ error: "recipient_queue_full" });
      }
      return;
    }

    res.status(201).json({ message_id: row.message_id, created_at: row.created_at.toISOString() });

    // Best effort: the inbox is the source of truth, so a failed nudge loses nothing.
    try {
      deps.onMessageStored?.(envelope.to);
    } catch (err) {
      console.error("push notify failed:", err);
    }
  });

  // Every message for the caller that has not been acknowledged yet, oldest first.
  // A message keeps coming back until it is acked, so a client that crashes
  // between fetching and saving does not lose it; a repeat of one it did save
  // no longer decrypts, and is dropped. delivered_at only records the first fetch.
  //
  // One page per request. `?after=<cursor>` continues from an earlier item,
  // so a client can step past messages it has chosen to leave here.
  router.get("/messages/inbox", requireSignedRequest(deps), limitByCaller((l) => l.signed, deps), async (req, res) => {
    const caller = authenticatedUserId(res);

    let after: { micros: string; messageId: string } | null = null;
    if (req.query.after !== undefined) {
      after = parseCursor(req.query.after);
      if (after === null) {
        res.status(400).json({ error: "invalid_request" });
        return;
      }
    }

    const result = await deps.pool.query<{
      message_id: string;
      from_user_id: string;
      ciphertext: Buffer;
      created_at: Date;
      micros: string;
      v: number;
      msg_type: number;
    }>(
      `WITH page AS (
         SELECT message_id FROM messages
         WHERE to_user_id = $1
           AND ($3::bigint IS NULL OR (created_at, message_id) >
                ('epoch'::timestamptz + $3::bigint * interval '1 microsecond', $4::uuid))
         ORDER BY created_at, message_id
         LIMIT $2
       ), marked AS (
         UPDATE messages SET delivered_at = now()
         WHERE message_id IN (SELECT message_id FROM page) AND delivered_at IS NULL
       )
       SELECT m.message_id, m.from_user_id, m.ciphertext, m.created_at, m.v, m.msg_type,
              (extract(epoch FROM m.created_at) * 1000000)::bigint::text AS micros
       FROM messages m JOIN page USING (message_id)
       ORDER BY m.created_at, m.message_id`,
      [caller, pageSize, after?.micros ?? null, after?.messageId ?? null],
    );

    res.json(
      result.rows.map((row) => ({
        message_id: row.message_id,
        from: row.from_user_id,
        v: row.v,
        type: row.msg_type,
        ciphertext: row.ciphertext.toString("base64"),
        created_at: row.created_at.toISOString(),
        cursor: `${row.micros}_${row.message_id}`,
      })),
    );
  });

  // Acknowledging deletes the row, so the server stops holding the ciphertext.
  // Only the recipient may do it. Someone else's message and a missing one get
  // the same 404, so the answer does not reveal whether an id exists.
  router.post("/messages/:id/ack", requireSignedRequest(deps), limitByCaller((l) => l.signed, deps), async (req, res) => {
    const messageId = req.params.id;
    if (typeof messageId !== "string" || !UUID_PATTERN.test(messageId)) {
      res.status(404).json({ error: "not_found" });
      return;
    }

    const deleted = await deps.pool.query(
      "DELETE FROM messages WHERE message_id = $1 AND to_user_id = $2",
      [messageId, authenticatedUserId(res)],
    );
    if (deleted.rowCount !== 1) {
      res.status(404).json({ error: "not_found" });
      return;
    }

    res.status(204).end();
  });

  return router;
}
