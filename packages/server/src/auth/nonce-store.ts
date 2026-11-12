import type { Pool } from "../db/pool.js";

export interface NonceRecord {
  /** The X-Nonce header value. */
  nonce: string;
  userId: string;
  /** When the nonce can be forgotten: after the request's timestamp window has closed. */
  expiresAt: Date;
}

/**
 * Records a request nonce. Returns true if it was new, false if it has been
 * seen before (a replay). The primary key makes this atomic, so two
 * simultaneous uses of one nonce cannot both succeed.
 */
export async function consumeNonce(pool: Pool, record: NonceRecord): Promise<boolean> {
  const result = await pool.query(
    "INSERT INTO auth_nonces (nonce, user_id, expires_at) VALUES ($1, $2, $3) ON CONFLICT (nonce) DO NOTHING",
    [record.nonce, record.userId, record.expiresAt],
  );
  return result.rowCount === 1;
}

/**
 * Deletes nonces whose window has closed; returns how many were removed.
 * Safe because a request that old already fails the timestamp check.
 */
export async function sweepExpiredNonces(pool: Pool, now: Date): Promise<number> {
  const result = await pool.query("DELETE FROM auth_nonces WHERE expires_at <= $1", [now]);
  return result.rowCount ?? 0;
}
