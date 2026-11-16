import { createHash, randomBytes } from "node:crypto";
import type { PoolClient } from "pg";
import type { Pool } from "./db/pool.js";

const INVITE_CODE_BYTES = 32;
export const MAX_INVITE_NOTE_LENGTH = 200;
/** How much of the hash the operator sees and types to refer to an invite. */
const INVITE_ID_HEX_CHARS = 12;
const MIN_REVOKE_ID_CHARS = 8;

/** Only this hash is ever stored or compared; the code itself exists in the database nowhere. */
export function hashInviteCode(code: string): Buffer {
  return createHash("sha256").update(code, "utf8").digest();
}

/** Creates a single-use invite. The returned code is shown to the operator once and cannot be recovered. */
export async function createInvite(
  pool: Pool,
  options: { note: string; expiresAt: Date },
): Promise<{ code: string; id: string }> {
  if (options.note.length > MAX_INVITE_NOTE_LENGTH) {
    throw new Error(`The note can be at most ${MAX_INVITE_NOTE_LENGTH} characters.`);
  }
  if (options.expiresAt.getTime() <= Date.now()) {
    throw new Error("The expiry must be in the future.");
  }
  const code = randomBytes(INVITE_CODE_BYTES).toString("base64url");
  const codeHash = hashInviteCode(code);
  await pool.query("INSERT INTO invites (code_hash, note, expires_at) VALUES ($1, $2, $3)", [
    codeHash,
    options.note,
    options.expiresAt,
  ]);
  return { code, id: codeHash.toString("hex").slice(0, INVITE_ID_HEX_CHARS) };
}

/** A read-only check, used to turn away a bad code before anything is written. */
export async function isInviteUsable(pool: Pool, codeHash: Buffer): Promise<boolean> {
  const result = await pool.query(
    "SELECT 1 FROM invites WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now()",
    [codeHash],
  );
  return result.rowCount === 1;
}

/**
 * Marks an invite as used by `userId`. Must run inside the caller's
 * transaction, after that user's row is inserted, so the invite is consumed
 * only if the registration commits. The single UPDATE is atomic: of any
 * number of simultaneous claims, exactly one sees a row.
 */
export async function claimInvite(client: PoolClient, codeHash: Buffer, userId: string): Promise<boolean> {
  const result = await client.query(
    `UPDATE invites SET used_at = now(), used_by = $2
     WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now()`,
    [codeHash, userId],
  );
  return result.rowCount === 1;
}

export interface InviteSummary {
  /** First characters of the code's hash. Identifies the invite without being usable as a code. */
  id: string;
  note: string;
  state: "unused" | "used" | "expired";
  createdAt: Date;
  expiresAt: Date;
  usedAt: Date | null;
  usedBy: string | null;
}

/** Every invite, newest first. Never includes a code. */
export async function listInvites(pool: Pool): Promise<InviteSummary[]> {
  const result = await pool.query<{
    code_hash: Buffer;
    note: string;
    created_at: Date;
    expires_at: Date;
    used_at: Date | null;
    used_by: string | null;
    expired: boolean;
  }>(
    `SELECT code_hash, note, created_at, expires_at, used_at, used_by, expires_at <= now() AS expired
     FROM invites ORDER BY created_at DESC, code_hash`,
  );
  return result.rows.map((row) => ({
    id: row.code_hash.toString("hex").slice(0, INVITE_ID_HEX_CHARS),
    note: row.note,
    state: row.used_at !== null ? "used" : row.expired ? "expired" : "unused",
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    usedAt: row.used_at,
    usedBy: row.used_by,
  }));
}

/**
 * Deletes an unused invite, identified by the start of its id from
 * `listInvites`. A used invite is kept as a record of who joined with it.
 */
export async function revokeInvite(
  pool: Pool,
  idPrefix: string,
): Promise<"revoked" | "not_found" | "already_used" | "ambiguous"> {
  if (!/^[0-9a-f]+$/.test(idPrefix) || idPrefix.length < MIN_REVOKE_ID_CHARS) {
    throw new Error(`Give at least ${MIN_REVOKE_ID_CHARS} characters of the invite id (letters a-f and digits).`);
  }
  const matches = await pool.query<{ code_hash: Buffer; used_at: Date | null }>(
    "SELECT code_hash, used_at FROM invites WHERE left(encode(code_hash, 'hex'), $2) = $1",
    [idPrefix, idPrefix.length],
  );
  if (matches.rows.length === 0) return "not_found";
  if (matches.rows.length > 1) return "ambiguous";
  const invite = matches.rows[0]!;
  if (invite.used_at !== null) return "already_used";
  const deleted = await pool.query("DELETE FROM invites WHERE code_hash = $1 AND used_at IS NULL", [
    invite.code_hash,
  ]);
  return deleted.rowCount === 1 ? "revoked" : "already_used";
}

/**
 * Removes an account and every undelivered message to or from it. With
 * single-use invites this is how one person's access is ended: their invite
 * stays marked as used, so it cannot let them back in.
 */
export async function removeUser(pool: Pool, userId: string): Promise<boolean> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("DELETE FROM messages WHERE from_user_id = $1 OR to_user_id = $1", [userId]);
    await client.query("DELETE FROM auth_nonces WHERE user_id = $1", [userId]);
    const deleted = await client.query("DELETE FROM users WHERE user_id = $1", [userId]);
    await client.query("COMMIT");
    return deleted.rowCount === 1;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}
