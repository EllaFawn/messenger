import { USER_ID_PATTERN } from "../auth/signed-request.js";
import type { Pool } from "../db/pool.js";
import { createInvite, listInvites, removeUser, revokeInvite } from "../invites.js";

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;
const DEFAULT_EXPIRY = "7d";
const MAX_EXPIRY_MS = 90 * DAY_MS;

const USAGE = `Usage:
  invite create [--note "who it is for"] [--expires 7d]
  invite list
  invite revoke <invite id>
  user list
  user remove <userID> --yes

Durations are a number followed by h (hours) or d (days), e.g. 12h or 7d.`;

/** Reads "12h" or "7d" as milliseconds. */
export function parseDuration(text: string): number {
  const match = /^([1-9]\d{0,3})([hd])$/.exec(text);
  const ms = match === null ? 0 : Number(match[1]) * (match[2] === "h" ? HOUR_MS : DAY_MS);
  if (ms < HOUR_MS || ms > MAX_EXPIRY_MS) {
    throw new Error("--expires must be between 1h and 90d, e.g. 12h or 7d");
  }
  return ms;
}

function formatDate(date: Date): string {
  return `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

/** Splits arguments into --name value options, bare --flags and positional words. */
function parseArgs(
  args: string[],
  valueOptions: string[],
  flags: string[],
): { options: Map<string, string>; flags: Set<string>; positional: string[] } {
  const options = new Map<string, string>();
  const seenFlags = new Set<string>();
  const positional: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (valueOptions.includes(arg)) {
      const value = args[i + 1];
      if (value === undefined) throw new Error(`${arg} needs a value`);
      options.set(arg, value);
      i += 1;
    } else if (flags.includes(arg)) {
      seenFlags.add(arg);
    } else if (arg.startsWith("--")) {
      throw new Error(`Unknown option ${arg}`);
    } else {
      positional.push(arg);
    }
  }
  return { options, flags: seenFlags, positional };
}

async function inviteCommand(args: string[], pool: Pool, out: (line: string) => void): Promise<number> {
  const [action, ...rest] = args;

  if (action === "create") {
    const { options, positional } = parseArgs(rest, ["--note", "--expires"], []);
    if (positional.length > 0) throw new Error(`Unexpected argument: ${positional[0]}`);
    const expiresAt = new Date(Date.now() + parseDuration(options.get("--expires") ?? DEFAULT_EXPIRY));
    const { code, id } = await createInvite(pool, { note: options.get("--note") ?? "", expiresAt });
    out(`Invite created (id ${id}), valid until ${formatDate(expiresAt)}.`);
    out("Give this code to one person. It works once and will not be shown again:");
    out("");
    out(`  ${code}`);
    out("");
    return 0;
  }

  if (action === "list") {
    const invites = await listInvites(pool);
    if (invites.length === 0) {
      out("No invites.");
      return 0;
    }
    for (const invite of invites) {
      const detail =
        invite.state === "used"
          ? `used ${formatDate(invite.usedAt!)} by ${invite.usedBy ?? "(account since removed)"}`
          : `${invite.state}, expires ${formatDate(invite.expiresAt)}`;
      out(`${invite.id}  ${detail}${invite.note === "" ? "" : `  "${invite.note}"`}`);
    }
    return 0;
  }

  if (action === "revoke") {
    const { positional } = parseArgs(rest, [], []);
    if (positional.length !== 1) throw new Error("Give the id of one invite, as shown by: invite list");
    const outcome = await revokeInvite(pool, positional[0]!);
    const messages = {
      revoked: "Revoked. That code no longer works.",
      not_found: "No invite has that id.",
      already_used: "That invite has already been used. To end the person's access, use: user remove",
      ambiguous: "More than one invite starts with that id; give more characters.",
    } as const;
    out(messages[outcome]);
    return outcome === "revoked" ? 0 : 1;
  }

  out(USAGE);
  return 1;
}

async function userCommand(args: string[], pool: Pool, out: (line: string) => void): Promise<number> {
  const [action, ...rest] = args;

  if (action === "list") {
    const users = await pool.query<{ user_id: string; created_at: Date }>(
      "SELECT user_id, created_at FROM users ORDER BY created_at",
    );
    if (users.rows.length === 0) {
      out("No accounts.");
      return 0;
    }
    for (const user of users.rows) {
      out(`${user.user_id}  registered ${formatDate(user.created_at)}`);
    }
    return 0;
  }

  if (action === "remove") {
    const { flags, positional } = parseArgs(rest, [], ["--yes"]);
    const userId = positional[0];
    if (positional.length !== 1 || userId === undefined || !USER_ID_PATTERN.test(userId)) {
      throw new Error("Give one full userID, as shown by: user list");
    }
    if (!flags.has("--yes")) {
      out(`This would permanently delete the account ${userId} and its undelivered messages.`);
      out("Run the command again with --yes to go ahead.");
      return 1;
    }
    if (!(await removeUser(pool, userId))) {
      out("No account has that userID.");
      return 1;
    }
    out(`Removed ${userId}. Their invite stays used, so it cannot let them back in.`);
    return 0;
  }

  out(USAGE);
  return 1;
}

/**
 * The operator's commands. They talk to the database directly and have no
 * network route, so only someone with access to the server can run them.
 * Returns the process exit code.
 */
export async function runAdmin(args: string[], pool: Pool, out: (line: string) => void): Promise<number> {
  const [area, ...rest] = args;
  try {
    if (area === "invite") return await inviteCommand(rest, pool, out);
    if (area === "user") return await userCommand(rest, pool, out);
  } catch (err) {
    out((err as Error).message);
    return 1;
  }
  out(USAGE);
  return 1;
}
