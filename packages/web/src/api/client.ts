import * as crypto from "@messager/crypto";
import {
  deriveUserId,
  signOneTimeKey,
  signRatchetKey,
  signRequest,
  verifyOneTimeKey,
  verifyRatchetKey,
  type Envelope,
  type RatchetMessageType,
} from "@messager/protocol";
import type { OneTimeKey } from "@messager/ratchet";
import type { StoredIdentity } from "../identity.js";

/** The browser reaches the server through this same-origin prefix; see vite.config.ts. */
export const DEFAULT_API_BASE = "/api";
const REQUEST_NONCE_BYTES = 16;

/** Any failed API call. `code` is the server's error string, or one of the client-side codes below. */
export class ApiError extends Error {
  constructor(
    /** HTTP status; 0 if no response was received. */
    readonly status: number,
    /** e.g. "invalid_invite", "unauthorized"; or "network_error", "invalid_response", "unknown_error". */
    readonly code: string,
  ) {
    super(`API request failed: ${code} (${status})`);
    this.name = "ApiError";
  }
}

export interface ApiClientOptions {
  baseUrl?: string;
  /** Injectable for tests. */
  fetch?: typeof fetch;
  /** Clock in unix ms; injectable for tests. */
  now?: () => number;
}

/** Another user's public keys, as returned (and checked) by getPubkeys. */
export interface PublicKeys {
  userId: string;
  identityPublicKey: Uint8Array;
  /** Their long-term ratchet key, signed by the identity key. */
  ratchetPublicKey: Uint8Array;
  /** Raised each time the user replaces their ratchet key. */
  keyEpoch: number;
}

/** A user's keys plus one of their one-time keys, for starting a session. All checked against the userID. */
export interface ClaimedKeys extends PublicKeys {
  oneTimeKey: Uint8Array;
  /** True if the server was out of one-time keys and gave the reusable fallback key. */
  fallback: boolean;
}

/** How many of this user's one-time keys the server still holds. */
export interface KeyCount {
  count: number;
  hasFallback: boolean;
}

/** A message waiting on the server. Still encrypted; `from` is the server's claim until decryption proves it. */
export interface InboxItem {
  messageId: string;
  from: string;
  /** 0: a pre-key message, which can start a session. 1: a normal message. */
  type: RatchetMessageType;
  /** Standard base64, as in the wire envelope. */
  ciphertext: string;
  /** ISO time the server stored it. */
  createdAt: string;
  /** Opaque position in the inbox; pass the last one back to fetch the next page. */
  cursor: string;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const USER_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
/** Guards against a server sending an absurdly large inbox entry. */
const MAX_CIPHERTEXT_CHARS = 64 * 1024;
const MAX_INBOX_ITEMS = 1000;
const CURSOR_PATTERN = /^\d{1,18}_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function parseInboxItem(value: unknown): InboxItem | null {
  if (typeof value !== "object" || value === null) {
    return null;
  }
  const { message_id, from, v, type, ciphertext, created_at, cursor } = value as Record<string, unknown>;
  if (
    v !== 2 ||
    (type !== 0 && type !== 1) ||
    typeof message_id !== "string" ||
    typeof from !== "string" ||
    typeof ciphertext !== "string" ||
    typeof created_at !== "string" ||
    typeof cursor !== "string" ||
    !CURSOR_PATTERN.test(cursor) ||
    !UUID_PATTERN.test(message_id) ||
    !USER_ID_PATTERN.test(from) ||
    ciphertext.length === 0 ||
    ciphertext.length > MAX_CIPHERTEXT_CHARS ||
    !BASE64_PATTERN.test(ciphertext) ||
    Number.isNaN(Date.parse(created_at))
  ) {
    return null;
  }
  return { messageId: message_id, from, type, ciphertext, createdAt: created_at, cursor };
}

/** Put in front of a fallback key's id when uploading it; see uploadOneTimeKeys. */
export const FALLBACK_ID_PREFIX = "fallback-";

/** Standard base64 of exactly 32 bytes. */
const KEY_PATTERN = /^[A-Za-z0-9+/]{43}=$/;
/** Standard base64 of exactly 64 bytes (an Ed25519 signature). */
const SIGNATURE_PATTERN = /^[A-Za-z0-9+/]{86}==$/;

export interface ApiClient {
  /**
   * Sends a request signed with the identity key and returns the parsed JSON
   * response (undefined if the response is empty). `path` is the server's
   * path, e.g. "/messages/inbox". Throws ApiError on any failure.
   */
  request(identity: StoredIdentity, method: string, path: string, body?: unknown): Promise<unknown>;
  /** Registers the identity key and the signed ratchet key with the server. */
  register(identity: StoredIdentity, inviteCode: string): Promise<void>;
  /**
   * Fetches a user's public keys. Rejects the reply unless the identity key
   * hashes to the userID that was asked for and has signed the ratchet key,
   * so the server cannot substitute either key. Throws ApiError "not_found"
   * if no such user.
   */
  getPubkeys(identity: StoredIdentity, userId: string): Promise<PublicKeys>;
  /**
   * Takes one of a user's one-time keys, to start a session with them. The
   * server hands each out once. Checked like getPubkeys, and the one-time
   * key must be signed together with that ratchet key. Throws ApiError
   * "no_one_time_keys" if they have none left at all.
   */
  claimOneTimeKey(identity: StoredIdentity, userId: string): Promise<ClaimedKeys>;
  /** How many of my one-time keys the server still holds. */
  countOneTimeKeys(identity: StoredIdentity): Promise<KeyCount>;
  /** Signs and uploads one-time keys, and optionally a new fallback key. */
  uploadOneTimeKeys(identity: StoredIdentity, keys: OneTimeKey[], fallback?: OneTimeKey): Promise<KeyCount>;
  /** Hands an already-encrypted envelope to the server for delivery. */
  sendMessage(identity: StoredIdentity, envelope: Envelope): Promise<{ messageId: string }>;
  /**
   * One page of the messages waiting for this user, oldest first. They stay
   * on the server until acknowledged. Pass the last item's cursor as `after`
   * for the next page; an empty page means the end.
   */
  fetchInbox(identity: StoredIdentity, after?: string): Promise<InboxItem[]>;
  /** Tells the server a message is safely stored here, so it can delete its copy. */
  ackMessage(identity: StoredIdentity, messageId: string): Promise<void>;
}

function errorCodeFrom(text: string): string {
  try {
    const parsed: unknown = JSON.parse(text);
    if (typeof parsed === "object" && parsed !== null) {
      const code = (parsed as Record<string, unknown>).error;
      if (typeof code === "string" && /^[a-z_]{1,64}$/.test(code)) {
        return code;
      }
    }
  } catch {
    // Not JSON; fall through.
  }
  return "unknown_error";
}

export function createApiClient(options: ApiClientOptions = {}): ApiClient {
  const baseUrl = options.baseUrl ?? DEFAULT_API_BASE;
  const doFetch = options.fetch ?? ((input, init) => fetch(input, init));
  const now = options.now ?? Date.now;

  async function request(
    identity: StoredIdentity,
    method: string,
    path: string,
    body?: unknown,
  ): Promise<unknown> {
    await crypto.ready;

    // The exact text sent is the exact text signed.
    const bodyText = body === undefined ? undefined : JSON.stringify(body);
    const timestamp = now();
    const nonce = crypto.toBase64(crypto.randomBytes(REQUEST_NONCE_BYTES));
    const signature = signRequest(
      { method, path, rawBody: crypto.utf8Encode(bodyText ?? ""), timestamp, nonce },
      identity.identityPrivateKey,
    );

    const headers: Record<string, string> = {
      "x-user-id": identity.userId,
      "x-timestamp": String(timestamp),
      "x-nonce": nonce,
      "x-signature": crypto.toBase64(signature),
    };
    if (bodyText !== undefined) {
      headers["content-type"] = "application/json";
    }

    let response: Response;
    let text: string;
    try {
      response = await doFetch(baseUrl + path, {
        method,
        headers,
        body: bodyText,
        // Auth is the signature alone: no cookies, and never follow a redirect elsewhere.
        credentials: "omit",
        redirect: "error",
        cache: "no-store",
        referrerPolicy: "no-referrer",
      });
      text = await response.text();
    } catch {
      throw new ApiError(0, "network_error");
    }

    if (!response.ok) {
      throw new ApiError(response.status, errorCodeFrom(text));
    }
    if (text === "") {
      return undefined;
    }
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new ApiError(response.status, "invalid_response");
    }
  }

  async function register(identity: StoredIdentity, inviteCode: string): Promise<void> {
    const result = await request(identity, "POST", "/register", {
      userID: identity.userId,
      identity_pubkey: crypto.toBase64(identity.identityPublicKey),
      ratchet_pubkey: crypto.toBase64(identity.ratchetPublicKey),
      // The identity key vouches for the ratchet key, so contacts can verify it from the userID alone.
      ratchet_sig: crypto.toBase64(signRatchetKey(identity.ratchetPublicKey, identity.identityPrivateKey)),
      inviteCode,
    });
    const confirmed =
      typeof result === "object" && result !== null ? (result as Record<string, unknown>).userID : undefined;
    if (confirmed !== identity.userId) {
      throw new ApiError(201, "invalid_response");
    }
  }

  /** Checks the keys part of a pubkeys or claim reply against the userID that was asked for. */
  function parseUserKeys(result: unknown, userId: string): PublicKeys {
    const reply = typeof result === "object" && result !== null ? (result as Record<string, unknown>) : {};
    const { userID, identity_pubkey, ratchet_pubkey, ratchet_sig, key_epoch } = reply;
    if (
      userID !== userId ||
      typeof identity_pubkey !== "string" ||
      typeof ratchet_pubkey !== "string" ||
      typeof ratchet_sig !== "string" ||
      !KEY_PATTERN.test(identity_pubkey) ||
      !KEY_PATTERN.test(ratchet_pubkey) ||
      !SIGNATURE_PATTERN.test(ratchet_sig) ||
      !Number.isSafeInteger(key_epoch) ||
      (key_epoch as number) < 1
    ) {
      throw new ApiError(200, "invalid_response");
    }
    const identityPublicKey = crypto.fromBase64(identity_pubkey);
    const ratchetPublicKey = crypto.fromBase64(ratchet_pubkey);
    if (
      deriveUserId(identityPublicKey) !== userId ||
      !verifyRatchetKey(ratchetPublicKey, crypto.fromBase64(ratchet_sig), identityPublicKey)
    ) {
      throw new ApiError(200, "invalid_response");
    }
    return { userId, identityPublicKey, ratchetPublicKey, keyEpoch: key_epoch as number };
  }

  async function getPubkeys(identity: StoredIdentity, userId: string): Promise<PublicKeys> {
    return parseUserKeys(await request(identity, "GET", `/users/${encodeURIComponent(userId)}/pubkeys`), userId);
  }

  async function claimOneTimeKey(identity: StoredIdentity, userId: string): Promise<ClaimedKeys> {
    const result = await request(identity, "POST", `/users/${encodeURIComponent(userId)}/keys/claim`);
    const keys = parseUserKeys(result, userId);
    const claimed = (result as Record<string, unknown>).one_time_key;
    const entry = typeof claimed === "object" && claimed !== null ? (claimed as Record<string, unknown>) : {};
    const { key, sig, fallback } = entry;
    if (
      typeof key !== "string" ||
      typeof sig !== "string" ||
      typeof fallback !== "boolean" ||
      !KEY_PATTERN.test(key) ||
      !SIGNATURE_PATTERN.test(sig)
    ) {
      throw new ApiError(200, "invalid_response");
    }
    const oneTimeKey = crypto.fromBase64(key);
    // Signed together with the ratchet key: the server cannot pair it with another account's key.
    if (!verifyOneTimeKey(keys.ratchetPublicKey, oneTimeKey, crypto.fromBase64(sig), keys.identityPublicKey)) {
      throw new ApiError(200, "invalid_response");
    }
    return { ...keys, oneTimeKey, fallback };
  }

  function parseKeyCount(result: unknown): KeyCount {
    const reply = typeof result === "object" && result !== null ? (result as Record<string, unknown>) : {};
    const { count, has_fallback } = reply;
    if (!Number.isSafeInteger(count) || (count as number) < 0 || typeof has_fallback !== "boolean") {
      throw new ApiError(200, "invalid_response");
    }
    return { count: count as number, hasFallback: has_fallback };
  }

  async function countOneTimeKeys(identity: StoredIdentity): Promise<KeyCount> {
    return parseKeyCount(await request(identity, "GET", "/keys/count"));
  }

  async function uploadOneTimeKeys(
    identity: StoredIdentity,
    keys: OneTimeKey[],
    fallback?: OneTimeKey,
  ): Promise<KeyCount> {
    const signed = (k: OneTimeKey) => ({
      id: k.id,
      key: crypto.toBase64(k.key),
      sig: crypto.toBase64(signOneTimeKey(identity.ratchetPublicKey, k.key, identity.identityPrivateKey)),
    });
    const body: Record<string, unknown> = { keys: keys.map(signed) };
    if (fallback !== undefined) {
      // The ratchet library numbers fallback keys separately from one-time
      // keys, so the same id can name one of each. The server keeps all of a
      // user's keys under one set of ids; the prefix keeps them apart. Ids
      // are only labels: a session is started from the key itself.
      body.fallback = { ...signed(fallback), id: `${FALLBACK_ID_PREFIX}${fallback.id}` };
    }
    return parseKeyCount(await request(identity, "POST", "/keys/one-time", body));
  }

  async function sendMessage(identity: StoredIdentity, envelope: Envelope): Promise<{ messageId: string }> {
    const result = await request(identity, "POST", "/messages", envelope);
    const messageId =
      typeof result === "object" && result !== null ? (result as Record<string, unknown>).message_id : undefined;
    if (typeof messageId !== "string" || !UUID_PATTERN.test(messageId)) {
      throw new ApiError(201, "invalid_response");
    }
    return { messageId };
  }

  async function fetchInbox(identity: StoredIdentity, after?: string): Promise<InboxItem[]> {
    if (after !== undefined && !CURSOR_PATTERN.test(after)) {
      throw new ApiError(0, "invalid_request");
    }
    // The query string is part of the signed path.
    const path = after === undefined ? "/messages/inbox" : `/messages/inbox?after=${after}`;
    const result = await request(identity, "GET", path);
    if (!Array.isArray(result) || result.length > MAX_INBOX_ITEMS) {
      throw new ApiError(200, "invalid_response");
    }
    // One malformed entry is refused as a whole reply: never guess at what the server meant.
    const items: InboxItem[] = [];
    for (const entry of result) {
      const item = parseInboxItem(entry);
      if (item === null) {
        throw new ApiError(200, "invalid_response");
      }
      items.push(item);
    }
    return items;
  }

  async function ackMessage(identity: StoredIdentity, messageId: string): Promise<void> {
    if (!UUID_PATTERN.test(messageId)) {
      throw new ApiError(0, "invalid_request");
    }
    await request(identity, "POST", `/messages/${messageId}/ack`);
  }

  return {
    request,
    register,
    getPubkeys,
    claimOneTimeKey,
    countOneTimeKeys,
    uploadOneTimeKeys,
    sendMessage,
    fetchInbox,
    ackMessage,
  };
}
