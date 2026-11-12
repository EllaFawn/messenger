import * as crypto from "@messager/crypto";
import {
  deriveUserId,
  signExchangeKey,
  signRequest,
  verifyExchangeKey,
  type Envelope,
} from "@messager/protocol";
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
  exchangePublicKey: Uint8Array;
}

/** A message waiting on the server. Still encrypted; `from` is the server's claim until decryption proves it. */
export interface InboxItem {
  messageId: string;
  from: string;
  /** Standard base64, as in the wire envelope. */
  nonce: string;
  ciphertext: string;
  /** ISO time the server stored it. */
  createdAt: string;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const USER_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;
/** Standard base64 of exactly 24 bytes. */
const MESSAGE_NONCE_PATTERN = /^[A-Za-z0-9+/]{32}$/;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
/** Guards against a server sending an absurdly large inbox entry. */
const MAX_CIPHERTEXT_CHARS = 64 * 1024;
const MAX_INBOX_ITEMS = 1000;

function parseInboxItem(value: unknown): InboxItem | null {
  if (typeof value !== "object" || value === null) {
    return null;
  }
  const { message_id, from, v, nonce, ciphertext, created_at } = value as Record<string, unknown>;
  if (
    v !== 1 ||
    typeof message_id !== "string" ||
    typeof from !== "string" ||
    typeof nonce !== "string" ||
    typeof ciphertext !== "string" ||
    typeof created_at !== "string" ||
    !UUID_PATTERN.test(message_id) ||
    !USER_ID_PATTERN.test(from) ||
    !MESSAGE_NONCE_PATTERN.test(nonce) ||
    ciphertext.length === 0 ||
    ciphertext.length > MAX_CIPHERTEXT_CHARS ||
    !BASE64_PATTERN.test(ciphertext) ||
    Number.isNaN(Date.parse(created_at))
  ) {
    return null;
  }
  return { messageId: message_id, from, nonce, ciphertext, createdAt: created_at };
}

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
  /** Registers the identity's public keys with the server. */
  register(identity: StoredIdentity, inviteCode: string): Promise<void>;
  /**
   * Fetches a user's public keys. Rejects the reply unless the identity key
   * hashes to the userID that was asked for and has signed the exchange key,
   * so the server cannot substitute either key. Throws ApiError "not_found"
   * if no such user.
   */
  getPubkeys(identity: StoredIdentity, userId: string): Promise<PublicKeys>;
  /** Hands an already-encrypted envelope to the server for delivery. */
  sendMessage(identity: StoredIdentity, envelope: Envelope): Promise<{ messageId: string }>;
  /** Messages waiting for this user, oldest first. They stay on the server until acknowledged. */
  fetchInbox(identity: StoredIdentity): Promise<InboxItem[]>;
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
      exchange_pubkey: crypto.toBase64(identity.exchangePublicKey),
      // The identity key vouches for the exchange key, so contacts can verify it from the userID alone.
      exchange_sig: crypto.toBase64(signExchangeKey(identity.exchangePublicKey, identity.identityPrivateKey)),
      inviteCode,
    });
    const confirmed =
      typeof result === "object" && result !== null ? (result as Record<string, unknown>).userID : undefined;
    if (confirmed !== identity.userId) {
      throw new ApiError(201, "invalid_response");
    }
  }

  async function getPubkeys(identity: StoredIdentity, userId: string): Promise<PublicKeys> {
    const result = await request(identity, "GET", `/users/${encodeURIComponent(userId)}/pubkeys`);
    const reply = typeof result === "object" && result !== null ? (result as Record<string, unknown>) : {};
    const { userID, identity_pubkey, exchange_pubkey, exchange_sig } = reply;
    if (
      userID !== userId ||
      typeof identity_pubkey !== "string" ||
      typeof exchange_pubkey !== "string" ||
      typeof exchange_sig !== "string" ||
      !KEY_PATTERN.test(identity_pubkey) ||
      !KEY_PATTERN.test(exchange_pubkey) ||
      !SIGNATURE_PATTERN.test(exchange_sig)
    ) {
      throw new ApiError(200, "invalid_response");
    }
    const identityPublicKey = crypto.fromBase64(identity_pubkey);
    const exchangePublicKey = crypto.fromBase64(exchange_pubkey);
    if (
      deriveUserId(identityPublicKey) !== userId ||
      !verifyExchangeKey(exchangePublicKey, crypto.fromBase64(exchange_sig), identityPublicKey)
    ) {
      throw new ApiError(200, "invalid_response");
    }
    return { userId, identityPublicKey, exchangePublicKey };
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

  async function fetchInbox(identity: StoredIdentity): Promise<InboxItem[]> {
    const result = await request(identity, "GET", "/messages/inbox");
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

  return { request, register, getPubkeys, sendMessage, fetchInbox, ackMessage };
}
