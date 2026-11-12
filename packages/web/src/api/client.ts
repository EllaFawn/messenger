import * as crypto from "@messager/crypto";
import { signRequest } from "@messager/protocol";
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

export interface ApiClient {
  /**
   * Sends a request signed with the identity key and returns the parsed JSON
   * response (undefined if the response is empty). `path` is the server's
   * path, e.g. "/messages/inbox". Throws ApiError on any failure.
   */
  request(identity: StoredIdentity, method: string, path: string, body?: unknown): Promise<unknown>;
  /** Registers the identity's public keys with the server. */
  register(identity: StoredIdentity, inviteCode: string): Promise<void>;
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
      inviteCode,
    });
    const confirmed =
      typeof result === "object" && result !== null ? (result as Record<string, unknown>).userID : undefined;
    if (confirmed !== identity.userId) {
      throw new ApiError(201, "invalid_response");
    }
  }

  return { request, register };
}
