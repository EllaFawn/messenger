import * as crypto from "@messager/crypto";

export interface CanonicalRequestParams {
  method: string;
  path: string;
  rawBody: Uint8Array;
  /** Unix timestamp in milliseconds. */
  timestamp: number;
  /** Base64-encoded 16 random bytes (the X-Nonce header value). */
  nonce: string;
}

/**
 * Builds the exact string signed by the client and verified by the server:
 * `v1\n{METHOD}\n{path}\n{hex(SHA-256(raw_body))}\n{timestamp}\n{nonce}`.
 * A single shared implementation so signer and verifier cannot drift.
 */
export function buildCanonicalString(params: CanonicalRequestParams): string {
  const bodyHashHex = crypto.toHex(crypto.sha256(params.rawBody));
  return [
    "v1",
    params.method.toUpperCase(),
    params.path,
    bodyHashHex,
    String(params.timestamp),
    params.nonce,
  ].join("\n");
}
