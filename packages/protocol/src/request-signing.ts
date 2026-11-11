import * as crypto from "@messager/crypto";
import { buildCanonicalString, type CanonicalRequestParams } from "./canonical-request.js";

/**
 * Ed25519-signs the canonical string for a request. Stateless: caller
 * supplies timestamp/nonce via params and reads them back off the same
 * object to build the X-Timestamp/X-Nonce headers.
 */
export function signRequest(params: CanonicalRequestParams, identityPrivateKey: Uint8Array): Uint8Array {
  const message = crypto.utf8Encode(buildCanonicalString(params));
  return crypto.sign(identityPrivateKey, message);
}

/**
 * Verifies an Ed25519 request signature against the same canonical string.
 * Returns false for a well-formed-but-wrong signature; throws (via
 * crypto.verify -> libsodium) if signature/public key have an invalid byte
 * length. No nonce-replay or timestamp-window checks — those require
 * persistent state and belong in packages/server.
 */
export function verifyRequest(
  params: CanonicalRequestParams,
  identityPublicKey: Uint8Array,
  signature: Uint8Array,
): boolean {
  const message = crypto.utf8Encode(buildCanonicalString(params));
  return crypto.verify(identityPublicKey, message, signature);
}
