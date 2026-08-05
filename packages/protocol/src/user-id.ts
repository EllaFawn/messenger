import * as crypto from "@messager/crypto";

/** userID = base64url(SHA-256(identity_pubkey)) — a lookup pointer, not a credential. */
export function deriveUserId(identityPublicKey: Uint8Array): string {
  return crypto.toBase64Url(crypto.sha256(identityPublicKey));
}
