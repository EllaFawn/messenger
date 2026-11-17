import * as crypto from "@messager/crypto";

/** Length of a ratchet (Curve25519) public key: the long-term key or a one-time key. */
export const RATCHET_PUBLIC_KEY_BYTES = 32;
const SIGNATURE_BYTES = 64;

/**
 * Domain separation. Neither prefix can begin a request-signing string
 * (those start "v1\n") or the other statement, so a signature made for one
 * purpose can never be passed off as another.
 */
const RATCHET_KEY_PREFIX = "messager/v2/ratchet-key\n";
const ONE_TIME_KEY_PREFIX = "messager/v2/one-time-key\n";

function concat(prefix: string, ...keys: Uint8Array[]): Uint8Array {
  for (const key of keys) {
    if (key.length !== RATCHET_PUBLIC_KEY_BYTES) {
      throw new Error("ratchet public keys must be 32 bytes");
    }
  }
  const head = crypto.utf8Encode(prefix);
  const out = new Uint8Array(head.length + keys.length * RATCHET_PUBLIC_KEY_BYTES);
  out.set(head, 0);
  keys.forEach((key, i) => out.set(key, head.length + i * RATCHET_PUBLIC_KEY_BYTES));
  return out;
}

/** The exact bytes signed for a long-term ratchet key: the prefix, then the key. */
export function buildRatchetKeyStatement(ratchetPublicKey: Uint8Array): Uint8Array {
  return concat(RATCHET_KEY_PREFIX, ratchetPublicKey);
}

/**
 * The exact bytes signed for a one-time (or fallback) key: the prefix, the
 * owner's long-term ratchet key, then the one-time key. Including the
 * long-term key ties each one-time key to the ratchet account it was made
 * by, so a server cannot pair an old one-time key with a newer account.
 */
export function buildOneTimeKeyStatement(ratchetPublicKey: Uint8Array, oneTimeKey: Uint8Array): Uint8Array {
  return concat(ONE_TIME_KEY_PREFIX, ratchetPublicKey, oneTimeKey);
}

function verifyStatement(statement: () => Uint8Array, signature: Uint8Array, identityPublicKey: Uint8Array): boolean {
  if (signature.length !== SIGNATURE_BYTES || identityPublicKey.length !== crypto.IDENTITY_PUBLIC_KEY_BYTES) {
    return false;
  }
  try {
    return crypto.verify(identityPublicKey, statement(), signature);
  } catch {
    return false;
  }
}

/**
 * The identity key vouches for the long-term ratchet key. Because a userID
 * is the hash of the identity key, anyone who holds the right userID can
 * check a ratchet key really belongs to that user.
 */
export function signRatchetKey(ratchetPublicKey: Uint8Array, identityPrivateKey: Uint8Array): Uint8Array {
  return crypto.sign(identityPrivateKey, buildRatchetKeyStatement(ratchetPublicKey));
}

/** Never throws: malformed input is simply not a valid signature. */
export function verifyRatchetKey(
  ratchetPublicKey: Uint8Array,
  signature: Uint8Array,
  identityPublicKey: Uint8Array,
): boolean {
  return verifyStatement(() => buildRatchetKeyStatement(ratchetPublicKey), signature, identityPublicKey);
}

export function signOneTimeKey(
  ratchetPublicKey: Uint8Array,
  oneTimeKey: Uint8Array,
  identityPrivateKey: Uint8Array,
): Uint8Array {
  return crypto.sign(identityPrivateKey, buildOneTimeKeyStatement(ratchetPublicKey, oneTimeKey));
}

/** Never throws: malformed input is simply not a valid signature. */
export function verifyOneTimeKey(
  ratchetPublicKey: Uint8Array,
  oneTimeKey: Uint8Array,
  signature: Uint8Array,
  identityPublicKey: Uint8Array,
): boolean {
  return verifyStatement(
    () => buildOneTimeKeyStatement(ratchetPublicKey, oneTimeKey),
    signature,
    identityPublicKey,
  );
}
