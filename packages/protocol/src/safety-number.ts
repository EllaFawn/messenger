import * as crypto from "@messager/crypto";

/** One user's public keys, as covered by the safety number. */
export interface SafetyNumberKeys {
  identityPublicKey: Uint8Array;
  exchangePublicKey: Uint8Array;
}

const PREFIX = "messager/v1/safety-number\n";
const GROUP_DIGITS = 5;
const GROUPS_PER_USER = 6;
const BYTES_PER_GROUP = 5;

/**
 * 30 digits derived from one user's identity AND exchange keys. Covering the
 * exchange key matters: it is the key that encrypts messages, so a swapped
 * exchange key must change the number.
 */
export function keyFingerprint(keys: SafetyNumberKeys): string {
  if (
    keys.identityPublicKey.length !== crypto.IDENTITY_PUBLIC_KEY_BYTES ||
    keys.exchangePublicKey.length !== crypto.EXCHANGE_KEY_BYTES
  ) {
    throw new Error("safety number needs a 32-byte identity key and a 32-byte exchange key");
  }
  const prefix = crypto.utf8Encode(PREFIX);
  const input = new Uint8Array(prefix.length + 64);
  input.set(prefix, 0);
  input.set(keys.identityPublicKey, prefix.length);
  input.set(keys.exchangePublicKey, prefix.length + 32);
  const hash = crypto.sha256(input);

  let digits = "";
  for (let group = 0; group < GROUPS_PER_USER; group++) {
    // Five bytes as a big-endian number, reduced to five decimal digits.
    let value = 0;
    for (let i = 0; i < BYTES_PER_GROUP; i++) {
      value = value * 256 + hash[group * BYTES_PER_GROUP + i]!;
    }
    digits += String(value % 10 ** GROUP_DIGITS).padStart(GROUP_DIGITS, "0");
  }
  return digits;
}

/**
 * The number two users compare out of band: twelve groups of five digits.
 * Each half depends on one user's keys only (so an attacker would have to
 * match a specific 30-digit value, not merely find any colliding pair), and
 * the halves are ordered so both users see the same number.
 */
export function computeSafetyNumber(a: SafetyNumberKeys, b: SafetyNumberKeys): string {
  const halves = [keyFingerprint(a), keyFingerprint(b)].sort();
  const digits = halves.join("");
  const groups: string[] = [];
  for (let i = 0; i < digits.length; i += GROUP_DIGITS) {
    groups.push(digits.slice(i, i + GROUP_DIGITS));
  }
  return groups.join(" ");
}
