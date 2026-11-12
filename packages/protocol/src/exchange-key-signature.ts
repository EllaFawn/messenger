import * as crypto from "@messager/crypto";

export const EXCHANGE_KEY_SIGNATURE_BYTES = 64;

/**
 * Domain separation: this prefix cannot begin a request-signing string
 * (those start "v1\n"), so one kind of signature can never be replayed as
 * the other.
 */
const STATEMENT_PREFIX = "messager/v1/exchange-key\n";

/** The exact bytes signed: the prefix followed by the raw exchange public key. */
export function buildExchangeKeyStatement(exchangePublicKey: Uint8Array): Uint8Array {
  if (exchangePublicKey.length !== crypto.EXCHANGE_KEY_BYTES) {
    throw new Error("exchange public key must be 32 bytes");
  }
  const prefix = crypto.utf8Encode(STATEMENT_PREFIX);
  const statement = new Uint8Array(prefix.length + exchangePublicKey.length);
  statement.set(prefix, 0);
  statement.set(exchangePublicKey, prefix.length);
  return statement;
}

/**
 * The identity key vouches for the exchange key. Because a userID is the
 * hash of the identity key, anyone who holds the right userID can check
 * that an exchange key really belongs to that user - the server cannot
 * substitute its own.
 */
export function signExchangeKey(exchangePublicKey: Uint8Array, identityPrivateKey: Uint8Array): Uint8Array {
  return crypto.sign(identityPrivateKey, buildExchangeKeyStatement(exchangePublicKey));
}

/** Never throws: malformed input is simply not a valid signature. */
export function verifyExchangeKey(
  exchangePublicKey: Uint8Array,
  signature: Uint8Array,
  identityPublicKey: Uint8Array,
): boolean {
  if (
    exchangePublicKey.length !== crypto.EXCHANGE_KEY_BYTES ||
    signature.length !== EXCHANGE_KEY_SIGNATURE_BYTES ||
    identityPublicKey.length !== crypto.IDENTITY_PUBLIC_KEY_BYTES
  ) {
    return false;
  }
  try {
    return crypto.verify(identityPublicKey, buildExchangeKeyStatement(exchangePublicKey), signature);
  } catch {
    return false;
  }
}
