import * as crypto from "@messager/crypto";
import { deriveUserId } from "@messager/protocol";

export const IDENTITY_PRIVATE_KEY_BYTES = 64;

/** This device's keys. The private keys never leave the browser. */
export interface StoredIdentity {
  userId: string;
  /** Ed25519: signs API requests. */
  identityPublicKey: Uint8Array;
  identityPrivateKey: Uint8Array;
  /** X25519: derives the per-contact message keys. */
  exchangePublicKey: Uint8Array;
  exchangePrivateKey: Uint8Array;
  /** Unix ms. */
  createdAt: number;
  /** Unix ms; null until the server has accepted the registration. */
  registeredAt: number | null;
}

/** Generates a brand-new identity. Requires `crypto.ready` to have resolved. */
export function createIdentity(now: number): StoredIdentity {
  const identity = crypto.generateIdentityKeyPair();
  const exchange = crypto.generateExchangeKeyPair();
  return {
    userId: deriveUserId(identity.publicKey),
    identityPublicKey: identity.publicKey,
    identityPrivateKey: identity.privateKey,
    exchangePublicKey: exchange.publicKey,
    exchangePrivateKey: exchange.privateKey,
    createdAt: now,
    registeredAt: null,
  };
}

function isBytes(value: unknown, length: number): value is Uint8Array {
  return value instanceof Uint8Array && value.length === length;
}

/** True only for a complete identity whose userID really is derived from its identity key. */
export function isValidIdentity(value: unknown): value is StoredIdentity {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    typeof v.userId === "string" &&
    isBytes(v.identityPublicKey, crypto.IDENTITY_PUBLIC_KEY_BYTES) &&
    isBytes(v.identityPrivateKey, IDENTITY_PRIVATE_KEY_BYTES) &&
    isBytes(v.exchangePublicKey, crypto.EXCHANGE_KEY_BYTES) &&
    isBytes(v.exchangePrivateKey, crypto.EXCHANGE_KEY_BYTES) &&
    typeof v.createdAt === "number" &&
    (v.registeredAt === null || typeof v.registeredAt === "number") &&
    deriveUserId(v.identityPublicKey) === v.userId
  );
}
