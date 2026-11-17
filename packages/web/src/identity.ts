import * as crypto from "@messager/crypto";
import { deriveUserId } from "@messager/protocol";
import { PICKLE_KEY_BYTES, RATCHET_KEY_BYTES, RatchetAccount } from "@messager/ratchet";

export const IDENTITY_PRIVATE_KEY_BYTES = 64;

/** This device's keys. The private keys never leave the browser. */
export interface StoredIdentity {
  userId: string;
  /** Ed25519: signs API requests and vouches for the ratchet keys. */
  identityPublicKey: Uint8Array;
  identityPrivateKey: Uint8Array;
  /**
   * The ratchet account's long-term public key, which contacts pin. The
   * account itself (private keys, one-time keys) is stored separately because
   * it changes; this key never does.
   */
  ratchetPublicKey: Uint8Array;
  /** Encrypts the saved ratchet account and sessions. Never changes. */
  pickleKey: Uint8Array;
  /** Unix ms. */
  createdAt: number;
  /** Unix ms; null until the server has accepted the registration. */
  registeredAt: number | null;
}

/** A new ratchet account, saved under a new pickle key. Requires the ratchet module to be loaded. */
export function createRatchetAccount(): { ratchetPublicKey: Uint8Array; pickleKey: Uint8Array; accountPickle: string } {
  const account = RatchetAccount.create();
  const pickleKey = crypto.randomBytes(PICKLE_KEY_BYTES);
  return { ratchetPublicKey: account.identityKey, pickleKey, accountPickle: account.save(pickleKey) };
}

/**
 * Generates a brand-new identity and its ratchet account. Requires
 * `crypto.ready` and the ratchet module to have loaded. The account is
 * returned saved, ready to be stored with the identity.
 */
export function createIdentity(now: number): { identity: StoredIdentity; accountPickle: string } {
  const identity = crypto.generateIdentityKeyPair();
  const { ratchetPublicKey, pickleKey, accountPickle } = createRatchetAccount();
  return {
    identity: {
      userId: deriveUserId(identity.publicKey),
      identityPublicKey: identity.publicKey,
      identityPrivateKey: identity.privateKey,
      ratchetPublicKey,
      pickleKey,
      createdAt: now,
      registeredAt: null,
    },
    accountPickle,
  };
}

function isBytes(value: unknown, length: number): value is Uint8Array {
  return value instanceof Uint8Array && value.length === length;
}

/** The parts every identity has had since the first version: enough to keep the userID. */
export function hasIdentityKeys(value: unknown): value is Pick<StoredIdentity, "userId" | "identityPublicKey" | "identityPrivateKey" | "createdAt"> {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    typeof v.userId === "string" &&
    isBytes(v.identityPublicKey, crypto.IDENTITY_PUBLIC_KEY_BYTES) &&
    isBytes(v.identityPrivateKey, IDENTITY_PRIVATE_KEY_BYTES) &&
    typeof v.createdAt === "number" &&
    deriveUserId(v.identityPublicKey) === v.userId
  );
}

/** True only for a complete identity whose userID really is derived from its identity key. */
export function isValidIdentity(value: unknown): value is StoredIdentity {
  if (!hasIdentityKeys(value)) {
    return false;
  }
  const v = value as unknown as Record<string, unknown>;
  return (
    isBytes(v.ratchetPublicKey, RATCHET_KEY_BYTES) &&
    isBytes(v.pickleKey, PICKLE_KEY_BYTES) &&
    (v.registeredAt === null || typeof v.registeredAt === "number")
  );
}
