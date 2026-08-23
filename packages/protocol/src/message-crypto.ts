import * as crypto from "@messager/crypto";
import { encodeEnvelope, decodeEnvelope, type Envelope } from "./envelope.js";
import {
  encodeMessagePlaintext,
  decodeMessagePlaintext,
  type MessagePlaintext,
} from "./message-plaintext.js";

/** salt = UTF8(sort(userIdA, userIdB).join("|")) — order-independent, shared by both directions of a pair. */
export function buildMessageSalt(userIdA: string, userIdB: string): Uint8Array {
  return crypto.utf8Encode([userIdA, userIdB].sort().join("|"));
}

/** info = "messager/v1/msg/{fromUserId}>{toUserId}" — directional, so A->B and B->A derive different keys. */
export function buildMessageInfo(fromUserId: string, toUserId: string): Uint8Array {
  return crypto.utf8Encode(`messager/v1/msg/${fromUserId}>${toUserId}`);
}

/** AD = UTF8("v1|{fromUserId}|{toUserId}") || nonce — binds direction and nonce into the AEAD tag. */
export function buildMessageAd(fromUserId: string, toUserId: string, nonce: Uint8Array): Uint8Array {
  const header = crypto.utf8Encode(`v1|${fromUserId}|${toUserId}`);
  const ad = new Uint8Array(header.length + nonce.length);
  ad.set(header, 0);
  ad.set(nonce, header.length);
  return ad;
}

/**
 * Directional per-message AEAD key from a static X25519 ECDH shared secret.
 * scalarMult is symmetric (A computing with B's pubkey == B computing with
 * A's pubkey), so both sides derive the same key given the same explicit
 * fromUserId/toUserId pair.
 */
export function deriveMessageKey(
  myExchangePrivateKey: Uint8Array,
  theirExchangePublicKey: Uint8Array,
  fromUserId: string,
  toUserId: string,
): Uint8Array {
  const sharedSecret = crypto.scalarMult(myExchangePrivateKey, theirExchangePublicKey);
  const prk = crypto.hkdfExtract(buildMessageSalt(fromUserId, toUserId), sharedSecret);
  return crypto.hkdfExpand(prk, buildMessageInfo(fromUserId, toUserId), crypto.AEAD_KEY_BYTES);
}

export interface EncryptMessageParams {
  message: MessagePlaintext;
  fromUserId: string;
  toUserId: string;
  myExchangePrivateKey: Uint8Array;
  theirExchangePublicKey: Uint8Array;
  /** Overrides the random nonce. For deterministic/golden tests only — never reuse a nonce for a real message under the same key. */
  nonce?: Uint8Array;
}

export function encryptMessage(params: EncryptMessageParams): Envelope {
  const nonce = params.nonce ?? crypto.randomBytes(crypto.AEAD_NONCE_BYTES);
  const key = deriveMessageKey(
    params.myExchangePrivateKey,
    params.theirExchangePublicKey,
    params.fromUserId,
    params.toUserId,
  );
  const ad = buildMessageAd(params.fromUserId, params.toUserId, nonce);
  const plaintext = encodeMessagePlaintext(params.message);
  const ciphertext = crypto.aeadEncrypt(key, nonce, plaintext, ad);
  return encodeEnvelope(params.toUserId, nonce, ciphertext);
}

export interface DecryptMessageParams {
  envelope: Envelope;
  fromUserId: string;
  toUserId: string;
  myExchangePrivateKey: Uint8Array;
  theirExchangePublicKey: Uint8Array;
}

export function decryptMessage(params: DecryptMessageParams): MessagePlaintext {
  const decoded = decodeEnvelope(params.envelope);
  if (decoded.to !== params.toUserId) {
    throw new Error("decryptMessage: envelope is addressed to a different recipient");
  }
  const key = deriveMessageKey(
    params.myExchangePrivateKey,
    params.theirExchangePublicKey,
    params.fromUserId,
    params.toUserId,
  );
  const ad = buildMessageAd(params.fromUserId, params.toUserId, decoded.nonce);
  const plaintext = crypto.aeadDecrypt(key, decoded.nonce, decoded.ciphertext, ad);
  return decodeMessagePlaintext(plaintext);
}
