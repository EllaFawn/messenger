import * as crypto from "@messager/crypto";

/** Wire envelope for a message POST body, versioned for M2 coexistence. */
export interface Envelope {
  v: 1;
  to: string;
  nonce: string;
  ciphertext: string;
}

export interface DecodedEnvelope {
  to: string;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

export function encodeEnvelope(to: string, nonce: Uint8Array, ciphertext: Uint8Array): Envelope {
  return {
    v: 1,
    to,
    nonce: crypto.toBase64(nonce),
    ciphertext: crypto.toBase64(ciphertext),
  };
}

export function decodeEnvelope(envelope: Envelope): DecodedEnvelope {
  if (envelope.v !== 1) {
    throw new Error(`unsupported envelope version: ${envelope.v}`);
  }
  return {
    to: envelope.to,
    nonce: crypto.fromBase64(envelope.nonce),
    ciphertext: crypto.fromBase64(envelope.ciphertext),
  };
}
