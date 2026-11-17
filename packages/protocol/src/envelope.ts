import * as crypto from "@messager/crypto";

/** 0: a pre-key message, which can create the session. 1: a normal message in an established session. */
export type RatchetMessageType = 0 | 1;

/**
 * Wire envelope for a message POST body. Version 2 carries a ratchet
 * message; version 1 (static keys, with a separate nonce) is no longer
 * accepted anywhere.
 */
export interface Envelope {
  v: 2;
  to: string;
  type: RatchetMessageType;
  /** Standard base64 of the ratchet message. */
  ciphertext: string;
}

export interface DecodedEnvelope {
  to: string;
  type: RatchetMessageType;
  body: Uint8Array;
}

function checkType(type: unknown): asserts type is RatchetMessageType {
  if (type !== 0 && type !== 1) {
    throw new Error("unknown ratchet message type");
  }
}

export function encodeEnvelope(to: string, message: { type: RatchetMessageType; body: Uint8Array }): Envelope {
  checkType(message.type);
  return { v: 2, to, type: message.type, ciphertext: crypto.toBase64(message.body) };
}

export function decodeEnvelope(envelope: Envelope): DecodedEnvelope {
  if (envelope.v !== 2) {
    throw new Error(`unsupported envelope version: ${String(envelope.v)}`);
  }
  checkType(envelope.type);
  return { to: envelope.to, type: envelope.type, body: crypto.fromBase64(envelope.ciphertext) };
}
