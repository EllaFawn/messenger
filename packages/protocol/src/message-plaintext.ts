import * as crypto from "@messager/crypto";

/**
 * Decrypted message body, JSON-encoded before encryption. There is no
 * counter: the ratchet gives every message its own key and rejects repeats.
 */
export interface MessagePlaintext {
  text: string;
  /** Unix timestamp in milliseconds, as stated by the sender. */
  sentAt: number;
}

export function encodeMessagePlaintext(message: MessagePlaintext): Uint8Array {
  return crypto.utf8Encode(JSON.stringify({ text: message.text, sentAt: message.sentAt }));
}

/** Throws unless the bytes are a JSON object with a string `text` and a numeric `sentAt`. Other fields are dropped. */
export function decodeMessagePlaintext(bytes: Uint8Array): MessagePlaintext {
  const parsed: unknown = JSON.parse(crypto.utf8Decode(bytes));
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("invalid message plaintext");
  }
  const { text, sentAt } = parsed as Record<string, unknown>;
  if (typeof text !== "string" || typeof sentAt !== "number") {
    throw new Error("invalid message plaintext");
  }
  return { text, sentAt };
}
