import * as crypto from "@messager/crypto";

/** Decrypted message body, JSON-encoded before encryption. */
export interface MessagePlaintext {
  /** Per-(sender->recipient) monotonic counter, maintained by the sender. */
  counter: number;
  text: string;
  /** Unix timestamp in milliseconds. */
  sentAt: number;
}

export function encodeMessagePlaintext(message: MessagePlaintext): Uint8Array {
  return crypto.utf8Encode(JSON.stringify(message));
}

export function decodeMessagePlaintext(bytes: Uint8Array): MessagePlaintext {
  const parsed: unknown = JSON.parse(crypto.utf8Decode(bytes));
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    typeof (parsed as MessagePlaintext).counter !== "number" ||
    typeof (parsed as MessagePlaintext).text !== "string" ||
    typeof (parsed as MessagePlaintext).sentAt !== "number"
  ) {
    throw new Error("invalid message plaintext");
  }
  return parsed as MessagePlaintext;
}
