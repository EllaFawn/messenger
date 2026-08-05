import { beforeAll, describe, expect, it } from "vitest";
import * as crypto from "@messager/crypto";
import { deriveUserId } from "./user-id.js";
import { buildCanonicalString } from "./canonical-request.js";
import { encodeEnvelope, decodeEnvelope } from "./envelope.js";
import { encodeMessagePlaintext, decodeMessagePlaintext } from "./message-plaintext.js";

beforeAll(async () => {
  await crypto.ready;
});

describe("deriveUserId", () => {
  it("matches base64url(SHA-256(identity_pubkey)) for a known key", () => {
    // Ed25519 public key from RFC 8032 TEST 1.
    const identityPubkey = crypto.fromHex(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    );
    const expectedHash = crypto.sha256(identityPubkey);
    const expectedUserId = crypto.toBase64Url(expectedHash);

    expect(deriveUserId(identityPubkey)).toBe(expectedUserId);
    // Deterministic and stable across calls.
    expect(deriveUserId(identityPubkey)).toBe(deriveUserId(identityPubkey));
  });

  it("produces different ids for different keys", () => {
    const a = crypto.fromHex(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    );
    const b = crypto.fromHex(
      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    );
    expect(deriveUserId(a)).not.toBe(deriveUserId(b));
  });
});

describe("buildCanonicalString (golden)", () => {
  it("matches the fixed format for an empty-body GET", () => {
    // SHA-256("") — verified via Node's crypto module, not hand-transcribed.
    const emptyBodyHashHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    const result = buildCanonicalString({
      method: "get",
      path: "/messages/inbox",
      rawBody: new Uint8Array(0),
      timestamp: 1754400000000,
      nonce: "AAAAAAAAAAAAAAAAAAAAAA==",
    });

    expect(result).toBe(
      `v1\nGET\n/messages/inbox\n${emptyBodyHashHex}\n1754400000000\nAAAAAAAAAAAAAAAAAAAAAA==`,
    );
  });

  it("produces identical bytes from independent call sites (signer vs verifier)", () => {
    const params = {
      method: "POST",
      path: "/messages",
      rawBody: crypto.utf8Encode('{"v":1,"to":"abc","nonce":"n","ciphertext":"c"}'),
      timestamp: Date.now(),
      nonce: crypto.toBase64(crypto.randomBytes(16)),
    };

    // Simulates the client building the string to sign and the server
    // independently rebuilding it to verify — same function, same inputs.
    const clientSide = buildCanonicalString(params);
    const serverSide = buildCanonicalString({ ...params });

    expect(clientSide).toBe(serverSide);
  });

  it("changes when method, path, body, timestamp, or nonce change", () => {
    const base = buildCanonicalString({
      method: "POST",
      path: "/messages",
      rawBody: crypto.utf8Encode("{}"),
      timestamp: 1,
      nonce: "nonce",
    });

    expect(buildCanonicalString({ method: "GET", path: "/messages", rawBody: crypto.utf8Encode("{}"), timestamp: 1, nonce: "nonce" })).not.toBe(base);
    expect(buildCanonicalString({ method: "POST", path: "/other", rawBody: crypto.utf8Encode("{}"), timestamp: 1, nonce: "nonce" })).not.toBe(base);
    expect(buildCanonicalString({ method: "POST", path: "/messages", rawBody: crypto.utf8Encode('{"a":1}'), timestamp: 1, nonce: "nonce" })).not.toBe(base);
    expect(buildCanonicalString({ method: "POST", path: "/messages", rawBody: crypto.utf8Encode("{}"), timestamp: 2, nonce: "nonce" })).not.toBe(base);
    expect(buildCanonicalString({ method: "POST", path: "/messages", rawBody: crypto.utf8Encode("{}"), timestamp: 1, nonce: "other" })).not.toBe(base);
  });
});

describe("envelope encode/decode", () => {
  it("round-trips to/nonce/ciphertext", () => {
    const to = "some-user-id";
    const nonce = crypto.randomBytes(24);
    const ciphertext = crypto.utf8Encode("opaque-ciphertext-bytes");

    const envelope = encodeEnvelope(to, nonce, ciphertext);
    expect(envelope.v).toBe(1);
    expect(typeof envelope.nonce).toBe("string");
    expect(typeof envelope.ciphertext).toBe("string");

    const decoded = decodeEnvelope(envelope);
    expect(decoded.to).toBe(to);
    expect(crypto.toHex(decoded.nonce)).toBe(crypto.toHex(nonce));
    expect(crypto.toHex(decoded.ciphertext)).toBe(crypto.toHex(ciphertext));
  });

  it("rejects an unsupported version", () => {
    const envelope = encodeEnvelope("u", crypto.randomBytes(24), crypto.utf8Encode("x"));
    // @ts-expect-error deliberately corrupting the version for the test
    envelope.v = 2;
    expect(() => decodeEnvelope(envelope)).toThrow();
  });
});

describe("message plaintext encode/decode", () => {
  it("round-trips counter/text/sentAt", () => {
    const message = { counter: 42, text: "hello", sentAt: 1754400000000 };
    const bytes = encodeMessagePlaintext(message);
    expect(decodeMessagePlaintext(bytes)).toEqual(message);
  });

  it("rejects malformed plaintext", () => {
    expect(() => decodeMessagePlaintext(crypto.utf8Encode('{"counter":1}'))).toThrow();
    expect(() => decodeMessagePlaintext(crypto.utf8Encode("not json"))).toThrow();
  });
});
