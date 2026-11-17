import * as crypto from "@messager/crypto";
import { beforeAll, describe, expect, it } from "vitest";
import {
  buildOneTimeKeyStatement,
  buildRatchetKeyStatement,
  signOneTimeKey,
  signRatchetKey,
  verifyOneTimeKey,
  verifyRatchetKey,
} from "./ratchet-key-signature.js";
import { signRequest } from "./request-signing.js";

beforeAll(async () => {
  await crypto.ready;
});

const key = (fill: number) => new Uint8Array(32).fill(fill);
// Identity key from RFC 8032 TEST 1.
const fixedIdentity = () =>
  crypto.identityKeyPairFromSeed(crypto.fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));

describe("ratchet key signature", () => {
  it("verifies a key signed by the matching identity key", () => {
    const identity = crypto.generateIdentityKeyPair();
    const signature = signRatchetKey(key(1), identity.privateKey);
    expect(signature).toHaveLength(64);
    expect(verifyRatchetKey(key(1), signature, identity.publicKey)).toBe(true);
  });

  it("signs the prefix followed by the key, and matches a fixed value", () => {
    const statement = buildRatchetKeyStatement(key(1));
    expect(crypto.utf8Decode(statement.slice(0, -32))).toBe("messager/v2/ratchet-key\n");
    expect(crypto.toHex(statement.slice(-32))).toBe(crypto.toHex(key(1)));
    // Pinned: changing the statement would invalidate every stored signature.
    expect(crypto.toHex(signRatchetKey(key(1), fixedIdentity().privateKey))).toBe(
      "0f2e702600947e5618185a50afd1ffc97046ec596ab0a08c55070003b507a3c5" +
        "475be4227b3fadd382c137b1eb5e29451fd5595db5222536c70c5ecc5083f30b",
    );
  });

  it("rejects a substituted key, a different signer and a flipped bit", () => {
    const identity = crypto.generateIdentityKeyPair();
    const signature = signRatchetKey(key(1), identity.privateKey);
    expect(verifyRatchetKey(key(2), signature, identity.publicKey)).toBe(false);
    expect(verifyRatchetKey(key(1), signature, crypto.generateIdentityKeyPair().publicKey)).toBe(false);
    signature[5]! ^= 1;
    expect(verifyRatchetKey(key(1), signature, identity.publicKey)).toBe(false);
  });

  it("returns false, without throwing, for inputs of the wrong length", () => {
    const identity = crypto.generateIdentityKeyPair();
    const signature = signRatchetKey(key(1), identity.privateKey);
    expect(verifyRatchetKey(key(1).slice(1), signature, identity.publicKey)).toBe(false);
    expect(verifyRatchetKey(key(1), signature.slice(1), identity.publicKey)).toBe(false);
    expect(verifyRatchetKey(key(1), signature, identity.publicKey.slice(1))).toBe(false);
  });

  it("refuses to sign a key of the wrong length", () => {
    expect(() => signRatchetKey(new Uint8Array(31), crypto.generateIdentityKeyPair().privateKey)).toThrow();
  });
});

describe("one-time key signature", () => {
  it("verifies a one-time key signed for a given ratchet key", () => {
    const identity = crypto.generateIdentityKeyPair();
    const signature = signOneTimeKey(key(1), key(7), identity.privateKey);
    expect(verifyOneTimeKey(key(1), key(7), signature, identity.publicKey)).toBe(true);
  });

  it("signs the prefix, the ratchet key, then the one-time key, and matches a fixed value", () => {
    const statement = buildOneTimeKeyStatement(key(1), key(7));
    expect(crypto.utf8Decode(statement.slice(0, -64))).toBe("messager/v2/one-time-key\n");
    expect(crypto.toHex(statement.slice(-64, -32))).toBe(crypto.toHex(key(1)));
    expect(crypto.toHex(statement.slice(-32))).toBe(crypto.toHex(key(7)));
    expect(crypto.toHex(signOneTimeKey(key(1), key(7), fixedIdentity().privateKey))).toBe(
      "a6997bc60232460bf9ddf44b6672e022d2c5e46389268f5cff278fbbb8ad3cb6" +
        "1ae9d5c31881248d7391af8ed44bcd5a52a92e8f07f318b5f832019a89e17104",
    );
  });

  it("is tied to the ratchet key it was made for", () => {
    const identity = crypto.generateIdentityKeyPair();
    const signature = signOneTimeKey(key(1), key(7), identity.privateKey);
    // The same one-time key offered alongside a different (say, newer) ratchet key does not verify.
    expect(verifyOneTimeKey(key(2), key(7), signature, identity.publicKey)).toBe(false);
  });

  it("rejects a substituted one-time key and a different signer", () => {
    const identity = crypto.generateIdentityKeyPair();
    const signature = signOneTimeKey(key(1), key(7), identity.privateKey);
    expect(verifyOneTimeKey(key(1), key(8), signature, identity.publicKey)).toBe(false);
    expect(verifyOneTimeKey(key(1), key(7), signature, crypto.generateIdentityKeyPair().publicKey)).toBe(false);
  });

  it("does not accept the two keys in the other order", () => {
    const identity = crypto.generateIdentityKeyPair();
    const signature = signOneTimeKey(key(1), key(7), identity.privateKey);
    expect(verifyOneTimeKey(key(7), key(1), signature, identity.publicKey)).toBe(false);
  });

  it("returns false, without throwing, for inputs of the wrong length", () => {
    const identity = crypto.generateIdentityKeyPair();
    const signature = signOneTimeKey(key(1), key(7), identity.privateKey);
    expect(verifyOneTimeKey(key(1).slice(1), key(7), signature, identity.publicKey)).toBe(false);
    expect(verifyOneTimeKey(key(1), new Uint8Array(0), signature, identity.publicKey)).toBe(false);
    expect(verifyOneTimeKey(key(1), key(7), new Uint8Array(63), identity.publicKey)).toBe(false);
  });
});

describe("signatures for different purposes cannot be swapped", () => {
  it("keeps ratchet-key, one-time-key, retired exchange-key and request signatures apart", () => {
    const identity = crypto.generateIdentityKeyPair();
    const ratchetSig = signRatchetKey(key(1), identity.privateKey);
    const oneTimeSig = signOneTimeKey(key(1), key(1), identity.privateKey);
    // The statement the retired static exchange key was signed with (M1).
    const oldPrefix = crypto.utf8Encode("messager/v1/exchange-key\n");
    const oldStatement = new Uint8Array(oldPrefix.length + 32);
    oldStatement.set(oldPrefix, 0);
    oldStatement.set(key(1), oldPrefix.length);
    const exchangeSig = crypto.sign(identity.privateKey, oldStatement);
    const requestSig = signRequest(
      { method: "POST", path: "/keys/one-time", rawBody: key(1), timestamp: 1, nonce: "n" },
      identity.privateKey,
    );

    expect(verifyRatchetKey(key(1), oneTimeSig, identity.publicKey)).toBe(false);
    expect(verifyRatchetKey(key(1), exchangeSig, identity.publicKey)).toBe(false);
    expect(verifyRatchetKey(key(1), requestSig, identity.publicKey)).toBe(false);
    expect(verifyOneTimeKey(key(1), key(1), ratchetSig, identity.publicKey)).toBe(false);
    expect(verifyOneTimeKey(key(1), key(1), exchangeSig, identity.publicKey)).toBe(false);
  });
});
