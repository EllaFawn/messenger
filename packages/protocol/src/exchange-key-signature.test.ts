import * as crypto from "@messager/crypto";
import { beforeAll, describe, expect, it } from "vitest";
import {
  buildExchangeKeyStatement,
  EXCHANGE_KEY_SIGNATURE_BYTES,
  signExchangeKey,
  verifyExchangeKey,
} from "./exchange-key-signature.js";
import { signRequest } from "./request-signing.js";

beforeAll(async () => {
  await crypto.ready;
});

describe("exchange key signature", () => {
  it("verifies a key signed by the matching identity key", () => {
    const identity = crypto.generateIdentityKeyPair();
    const exchange = crypto.generateExchangeKeyPair();
    const signature = signExchangeKey(exchange.publicKey, identity.privateKey);
    expect(signature).toHaveLength(EXCHANGE_KEY_SIGNATURE_BYTES);
    expect(verifyExchangeKey(exchange.publicKey, signature, identity.publicKey)).toBe(true);
  });

  it("is deterministic and matches a fixed vector", () => {
    // Identity key from RFC 8032 TEST 1; exchange key is 32 bytes of 0x01.
    const identity = crypto.identityKeyPairFromSeed(
      crypto.fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
    );
    const exchangeKey = new Uint8Array(32).fill(1);
    expect(crypto.utf8Decode(buildExchangeKeyStatement(exchangeKey).slice(0, 25))).toBe(
      "messager/v1/exchange-key\n",
    );
    expect(buildExchangeKeyStatement(exchangeKey)).toHaveLength(25 + 32);
    const signature = signExchangeKey(exchangeKey, identity.privateKey);
    // Pinned so any change to the signed statement is noticed: it would break every existing account.
    expect(crypto.toHex(signature)).toBe(
      "3612bdf59e7b33daf68b98c93b9981b951fb369ff53293a218de6e2697233b9e" +
        "868521ac3d54eb52d2effedb58f93d51255cfa2079785e6b02103b781cb88303",
    );
    expect(verifyExchangeKey(exchangeKey, signature, identity.publicKey)).toBe(true);
  });

  it("rejects a substituted exchange key", () => {
    const identity = crypto.generateIdentityKeyPair();
    const signature = signExchangeKey(crypto.generateExchangeKeyPair().publicKey, identity.privateKey);
    const attackerKey = crypto.generateExchangeKeyPair().publicKey;
    expect(verifyExchangeKey(attackerKey, signature, identity.publicKey)).toBe(false);
  });

  it("rejects a signature made by a different identity key", () => {
    const exchangeKey = crypto.generateExchangeKeyPair().publicKey;
    const signature = signExchangeKey(exchangeKey, crypto.generateIdentityKeyPair().privateKey);
    expect(verifyExchangeKey(exchangeKey, signature, crypto.generateIdentityKeyPair().publicKey)).toBe(false);
  });

  it("rejects a signature with a flipped bit", () => {
    const identity = crypto.generateIdentityKeyPair();
    const exchangeKey = crypto.generateExchangeKeyPair().publicKey;
    const signature = signExchangeKey(exchangeKey, identity.privateKey);
    signature[10]! ^= 1;
    expect(verifyExchangeKey(exchangeKey, signature, identity.publicKey)).toBe(false);
  });

  it("returns false, without throwing, for inputs of the wrong length", () => {
    const identity = crypto.generateIdentityKeyPair();
    const exchangeKey = crypto.generateExchangeKeyPair().publicKey;
    const signature = signExchangeKey(exchangeKey, identity.privateKey);
    expect(verifyExchangeKey(exchangeKey.slice(0, 31), signature, identity.publicKey)).toBe(false);
    expect(verifyExchangeKey(exchangeKey, signature.slice(0, 63), identity.publicKey)).toBe(false);
    expect(verifyExchangeKey(exchangeKey, signature, identity.publicKey.slice(0, 31))).toBe(false);
    expect(verifyExchangeKey(exchangeKey, new Uint8Array(0), identity.publicKey)).toBe(false);
  });

  it("refuses to sign a key of the wrong length", () => {
    const identity = crypto.generateIdentityKeyPair();
    expect(() => signExchangeKey(new Uint8Array(31), identity.privateKey)).toThrow();
  });

  it("cannot be confused with a request signature", () => {
    // A signed API request must never double as an exchange-key signature, or the reverse.
    const identity = crypto.generateIdentityKeyPair();
    const exchangeKey = crypto.generateExchangeKeyPair().publicKey;
    const requestSignature = signRequest(
      { method: "POST", path: "/register", rawBody: exchangeKey, timestamp: 1, nonce: "n" },
      identity.privateKey,
    );
    expect(verifyExchangeKey(exchangeKey, requestSignature, identity.publicKey)).toBe(false);
  });
});
