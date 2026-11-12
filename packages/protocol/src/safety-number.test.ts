import * as crypto from "@messager/crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { computeSafetyNumber, keyFingerprint, type SafetyNumberKeys } from "./safety-number.js";

beforeAll(async () => {
  await crypto.ready;
});

function randomKeys(): SafetyNumberKeys {
  return {
    identityPublicKey: crypto.generateIdentityKeyPair().publicKey,
    exchangePublicKey: crypto.generateExchangeKeyPair().publicKey,
  };
}

const FIXED_A: SafetyNumberKeys = {
  identityPublicKey: new Uint8Array(32).fill(1),
  exchangePublicKey: new Uint8Array(32).fill(2),
};
const FIXED_B: SafetyNumberKeys = {
  identityPublicKey: new Uint8Array(32).fill(3),
  exchangePublicKey: new Uint8Array(32).fill(4),
};

describe("safety number", () => {
  it("is twelve groups of five digits", () => {
    expect(computeSafetyNumber(randomKeys(), randomKeys())).toMatch(/^\d{5}( \d{5}){11}$/);
  });

  it("is the same whichever user computes it", () => {
    const a = randomKeys();
    const b = randomKeys();
    expect(computeSafetyNumber(a, b)).toBe(computeSafetyNumber(b, a));
  });

  it("matches fixed values", () => {
    // Pinned: changing the derivation would make every pair's number change.
    expect(keyFingerprint(FIXED_A)).toBe("101497340341902156561904816833");
    expect(keyFingerprint(FIXED_B)).toBe("511224359483142768556075042734");
    expect(computeSafetyNumber(FIXED_A, FIXED_B)).toBe("10149 73403 41902 15656 19048 16833 51122 43594 83142 76855 60750 42734");
  });

  it("changes when either user's exchange key is swapped", () => {
    const a = randomKeys();
    const b = randomKeys();
    const original = computeSafetyNumber(a, b);
    const swapped = crypto.generateExchangeKeyPair().publicKey;
    expect(computeSafetyNumber(a, { ...b, exchangePublicKey: swapped })).not.toBe(original);
    expect(computeSafetyNumber({ ...a, exchangePublicKey: swapped }, b)).not.toBe(original);
  });

  it("changes when either user's identity key is swapped", () => {
    const a = randomKeys();
    const b = randomKeys();
    const original = computeSafetyNumber(a, b);
    const swapped = crypto.generateIdentityKeyPair().publicKey;
    expect(computeSafetyNumber(a, { ...b, identityPublicKey: swapped })).not.toBe(original);
    expect(computeSafetyNumber({ ...a, identityPublicKey: swapped }, b)).not.toBe(original);
  });

  it("does not treat the two keys as interchangeable", () => {
    const keys = randomKeys();
    const flipped = { identityPublicKey: keys.exchangePublicKey, exchangePublicKey: keys.identityPublicKey };
    expect(keyFingerprint(flipped)).not.toBe(keyFingerprint(keys));
  });

  it("gives each user a half that depends only on their own keys", () => {
    const a = randomKeys();
    const withB = computeSafetyNumber(a, randomKeys()).replaceAll(" ", "");
    const withC = computeSafetyNumber(a, randomKeys()).replaceAll(" ", "");
    expect(withB).toContain(keyFingerprint(a));
    expect(withC).toContain(keyFingerprint(a));
  });

  it("keeps leading zeros in a group", () => {
    // Across 200 keys some groups are certain to start with 0; every one must still be 30 digits.
    for (let i = 0; i < 200; i++) {
      const fingerprint = keyFingerprint({ ...FIXED_A, exchangePublicKey: new Uint8Array(32).fill(i) });
      expect(fingerprint).toHaveLength(30);
      expect(fingerprint).toMatch(/^\d{30}$/);
    }
  });

  it("refuses keys of the wrong length", () => {
    expect(() => keyFingerprint({ ...FIXED_A, exchangePublicKey: new Uint8Array(31) })).toThrow();
    expect(() => computeSafetyNumber(FIXED_A, { ...FIXED_B, identityPublicKey: new Uint8Array(33) })).toThrow();
  });
});
