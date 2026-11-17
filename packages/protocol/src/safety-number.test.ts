import * as crypto from "@messager/crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { computeSafetyNumber, keyFingerprint, type SafetyNumberKeys } from "./safety-number.js";

beforeAll(async () => {
  await crypto.ready;
});

function randomKeys(): SafetyNumberKeys {
  return {
    identityPublicKey: crypto.generateIdentityKeyPair().publicKey,
    ratchetPublicKey: crypto.randomBytes(32),
  };
}

const FIXED_A: SafetyNumberKeys = {
  identityPublicKey: new Uint8Array(32).fill(1),
  ratchetPublicKey: new Uint8Array(32).fill(2),
};
const FIXED_B: SafetyNumberKeys = {
  identityPublicKey: new Uint8Array(32).fill(3),
  ratchetPublicKey: new Uint8Array(32).fill(4),
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
    expect(keyFingerprint(FIXED_A)).toBe("454602193328691609857958431761");
    expect(keyFingerprint(FIXED_B)).toBe("877537721943452803081335283211");
    expect(computeSafetyNumber(FIXED_A, FIXED_B)).toBe("45460 21933 28691 60985 79584 31761 87753 77219 43452 80308 13352 83211");
  });

  it("changes when either user's ratchet key is swapped", () => {
    const a = randomKeys();
    const b = randomKeys();
    const original = computeSafetyNumber(a, b);
    const swapped = crypto.randomBytes(32);
    expect(computeSafetyNumber(a, { ...b, ratchetPublicKey: swapped })).not.toBe(original);
    expect(computeSafetyNumber({ ...a, ratchetPublicKey: swapped }, b)).not.toBe(original);
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
    const flipped = { identityPublicKey: keys.ratchetPublicKey, ratchetPublicKey: keys.identityPublicKey };
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
      const fingerprint = keyFingerprint({ ...FIXED_A, ratchetPublicKey: new Uint8Array(32).fill(i) });
      expect(fingerprint).toHaveLength(30);
      expect(fingerprint).toMatch(/^\d{30}$/);
    }
  });

  it("refuses keys of the wrong length", () => {
    expect(() => keyFingerprint({ ...FIXED_A, ratchetPublicKey: new Uint8Array(31) })).toThrow();
    expect(() => computeSafetyNumber(FIXED_A, { ...FIXED_B, identityPublicKey: new Uint8Array(33) })).toThrow();
  });
});
