import { beforeAll, describe, expect, it } from "vitest";
import * as crypto from "@messager/crypto";
import { signRequest, verifyRequest } from "./request-signing.js";
import { buildCanonicalString, type CanonicalRequestParams } from "./canonical-request.js";

beforeAll(async () => {
  await crypto.ready;
});

function baseParams(): CanonicalRequestParams {
  return {
    method: "POST",
    path: "/messages",
    rawBody: crypto.utf8Encode('{"v":1,"to":"abc","nonce":"n","ciphertext":"c"}'),
    timestamp: 1754400000000,
    nonce: crypto.toBase64(crypto.randomBytes(16)),
  };
}

describe("signRequest / verifyRequest round-trip", () => {
  it("verifies a signature produced for the same params and matching keypair", () => {
    const kp = crypto.generateIdentityKeyPair();
    const params = baseParams();

    const signature = signRequest(params, kp.privateKey);

    expect(verifyRequest(params, kp.publicKey, signature)).toBe(true);
  });

  it("still verifies when the verifier rebuilds params as an independent object", () => {
    const kp = crypto.generateIdentityKeyPair();
    const params = baseParams();

    const signature = signRequest(params, kp.privateKey);
    const rebuilt = { ...params };

    expect(verifyRequest(rebuilt, kp.publicKey, signature)).toBe(true);
  });
});

describe("signRequest (golden by recomputation)", () => {
  it("matches an independent Ed25519 signature over the same canonical string", () => {
    // RFC 8032 §7.1 TEST 1 seed, reused from crypto.test.ts, so the keypair
    // this test relies on is itself externally verified.
    const seed = crypto.fromHex(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    );
    const kp = crypto.identityKeyPairFromSeed(seed);
    const params: CanonicalRequestParams = {
      method: "get",
      path: "/messages/inbox",
      rawBody: new Uint8Array(0),
      timestamp: 1754400000000,
      nonce: "AAAAAAAAAAAAAAAAAAAAAA==",
    };

    // Ed25519 signing is deterministic, so signing the same canonical string
    // independently (bypassing signRequest) must produce byte-identical output.
    const expectedSignature = crypto.sign(kp.privateKey, crypto.utf8Encode(buildCanonicalString(params)));

    const signature = signRequest(params, kp.privateKey);

    expect(crypto.toHex(signature)).toBe(crypto.toHex(expectedSignature));
    expect(verifyRequest(params, kp.publicKey, signature)).toBe(true);
  });
});

describe("verifyRequest negative/tamper cases", () => {
  it("rejects when method is changed after signing", () => {
    const kp = crypto.generateIdentityKeyPair();
    const params = baseParams();
    const signature = signRequest(params, kp.privateKey);

    expect(verifyRequest({ ...params, method: "GET" }, kp.publicKey, signature)).toBe(false);
  });

  it("rejects when path is changed after signing", () => {
    const kp = crypto.generateIdentityKeyPair();
    const params = baseParams();
    const signature = signRequest(params, kp.privateKey);

    expect(verifyRequest({ ...params, path: "/other" }, kp.publicKey, signature)).toBe(false);
  });

  it("rejects when rawBody is changed after signing", () => {
    const kp = crypto.generateIdentityKeyPair();
    const params = baseParams();
    const signature = signRequest(params, kp.privateKey);

    expect(
      verifyRequest({ ...params, rawBody: crypto.utf8Encode("{}") }, kp.publicKey, signature),
    ).toBe(false);
  });

  it("rejects when timestamp is changed after signing", () => {
    const kp = crypto.generateIdentityKeyPair();
    const params = baseParams();
    const signature = signRequest(params, kp.privateKey);

    expect(
      verifyRequest({ ...params, timestamp: params.timestamp + 1 }, kp.publicKey, signature),
    ).toBe(false);
  });

  it("rejects when nonce is changed after signing", () => {
    const kp = crypto.generateIdentityKeyPair();
    const params = baseParams();
    const signature = signRequest(params, kp.privateKey);

    expect(
      verifyRequest({ ...params, nonce: crypto.toBase64(crypto.randomBytes(16)) }, kp.publicKey, signature),
    ).toBe(false);
  });

  it("rejects when verified against a different signer's public key", () => {
    const kp = crypto.generateIdentityKeyPair();
    const otherKp = crypto.generateIdentityKeyPair();
    const params = baseParams();
    const signature = signRequest(params, kp.privateKey);

    expect(verifyRequest(params, otherKp.publicKey, signature)).toBe(false);
  });

  it("rejects a corrupted signature", () => {
    const kp = crypto.generateIdentityKeyPair();
    const params = baseParams();
    const signature = signRequest(params, kp.privateKey);
    const tampered = new Uint8Array(signature);
    tampered[0] = (tampered[0] ?? 0) ^ 0x01;

    expect(verifyRequest(params, kp.publicKey, tampered)).toBe(false);
  });

  it("throws, rather than returning false, when the signature has an invalid byte length", () => {
    const kp = crypto.generateIdentityKeyPair();
    const params = baseParams();

    expect(() => verifyRequest(params, kp.publicKey, new Uint8Array(3))).toThrow();
  });
});
