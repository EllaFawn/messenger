import { beforeAll, describe, expect, it } from "vitest";
import * as crypto from "./index.js";

beforeAll(async () => {
  await crypto.ready;
});

describe("X25519 (RFC 7748 §6.1 test vector)", () => {
  it("matches Alice/Bob shared secret", () => {
    const alicePriv = crypto.fromHex(
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    );
    const alicePub = crypto.fromHex(
      "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    );
    const bobPriv = crypto.fromHex(
      "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    );
    const bobPub = crypto.fromHex(
      "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    );
    const shared = crypto.fromHex(
      "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    );

    expect(crypto.toHex(crypto.scalarMult(alicePriv, bobPub))).toBe(crypto.toHex(shared));
    expect(crypto.toHex(crypto.scalarMult(bobPriv, alicePub))).toBe(crypto.toHex(shared));
  });
});

describe("HKDF-SHA256 (RFC 5869 Appendix A.1, Test Case 1)", () => {
  it("matches published PRK and OKM", () => {
    const ikm = crypto.fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = crypto.fromHex("000102030405060708090a0b0c");
    const info = crypto.fromHex("f0f1f2f3f4f5f6f7f8f9");
    const expectedPrk = crypto.fromHex(
      "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
    );
    const expectedOkm = crypto.fromHex(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );

    const prk = crypto.hkdfExtract(salt, ikm);
    expect(crypto.toHex(prk)).toBe(crypto.toHex(expectedPrk));

    const okm = crypto.hkdfExpand(prk, info, 42);
    expect(crypto.toHex(okm)).toBe(crypto.toHex(expectedOkm));
  });
});

describe("Ed25519 (RFC 8032 §7.1 test vectors)", () => {
  it("TEST 1: empty message", () => {
    const seed = crypto.fromHex(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    );
    const expectedPub = crypto.fromHex(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    );
    const expectedSig = crypto.fromHex(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );

    const kp = crypto.identityKeyPairFromSeed(seed);
    expect(crypto.toHex(kp.publicKey)).toBe(crypto.toHex(expectedPub));

    const message = new Uint8Array(0);
    const sig = crypto.sign(kp.privateKey, message);
    expect(crypto.toHex(sig)).toBe(crypto.toHex(expectedSig));
    expect(crypto.verify(kp.publicKey, message, sig)).toBe(true);
  });

  it("TEST 2: one-byte message", () => {
    const seed = crypto.fromHex(
      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    );
    const expectedPub = crypto.fromHex(
      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    );
    const expectedSig = crypto.fromHex(
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    );

    const kp = crypto.identityKeyPairFromSeed(seed);
    expect(crypto.toHex(kp.publicKey)).toBe(crypto.toHex(expectedPub));

    const message = crypto.fromHex("72");
    const sig = crypto.sign(kp.privateKey, message);
    expect(crypto.toHex(sig)).toBe(crypto.toHex(expectedSig));
    expect(crypto.verify(kp.publicKey, message, sig)).toBe(true);
  });
});

describe("XChaCha20-Poly1305-ietf (libsodium test suite vector)", () => {
  const key = new Uint8Array(Array.from({ length: 32 }, (_, i) => 0x80 + i));
  // Nonce/AD/message/ciphertext taken verbatim from libsodium's
  // test/default/aead_xchacha20poly1305.{c,exp}.
  const nonce = new Uint8Array([
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,
    0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
  ]);
  const ad = new Uint8Array([0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7]);

  // Computed in beforeAll, not at describe-collection time: sodium isn't
  // initialized yet when describe() bodies run.
  let plaintext: Uint8Array;
  let expectedCiphertext: Uint8Array;

  beforeAll(() => {
    plaintext = crypto.utf8Encode(
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
    );
    expectedCiphertext = crypto.fromHex(
      "f8ebea4875044066fc162a0604e171feecfb3d20425248563bcfd5a155dcc47bbda70b86e5ab9b55002bd1274c02db35321acd7af8b2e2d25015e136b7679458e9f43243bf719d639badb5feac03f80a19a96ef10cb1d15333a837b90946ba3854ee74da3f2585efc7e1e170e17e15e563e77601f4f85cafa8e5877614e143e68420",
    );
  });

  it("encrypts to the published ciphertext", () => {
    const ct = crypto.aeadEncrypt(key, nonce, plaintext, ad);
    expect(crypto.toHex(ct)).toBe(crypto.toHex(expectedCiphertext));
  });

  it("decrypts back to the original plaintext", () => {
    const pt = crypto.aeadDecrypt(key, nonce, expectedCiphertext, ad);
    expect(crypto.toHex(pt)).toBe(crypto.toHex(plaintext));
  });
});

describe("negative cases", () => {
  it("rejects a flipped ciphertext bit", () => {
    const key = crypto.randomBytes(crypto.AEAD_KEY_BYTES);
    const nonce = crypto.randomBytes(crypto.AEAD_NONCE_BYTES);
    const ad = crypto.utf8Encode("v1|a|b");
    const ct = crypto.aeadEncrypt(key, nonce, crypto.utf8Encode("hello"), ad);

    const tampered = new Uint8Array(ct);
    tampered[0] = (tampered[0] ?? 0) ^ 0x01;

    expect(() => crypto.aeadDecrypt(key, nonce, tampered, ad)).toThrow();
  });

  it("rejects the wrong associated data", () => {
    const key = crypto.randomBytes(crypto.AEAD_KEY_BYTES);
    const nonce = crypto.randomBytes(crypto.AEAD_NONCE_BYTES);
    const ct = crypto.aeadEncrypt(key, nonce, crypto.utf8Encode("hello"), crypto.utf8Encode("v1|a|b"));

    expect(() => crypto.aeadDecrypt(key, nonce, ct, crypto.utf8Encode("v1|a|c"))).toThrow();
  });

  it("rejects decryption under the wrong recipient key", () => {
    const key = crypto.randomBytes(crypto.AEAD_KEY_BYTES);
    const wrongKey = crypto.randomBytes(crypto.AEAD_KEY_BYTES);
    const nonce = crypto.randomBytes(crypto.AEAD_NONCE_BYTES);
    const ad = crypto.utf8Encode("v1|a|b");
    const ct = crypto.aeadEncrypt(key, nonce, crypto.utf8Encode("hello"), ad);

    expect(() => crypto.aeadDecrypt(wrongKey, nonce, ct, ad)).toThrow();
  });

  it("derives different keys for A->B and B->A from the same shared secret", async () => {
    const a = crypto.generateExchangeKeyPair();
    const b = crypto.generateExchangeKeyPair();
    const ss = crypto.scalarMult(a.privateKey, b.publicKey);

    const prk = crypto.hkdfExtract(crypto.utf8Encode("a|b"), ss);
    const keyAtoB = crypto.hkdfExpand(prk, crypto.utf8Encode("messager/v1/msg/a>b"), 32);
    const keyBtoA = crypto.hkdfExpand(prk, crypto.utf8Encode("messager/v1/msg/b>a"), 32);

    expect(crypto.toHex(keyAtoB)).not.toBe(crypto.toHex(keyBtoA));
  });
});
