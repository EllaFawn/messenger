import { beforeAll, describe, expect, it } from "vitest";
import * as crypto from "@messager/crypto";
import {
  buildMessageSalt,
  buildMessageInfo,
  buildMessageAd,
  deriveMessageKey,
  encryptMessage,
  decryptMessage,
} from "./message-crypto.js";
import { encodeEnvelope, type Envelope } from "./envelope.js";
import type { MessagePlaintext } from "./message-plaintext.js";

beforeAll(async () => {
  await crypto.ready;
});

describe("buildMessageSalt", () => {
  it("is order-independent between the two user ids", () => {
    expect(crypto.toHex(buildMessageSalt("alice", "bob"))).toBe(
      crypto.toHex(buildMessageSalt("bob", "alice")),
    );
  });

  it("matches UTF8(sorted.join(\"|\")) exactly", () => {
    expect(crypto.toHex(buildMessageSalt("bob", "alice"))).toBe(
      crypto.toHex(crypto.utf8Encode("alice|bob")),
    );
  });
});

describe("buildMessageInfo", () => {
  it("is directional", () => {
    expect(crypto.toHex(buildMessageInfo("alice", "bob"))).not.toBe(
      crypto.toHex(buildMessageInfo("bob", "alice")),
    );
  });

  it("matches the fixed format exactly", () => {
    expect(crypto.toHex(buildMessageInfo("alice", "bob"))).toBe(
      crypto.toHex(crypto.utf8Encode("messager/v1/msg/alice>bob")),
    );
  });
});

describe("buildMessageAd", () => {
  it("matches UTF8(header) || nonce exactly", () => {
    const nonce = crypto.utf8Encode("0123456789abcdef01234567");
    const expected = new Uint8Array(crypto.utf8Encode("v1|alice|bob").length + nonce.length);
    expected.set(crypto.utf8Encode("v1|alice|bob"), 0);
    expected.set(nonce, crypto.utf8Encode("v1|alice|bob").length);

    expect(crypto.toHex(buildMessageAd("alice", "bob", nonce))).toBe(crypto.toHex(expected));
  });

  it("changes when the nonce, fromUserId, or toUserId change", () => {
    const nonce = crypto.randomBytes(crypto.AEAD_NONCE_BYTES);
    const base = crypto.toHex(buildMessageAd("alice", "bob", nonce));

    expect(crypto.toHex(buildMessageAd("alice", "bob", crypto.randomBytes(crypto.AEAD_NONCE_BYTES)))).not.toBe(base);
    expect(crypto.toHex(buildMessageAd("carol", "bob", nonce))).not.toBe(base);
    expect(crypto.toHex(buildMessageAd("alice", "carol", nonce))).not.toBe(base);
  });
});

describe("deriveMessageKey", () => {
  it("produces the same key regardless of which side computes it", () => {
    const alice = crypto.generateExchangeKeyPair();
    const bob = crypto.generateExchangeKeyPair();

    const fromAlice = deriveMessageKey(alice.privateKey, bob.publicKey, "alice", "bob");
    const fromBob = deriveMessageKey(bob.privateKey, alice.publicKey, "alice", "bob");

    expect(crypto.toHex(fromAlice)).toBe(crypto.toHex(fromBob));
  });

  it("derives different keys for opposite directions between the same pair", () => {
    const alice = crypto.generateExchangeKeyPair();
    const bob = crypto.generateExchangeKeyPair();

    const aToB = deriveMessageKey(alice.privateKey, bob.publicKey, "alice", "bob");
    const bToA = deriveMessageKey(alice.privateKey, bob.publicKey, "bob", "alice");

    expect(crypto.toHex(aToB)).not.toBe(crypto.toHex(bToA));
  });

  it("derives different keys for a different pair of user ids", () => {
    const alice = crypto.generateExchangeKeyPair();
    const bob = crypto.generateExchangeKeyPair();
    const carol = crypto.generateExchangeKeyPair();

    const aliceToBob = deriveMessageKey(alice.privateKey, bob.publicKey, "alice", "bob");
    const aliceToCarol = deriveMessageKey(alice.privateKey, carol.publicKey, "alice", "carol");

    expect(crypto.toHex(aliceToBob)).not.toBe(crypto.toHex(aliceToCarol));
  });
});

describe("encryptMessage / decryptMessage (golden by recomputation)", () => {
  // RFC 7748 §6.1 Alice/Bob X25519 test vector, reused from crypto.test.ts, so
  // the shared secret this test relies on is itself externally verified.
  const alicePriv = crypto.fromHex(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  );
  const bobPub = crypto.fromHex(
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  );
  const nonce = crypto.fromHex("000102030405060708090a0b0c0d0e0f1011121314151617");
  const message: MessagePlaintext = { counter: 1, text: "hi", sentAt: 1754400000000 };

  it("matches an independent recomputation of the design-doc algorithm", () => {
    // Recomputed here directly from crypto primitives (not via
    // buildMessageSalt/Info/Ad), so this also cross-checks that
    // encryptMessage wires those helpers together correctly.
    const ss = crypto.scalarMult(alicePriv, bobPub);
    const prk = crypto.hkdfExtract(crypto.utf8Encode("alice-id|bob-id"), ss);
    const key = crypto.hkdfExpand(prk, crypto.utf8Encode("messager/v1/msg/alice-id>bob-id"), crypto.AEAD_KEY_BYTES);
    const ad = new Uint8Array(crypto.utf8Encode("v1|alice-id|bob-id").length + nonce.length);
    ad.set(crypto.utf8Encode("v1|alice-id|bob-id"), 0);
    ad.set(nonce, crypto.utf8Encode("v1|alice-id|bob-id").length);
    const plaintext = crypto.utf8Encode(JSON.stringify(message));
    const expectedCiphertext = crypto.aeadEncrypt(key, nonce, plaintext, ad);

    const envelope = encryptMessage({
      message,
      fromUserId: "alice-id",
      toUserId: "bob-id",
      myExchangePrivateKey: alicePriv,
      theirExchangePublicKey: bobPub,
      nonce,
    });

    expect(envelope.v).toBe(1);
    expect(envelope.to).toBe("bob-id");
    expect(envelope.nonce).toBe(crypto.toBase64(nonce));
    expect(envelope.ciphertext).toBe(crypto.toBase64(expectedCiphertext));
  });
});

describe("encryptMessage / decryptMessage (round-trip)", () => {
  it("round-trips a message between two freshly generated keypairs", () => {
    const alice = crypto.generateExchangeKeyPair();
    const bob = crypto.generateExchangeKeyPair();
    const message: MessagePlaintext = { counter: 7, text: "hello bob", sentAt: Date.now() };

    const envelope = encryptMessage({
      message,
      fromUserId: "alice",
      toUserId: "bob",
      myExchangePrivateKey: alice.privateKey,
      theirExchangePublicKey: bob.publicKey,
    });

    const decrypted = decryptMessage({
      envelope,
      fromUserId: "alice",
      toUserId: "bob",
      myExchangePrivateKey: bob.privateKey,
      theirExchangePublicKey: alice.publicKey,
    });

    expect(decrypted).toEqual(message);
  });

  it("produces a well-formed envelope", () => {
    const alice = crypto.generateExchangeKeyPair();
    const bob = crypto.generateExchangeKeyPair();

    const envelope = encryptMessage({
      message: { counter: 1, text: "hi", sentAt: Date.now() },
      fromUserId: "alice",
      toUserId: "bob",
      myExchangePrivateKey: alice.privateKey,
      theirExchangePublicKey: bob.publicKey,
    });

    expect(envelope.v).toBe(1);
    expect(envelope.to).toBe("bob");
    expect(typeof envelope.nonce).toBe("string");
    expect(typeof envelope.ciphertext).toBe("string");
  });

  it("survives JSON.stringify/JSON.parse of the envelope", () => {
    const alice = crypto.generateExchangeKeyPair();
    const bob = crypto.generateExchangeKeyPair();
    const message: MessagePlaintext = { counter: 2, text: "wire format", sentAt: Date.now() };

    const envelope = encryptMessage({
      message,
      fromUserId: "alice",
      toUserId: "bob",
      myExchangePrivateKey: alice.privateKey,
      theirExchangePublicKey: bob.publicKey,
    });

    const overWire: Envelope = JSON.parse(JSON.stringify(envelope));
    const decrypted = decryptMessage({
      envelope: overWire,
      fromUserId: "alice",
      toUserId: "bob",
      myExchangePrivateKey: bob.privateKey,
      theirExchangePublicKey: alice.publicKey,
    });

    expect(decrypted).toEqual(message);
  });

  it("uses a fresh random nonce per call by default", () => {
    const alice = crypto.generateExchangeKeyPair();
    const bob = crypto.generateExchangeKeyPair();
    const params = {
      message: { counter: 1, text: "hi", sentAt: 1 },
      fromUserId: "alice",
      toUserId: "bob",
      myExchangePrivateKey: alice.privateKey,
      theirExchangePublicKey: bob.publicKey,
    };

    const first = encryptMessage(params);
    const second = encryptMessage(params);

    expect(first.nonce).not.toBe(second.nonce);
    expect(first.ciphertext).not.toBe(second.ciphertext);
  });

  it("honors an explicit nonce override", () => {
    const alice = crypto.generateExchangeKeyPair();
    const bob = crypto.generateExchangeKeyPair();
    const nonce = crypto.randomBytes(crypto.AEAD_NONCE_BYTES);

    const envelope = encryptMessage({
      message: { counter: 1, text: "hi", sentAt: 1 },
      fromUserId: "alice",
      toUserId: "bob",
      myExchangePrivateKey: alice.privateKey,
      theirExchangePublicKey: bob.publicKey,
      nonce,
    });

    expect(envelope.nonce).toBe(crypto.toBase64(nonce));
  });
});

describe("negative / tamper cases", () => {
  function makeEnvelope() {
    const alice = crypto.generateExchangeKeyPair();
    const bob = crypto.generateExchangeKeyPair();
    const envelope = encryptMessage({
      message: { counter: 1, text: "hi", sentAt: 1 },
      fromUserId: "alice",
      toUserId: "bob",
      myExchangePrivateKey: alice.privateKey,
      theirExchangePublicKey: bob.publicKey,
    });
    return { alice, bob, envelope };
  }

  it("rejects a flipped ciphertext bit", () => {
    const { bob, alice, envelope } = makeEnvelope();
    const tampered = crypto.fromBase64(envelope.ciphertext);
    tampered[0] = (tampered[0] ?? 0) ^ 0x01;
    envelope.ciphertext = crypto.toBase64(tampered);

    expect(() =>
      decryptMessage({
        envelope,
        fromUserId: "alice",
        toUserId: "bob",
        myExchangePrivateKey: bob.privateKey,
        theirExchangePublicKey: alice.publicKey,
      }),
    ).toThrow();
  });

  it("rejects a tampered nonce", () => {
    const { bob, alice, envelope } = makeEnvelope();
    const tampered = crypto.fromBase64(envelope.nonce);
    tampered[0] = (tampered[0] ?? 0) ^ 0x01;
    envelope.nonce = crypto.toBase64(tampered);

    expect(() =>
      decryptMessage({
        envelope,
        fromUserId: "alice",
        toUserId: "bob",
        myExchangePrivateKey: bob.privateKey,
        theirExchangePublicKey: alice.publicKey,
      }),
    ).toThrow();
  });

  it("rejects a toUserId that doesn't match the envelope's recipient", () => {
    const { bob, alice, envelope } = makeEnvelope();

    expect(() =>
      decryptMessage({
        envelope,
        fromUserId: "alice",
        toUserId: "carol",
        myExchangePrivateKey: bob.privateKey,
        theirExchangePublicKey: alice.publicKey,
      }),
    ).toThrow();
  });

  it("rejects the wrong fromUserId", () => {
    const { bob, alice, envelope } = makeEnvelope();

    expect(() =>
      decryptMessage({
        envelope,
        fromUserId: "mallory",
        toUserId: "bob",
        myExchangePrivateKey: bob.privateKey,
        theirExchangePublicKey: alice.publicKey,
      }),
    ).toThrow();
  });

  it("rejects the wrong recipient private key", () => {
    const { alice, envelope } = makeEnvelope();
    const wrongRecipient = crypto.generateExchangeKeyPair();

    expect(() =>
      decryptMessage({
        envelope,
        fromUserId: "alice",
        toUserId: "bob",
        myExchangePrivateKey: wrongRecipient.privateKey,
        theirExchangePublicKey: alice.publicKey,
      }),
    ).toThrow();
  });

  it("rejects the wrong sender public key", () => {
    const { bob, envelope } = makeEnvelope();
    const wrongSender = crypto.generateExchangeKeyPair();

    expect(() =>
      decryptMessage({
        envelope,
        fromUserId: "alice",
        toUserId: "bob",
        myExchangePrivateKey: bob.privateKey,
        theirExchangePublicKey: wrongSender.publicKey,
      }),
    ).toThrow();
  });

  it("propagates decodeMessagePlaintext's validation error for malformed plaintext", () => {
    const alice = crypto.generateExchangeKeyPair();
    const bob = crypto.generateExchangeKeyPair();
    const nonce = crypto.randomBytes(crypto.AEAD_NONCE_BYTES);
    const key = deriveMessageKey(alice.privateKey, bob.publicKey, "alice", "bob");
    const ad = buildMessageAd("alice", "bob", nonce);
    const ciphertext = crypto.aeadEncrypt(key, nonce, crypto.utf8Encode("not valid message plaintext json"), ad);
    const envelope = encodeEnvelope("bob", nonce, ciphertext);

    expect(() =>
      decryptMessage({
        envelope,
        fromUserId: "alice",
        toUserId: "bob",
        myExchangePrivateKey: bob.privateKey,
        theirExchangePublicKey: alice.publicKey,
      }),
    ).toThrow();
  });
});
