import { beforeAll, describe, expect, it } from "vitest";
import {
  initRatchet,
  MESSAGE_TYPE_NORMAL,
  MESSAGE_TYPE_PREKEY,
  preKeyMessageSessionId,
  RatchetAccount,
  RatchetSession,
  type EncryptedMessage,
} from "./index.js";
import { initRatchetForNode } from "./test-init.js";

beforeAll(async () => {
  await initRatchetForNode();
});

const text = (s: string) => new TextEncoder().encode(s);
const read = (b: Uint8Array) => new TextDecoder().decode(b);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const PICKLE_KEY = new Uint8Array(32).fill(9);

/** Alice starts a conversation with Bob while Bob is offline, using one of his published one-time keys. */
function start() {
  const alice = RatchetAccount.create();
  const bob = RatchetAccount.create();
  const published = bob.generateOneTimeKeys(5);
  bob.markKeysAsPublished();
  const aliceSession = alice.startSession(bob.identityKey, published[0]!.key);
  return { alice, bob, published, aliceSession };
}

/** A conversation where both sides have a session and Bob has replied once. */
function established() {
  const scene = start();
  const { session: bobSession } = scene.bob.acceptSession(scene.alice.identityKey, scene.aliceSession.encrypt(text("hi")).body);
  scene.aliceSession.decrypt(bobSession.encrypt(text("hello")));
  return { ...scene, bobSession };
}

describe("initRatchet", () => {
  it("can be called again without reloading", async () => {
    await initRatchet();
    await initRatchetForNode();
    expect(RatchetAccount.create().identityKey).toHaveLength(32);
  });
});

describe("accounts and keys", () => {
  it("gives every account its own 32-byte identity key", () => {
    const a = RatchetAccount.create();
    const b = RatchetAccount.create();
    expect(a.identityKey).toHaveLength(32);
    expect(hex(a.identityKey)).not.toBe(hex(b.identityKey));
    expect(hex(a.identityKey)).toBe(hex(a.identityKey));
  });

  it("generates distinct one-time keys with ids", () => {
    const account = RatchetAccount.create();
    const keys = account.generateOneTimeKeys(10);
    expect(keys).toHaveLength(10);
    expect(new Set(keys.map((k) => k.id)).size).toBe(10);
    expect(new Set(keys.map((k) => hex(k.key))).size).toBe(10);
    for (const key of keys) expect(key.key).toHaveLength(32);
  });

  it("stops listing keys once they are marked as published, and can top up", () => {
    const account = RatchetAccount.create();
    account.generateOneTimeKeys(4);
    account.markKeysAsPublished();
    expect(account.unpublishedOneTimeKeys()).toEqual([]);
    expect(account.generateOneTimeKeys(3)).toHaveLength(3);
  });

  it.each([[0], [-1], [1.5], [100_000]])("refuses to generate %s one-time keys", (count) => {
    expect(() => RatchetAccount.create().generateOneTimeKeys(count)).toThrow(/out of range/);
  });

  it("generates a fallback key that changes each time", () => {
    const account = RatchetAccount.create();
    const first = account.generateFallbackKey();
    expect(first.key).toHaveLength(32);
    account.markKeysAsPublished();
    const second = account.generateFallbackKey();
    expect(hex(second.key)).not.toBe(hex(first.key));
  });
});

describe("starting a conversation", () => {
  it("lets the first message be sent while the recipient is offline", () => {
    const scene = start();
    const first = scene.aliceSession.encrypt(text("hello bob"));
    expect(first.type).toBe(MESSAGE_TYPE_PREKEY);

    const { session, plaintext } = scene.bob.acceptSession(scene.alice.identityKey, first.body);
    expect(read(plaintext)).toBe("hello bob");
    expect(session.id).toBe(scene.aliceSession.id);
    expect(preKeyMessageSessionId(first.body)).toBe(session.id);
  });

  it("keeps sending pre-key messages until the other side replies, all readable by the one session", () => {
    const scene = start();
    const one = scene.aliceSession.encrypt(text("one"));
    const two = scene.aliceSession.encrypt(text("two"));
    const three = scene.aliceSession.encrypt(text("three"));
    expect([one.type, two.type, three.type]).toEqual([0, 0, 0]);
    expect(scene.aliceSession.hasReceivedMessage).toBe(false);

    const { session: bobSession } = scene.bob.acceptSession(scene.alice.identityKey, one.body);
    // The later ones belong to the session that now exists, and must not create another.
    expect(preKeyMessageSessionId(two.body)).toBe(bobSession.id);
    expect(read(bobSession.decrypt(two))).toBe("two");
    expect(read(bobSession.decrypt(three))).toBe("three");

    scene.aliceSession.decrypt(bobSession.encrypt(text("reply")));
    expect(scene.aliceSession.hasReceivedMessage).toBe(true);
    expect(scene.aliceSession.encrypt(text("four")).type).toBe(MESSAGE_TYPE_NORMAL);
  });

  it("works with the fallback key when one-time keys have run out", () => {
    const alice = RatchetAccount.create();
    const bob = RatchetAccount.create();
    const fallback = bob.generateFallbackKey();
    bob.markKeysAsPublished();

    // Two different people both get the fallback key.
    const carol = RatchetAccount.create();
    const fromAlice = alice.startSession(bob.identityKey, fallback.key).encrypt(text("from alice"));
    const fromCarol = carol.startSession(bob.identityKey, fallback.key).encrypt(text("from carol"));
    expect(read(bob.acceptSession(alice.identityKey, fromAlice.body).plaintext)).toBe("from alice");
    expect(read(bob.acceptSession(carol.identityKey, fromCarol.body).plaintext)).toBe("from carol");
  });

  it("lets two people start conversations with the same person", () => {
    const scene = start();
    const carol = RatchetAccount.create();
    const carolFirst = carol.startSession(scene.bob.identityKey, scene.published[1]!.key).encrypt(text("from carol"));
    const aliceFirst = scene.aliceSession.encrypt(text("from alice"));
    expect(read(scene.bob.acceptSession(carol.identityKey, carolFirst.body).plaintext)).toBe("from carol");
    expect(read(scene.bob.acceptSession(scene.alice.identityKey, aliceFirst.body).plaintext)).toBe("from alice");
  });

  it("uses each one-time key only once", () => {
    const scene = start();
    const first = scene.aliceSession.encrypt(text("hello"));
    scene.bob.acceptSession(scene.alice.identityKey, first.body);
    // Replaying the first message cannot create a second session: its one-time key is gone.
    expect(() => scene.bob.acceptSession(scene.alice.identityKey, first.body)).toThrow();
  });

  it("refuses a first message that claims to be from someone else", () => {
    const scene = start();
    const first = scene.aliceSession.encrypt(text("hello"));
    const mallory = RatchetAccount.create();
    expect(() => scene.bob.acceptSession(mallory.identityKey, first.body)).toThrow();
  });

  it("refuses a first message meant for a different account", () => {
    const scene = start();
    const first = scene.aliceSession.encrypt(text("hello"));
    const eve = RatchetAccount.create();
    eve.generateOneTimeKeys(1);
    expect(() => eve.acceptSession(scene.alice.identityKey, first.body)).toThrow();
  });

  it.each([
    ["an identity key of the wrong length", new Uint8Array(31), new Uint8Array(32).fill(1)],
    ["a one-time key of the wrong length", new Uint8Array(32).fill(1), new Uint8Array(5)],
  ])("refuses to start a session with %s", (_name, identity, oneTime) => {
    expect(() => RatchetAccount.create().startSession(identity, oneTime)).toThrow();
  });

  it("refuses garbage as a first message", () => {
    const bob = RatchetAccount.create();
    expect(() => bob.acceptSession(RatchetAccount.create().identityKey, text("not a message"))).toThrow();
    expect(() => preKeyMessageSessionId(new Uint8Array(0))).toThrow();
  });
});

describe("an established conversation", () => {
  it("carries many messages in both directions", () => {
    const scene = established();
    for (let i = 0; i < 300; i++) {
      const [from, to] = i % 3 === 0 ? [scene.bobSession, scene.aliceSession] : [scene.aliceSession, scene.bobSession];
      expect(read(to.decrypt(from.encrypt(text(`message ${i}`))))).toBe(`message ${i}`);
    }
  });

  it("decrypts messages that arrive out of order", () => {
    const scene = established();
    const batch = [0, 1, 2, 3, 4].map((i) => scene.aliceSession.encrypt(text(`m${i}`)));
    for (const i of [3, 0, 4, 1, 2]) {
      expect(read(scene.bobSession.decrypt(batch[i]!))).toBe(`m${i}`);
    }
  });

  it("survives a message that never arrives", () => {
    const scene = established();
    scene.aliceSession.encrypt(text("lost in transit"));
    expect(read(scene.bobSession.decrypt(scene.aliceSession.encrypt(text("arrives"))))).toBe("arrives");
  });

  it("rejects a replayed message", () => {
    const scene = established();
    const message = scene.aliceSession.encrypt(text("pay 10"));
    expect(read(scene.bobSession.decrypt(message))).toBe("pay 10");
    expect(() => scene.bobSession.decrypt(message)).toThrow();
  });

  it("rejects an altered message, and keeps working afterwards", () => {
    const scene = established();
    const message = scene.aliceSession.encrypt(text("hello"));
    for (const position of [0, Math.floor(message.body.length / 2), message.body.length - 1]) {
      const altered: EncryptedMessage = { type: message.type, body: Uint8Array.from(message.body) };
      altered.body[position]! ^= 1;
      expect(() => scene.bobSession.decrypt(altered)).toThrow();
    }
    expect(read(scene.bobSession.decrypt(message))).toBe("hello");
  });

  it("rejects a message with the wrong type label", () => {
    const scene = established();
    const message = scene.aliceSession.encrypt(text("hello"));
    expect(() => scene.bobSession.decrypt({ type: MESSAGE_TYPE_PREKEY, body: message.body })).toThrow();
  });

  it("does not let a message from one conversation be read in another", () => {
    const one = established();
    const two = established();
    expect(() => two.bobSession.decrypt(one.aliceSession.encrypt(text("private")))).toThrow();
  });

  it("does not let a sender decrypt their own outgoing message", () => {
    const scene = established();
    const message = scene.aliceSession.encrypt(text("hello"));
    expect(() => scene.aliceSession.decrypt(message)).toThrow();
  });

  it("never contains the plaintext, and differs every time", () => {
    const scene = established();
    const a = scene.aliceSession.encrypt(text("the same secret words"));
    const b = scene.aliceSession.encrypt(text("the same secret words"));
    expect(Buffer.from(a.body).includes(Buffer.from("secret"))).toBe(false);
    expect(hex(a.body)).not.toBe(hex(b.body));
  });

  it("handles empty and large messages", () => {
    const scene = established();
    expect(scene.bobSession.decrypt(scene.aliceSession.encrypt(new Uint8Array(0)))).toHaveLength(0);
    const large = new Uint8Array(100_000).fill(7);
    expect(hex(scene.bobSession.decrypt(scene.aliceSession.encrypt(large)))).toBe(hex(large));
  });
});

describe("saving and restoring", () => {
  it("restores an account that can still accept a session started before it was saved", () => {
    const scene = start();
    const first = scene.aliceSession.encrypt(text("sent while bob was away"));
    const bob = RatchetAccount.restore(scene.bob.save(PICKLE_KEY), PICKLE_KEY);
    expect(hex(bob.identityKey)).toBe(hex(scene.bob.identityKey));
    expect(read(bob.acceptSession(scene.alice.identityKey, first.body).plaintext)).toBe("sent while bob was away");
  });

  it("restores sessions between every message of a conversation", () => {
    let { aliceSession, bobSession } = established();
    for (let i = 0; i < 40; i++) {
      aliceSession = RatchetSession.restore(aliceSession.save(PICKLE_KEY), PICKLE_KEY);
      bobSession = RatchetSession.restore(bobSession.save(PICKLE_KEY), PICKLE_KEY);
      const [from, to] = i % 2 ? [bobSession, aliceSession] : [aliceSession, bobSession];
      expect(read(to.decrypt(from.encrypt(text(`n${i}`))))).toBe(`n${i}`);
    }
  });

  it("keeps the session id across a restore", () => {
    const { bobSession } = established();
    expect(RatchetSession.restore(bobSession.save(PICKLE_KEY), PICKLE_KEY).id).toBe(bobSession.id);
  });

  it("produces saved state that is text, for IndexedDB, and does not contain the key", () => {
    const { bob, bobSession } = established();
    const account = bob.save(PICKLE_KEY);
    const session = bobSession.save(PICKLE_KEY);
    expect(typeof account).toBe("string");
    expect(typeof session).toBe("string");
    expect(account).not.toContain(hex(PICKLE_KEY));
  });

  it("refuses the wrong key, a key of the wrong length, and damaged data", () => {
    const { bob, bobSession } = established();
    const saved = bobSession.save(PICKLE_KEY);
    expect(() => RatchetSession.restore(saved, new Uint8Array(32).fill(1))).toThrow();
    expect(() => RatchetSession.restore(saved, new Uint8Array(16))).toThrow(/32 bytes/);
    expect(() => RatchetSession.restore(saved.slice(0, -8) + "AAAAAAAA", PICKLE_KEY)).toThrow();
    expect(() => RatchetSession.restore("", PICKLE_KEY)).toThrow();
    expect(() => bobSession.save(new Uint8Array(31))).toThrow(/32 bytes/);
    expect(() => RatchetAccount.restore(bob.save(PICKLE_KEY), new Uint8Array(32))).toThrow();
    // A session's saved state is not an account's.
    expect(() => RatchetAccount.restore(saved, PICKLE_KEY)).toThrow();
  });

  it("a restored old copy cannot decrypt a message the live session already used", () => {
    const scene = established();
    const message = scene.aliceSession.encrypt(text("once only"));
    scene.bobSession.decrypt(message);
    // The live session has destroyed that message's key.
    expect(() => scene.bobSession.decrypt(message)).toThrow();
    const afterwards = RatchetSession.restore(scene.bobSession.save(PICKLE_KEY), PICKLE_KEY);
    expect(() => afterwards.decrypt(message)).toThrow();
  });
});

describe("losing a session", () => {
  it("lets the side that lost its session start a new one with another one-time key", () => {
    const scene = established();
    const fresh = scene.alice.startSession(scene.bob.identityKey, scene.published[1]!.key);
    const first = fresh.encrypt(text("starting over"));

    // It is a different session: the old one cannot read it, and its id says so.
    expect(preKeyMessageSessionId(first.body)).not.toBe(scene.bobSession.id);
    expect(() => scene.bobSession.decrypt(first)).toThrow();

    const { session, plaintext } = scene.bob.acceptSession(scene.alice.identityKey, first.body);
    expect(read(plaintext)).toBe("starting over");
    expect(read(fresh.decrypt(session.encrypt(text("got it"))))).toBe("got it");
  });
});
