import * as crypto from "@messager/crypto";
import { signOneTimeKey, signRatchetKey, verifyOneTimeKey, verifyRatchetKey, verifyRequest } from "@messager/protocol";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createIdentity as createIdentityWithAccount, type StoredIdentity } from "../identity.js";
import { ApiError, createApiClient, type ApiClient } from "./client.js";

const NOW = 1_800_000_000_000;

const createIdentity = (now: number): StoredIdentity => createIdentityWithAccount(now).identity;

interface SeenRequest {
  url: string;
  method: string;
  headers: Headers;
  body: string | undefined;
}

let identity: StoredIdentity;
let seen: SeenRequest[];
let respond: () => Response | Promise<Response>;
let client: ApiClient;

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

beforeAll(async () => {
  await crypto.ready;
});

beforeEach(() => {
  identity = createIdentity(NOW);
  seen = [];
  respond = () => json(200, { ok: true });
  client = createApiClient({
    now: () => NOW,
    fetch: async (input, init) => {
      const headers = new Headers(init?.headers);
      seen.push({
        url: String(input),
        method: init?.method ?? "GET",
        headers,
        body: typeof init?.body === "string" ? init.body : undefined,
      });
      return respond();
    },
  });
});

/** Checks a captured request the way the server does. */
function signatureIsValid(request: SeenRequest, serverPath: string): boolean {
  return verifyRequest(
    {
      method: request.method,
      path: serverPath,
      rawBody: crypto.utf8Encode(request.body ?? ""),
      timestamp: Number(request.headers.get("x-timestamp")),
      nonce: request.headers.get("x-nonce")!,
    },
    identity.identityPublicKey,
    crypto.fromBase64(request.headers.get("x-signature")!),
  );
}

describe("signed requests", () => {
  it("sends to /api but signs the path the server sees", async () => {
    await client.request(identity, "GET", "/users/abc/pubkeys");
    expect(seen).toHaveLength(1);
    expect(seen[0]!.url).toBe("/api/users/abc/pubkeys");
    expect(signatureIsValid(seen[0]!, "/users/abc/pubkeys")).toBe(true);
    expect(signatureIsValid(seen[0]!, "/api/users/abc/pubkeys")).toBe(false);
  });

  it("sends the four auth headers in the formats the server requires", async () => {
    await client.request(identity, "GET", "/messages/inbox");
    const headers = seen[0]!.headers;
    expect(headers.get("x-user-id")).toBe(identity.userId);
    expect(headers.get("x-timestamp")).toBe(String(NOW));
    expect(headers.get("x-nonce")).toMatch(/^[A-Za-z0-9+/]{22}==$/);
    expect(headers.get("x-signature")).toMatch(/^[A-Za-z0-9+/]{86}==$/);
  });

  it("signs exactly the body bytes it sends", async () => {
    await client.request(identity, "POST", "/messages", { v: 1, text: "héllo ✓" });
    const request = seen[0]!;
    expect(request.headers.get("content-type")).toBe("application/json");
    expect(JSON.parse(request.body!)).toEqual({ v: 1, text: "héllo ✓" });
    expect(signatureIsValid(request, "/messages")).toBe(true);
  });

  it("sends no body and no content type when there is nothing to send", async () => {
    await client.request(identity, "POST", "/messages/some-id/ack");
    expect(seen[0]!.body).toBeUndefined();
    expect(seen[0]!.headers.has("content-type")).toBe(false);
    expect(signatureIsValid(seen[0]!, "/messages/some-id/ack")).toBe(true);
  });

  it("uses a fresh nonce for every request", async () => {
    await client.request(identity, "GET", "/messages/inbox");
    await client.request(identity, "GET", "/messages/inbox");
    expect(seen[0]!.headers.get("x-nonce")).not.toBe(seen[1]!.headers.get("x-nonce"));
  });

  it("never sends private key material", async () => {
    await client.request(identity, "POST", "/messages", { hello: "world" });
    const everything = JSON.stringify([seen[0]!.url, [...seen[0]!.headers.entries()], seen[0]!.body]);
    for (const secret of [identity.identityPrivateKey, identity.pickleKey]) {
      expect(everything).not.toContain(crypto.toBase64(secret));
      expect(everything).not.toContain(crypto.toHex(secret));
    }
    // An Ed25519 private key embeds its seed in the first 32 bytes.
    expect(everything).not.toContain(crypto.toBase64(identity.identityPrivateKey.slice(0, 32)));
  });

  it("does not send cookies or follow redirects", async () => {
    let init: RequestInit | undefined;
    const plain = createApiClient({
      now: () => NOW,
      fetch: async (_input, i) => {
        init = i;
        return json(200, {});
      },
    });
    await plain.request(identity, "GET", "/messages/inbox");
    expect(init!.credentials).toBe("omit");
    expect(init!.redirect).toBe("error");
  });

  it("returns the parsed JSON on success", async () => {
    respond = () => json(200, [{ a: 1 }]);
    expect(await client.request(identity, "GET", "/messages/inbox")).toEqual([{ a: 1 }]);
  });

  it("returns undefined for an empty success response", async () => {
    respond = () => new Response(null, { status: 204 });
    expect(await client.request(identity, "POST", "/messages/x/ack")).toBeUndefined();
  });

  it("turns an error response into an ApiError with the server's code", async () => {
    respond = () => json(403, { error: "invalid_invite" });
    const error = await client.request(identity, "POST", "/register", {}).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(403);
    expect((error as ApiError).code).toBe("invalid_invite");
  });

  it("copes with an error response that is not JSON", async () => {
    respond = () => new Response("<html>Bad Gateway</html>", { status: 502 });
    const error = await client.request(identity, "GET", "/messages/inbox").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(502);
    expect((error as ApiError).code).toBe("unknown_error");
  });

  it("reports a success response that is not JSON as an error", async () => {
    respond = () => new Response("<html>hello</html>", { status: 200 });
    const error = await client.request(identity, "GET", "/messages/inbox").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).code).toBe("invalid_response");
  });

  it("reports a failed connection as an ApiError", async () => {
    respond = () => {
      throw new TypeError("fetch failed");
    };
    const error = await client.request(identity, "GET", "/messages/inbox").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(0);
    expect((error as ApiError).code).toBe("network_error");
  });
});

describe("register", () => {
  it("posts the identity key, the signed ratchet key and the invite code, signed by the new identity", async () => {
    respond = () => json(201, { userID: identity.userId });
    await client.register(identity, "the-invite-code-0123456789");

    const request = seen[0]!;
    expect(request.method).toBe("POST");
    expect(request.url).toBe("/api/register");
    const body = JSON.parse(request.body!) as Record<string, string>;
    expect(body).toEqual({
      userID: identity.userId,
      identity_pubkey: crypto.toBase64(identity.identityPublicKey),
      ratchet_pubkey: crypto.toBase64(identity.ratchetPublicKey),
      ratchet_sig: body.ratchet_sig,
      inviteCode: "the-invite-code-0123456789",
    });
    expect(
      verifyRatchetKey(identity.ratchetPublicKey, crypto.fromBase64(body.ratchet_sig!), identity.identityPublicKey),
    ).toBe(true);
    expect(signatureIsValid(request, "/register")).toBe(true);
  });

  it("fails if the server confirms a different userID", async () => {
    respond = () => json(201, { userID: createIdentity(NOW).userId });
    const error = await client.register(identity, "code").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).code).toBe("invalid_response");
  });

  it("passes on the server's refusal", async () => {
    respond = () => json(403, { error: "invalid_invite" });
    const error = await client.register(identity, "wrong").catch((e: unknown) => e);
    expect((error as ApiError).code).toBe("invalid_invite");
  });
});

/** The keys part of a pubkeys or claim reply, as the real server sends it. */
function keysReply(of: StoredIdentity, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    userID: of.userId,
    identity_pubkey: crypto.toBase64(of.identityPublicKey),
    ratchet_pubkey: crypto.toBase64(of.ratchetPublicKey),
    ratchet_sig: crypto.toBase64(signRatchetKey(of.ratchetPublicKey, of.identityPrivateKey)),
    key_epoch: 1,
    ...overrides,
  };
}

/** Cases every keys reply must be refused for. Built lazily: the crypto library is not loaded at definition time. */
const BAD_KEYS: [string, (bob: StoredIdentity, mallory: StoredIdentity) => Record<string, unknown>][] = [
  ["an identity key that does not hash to the userID", (_b, m) => ({ identity_pubkey: crypto.toBase64(m.identityPublicKey) })],
  ["a ratchet key swapped in by the server", (_b, m) => ({ ratchet_pubkey: crypto.toBase64(m.ratchetPublicKey) })],
  [
    "a ratchet key signed by a different identity",
    (_b, m) => ({
      ratchet_pubkey: crypto.toBase64(m.ratchetPublicKey),
      ratchet_sig: crypto.toBase64(signRatchetKey(m.ratchetPublicKey, m.identityPrivateKey)),
    }),
  ],
  ["a reply about a different user", (_b, m) => ({ userID: m.userId })],
  ["a missing ratchet key", () => ({ ratchet_pubkey: undefined })],
  ["a missing signature", () => ({ ratchet_sig: undefined })],
  ["a signature of the wrong length", () => ({ ratchet_sig: "AAAA" })],
  ["a ratchet key of the wrong length", () => ({ ratchet_pubkey: "AAAA" })],
  ["a ratchet key that is not text", () => ({ ratchet_pubkey: 5 })],
  ["an identity key that is not base64", () => ({ identity_pubkey: "!".repeat(44) })],
  ["a missing key epoch", () => ({ key_epoch: undefined })],
  ["a key epoch of zero", () => ({ key_epoch: 0 })],
  ["a key epoch that is not a whole number", () => ({ key_epoch: 1.5 })],
];

describe("getPubkeys", () => {
  it("returns the keys as bytes and signs the request", async () => {
    const bob = createIdentity(NOW);
    respond = () => json(200, keysReply(bob, { key_epoch: 3 }));
    const keys = await client.getPubkeys(identity, bob.userId);
    expect(keys).toEqual({
      userId: bob.userId,
      identityPublicKey: bob.identityPublicKey,
      ratchetPublicKey: bob.ratchetPublicKey,
      keyEpoch: 3,
    });
    expect(seen[0]!.url).toBe(`/api/users/${bob.userId}/pubkeys`);
    expect(signatureIsValid(seen[0]!, `/users/${bob.userId}/pubkeys`)).toBe(true);
  });

  it.each(BAD_KEYS)("rejects %s", async (_name, overrides) => {
    const bob = createIdentity(NOW);
    respond = () => json(200, keysReply(bob, overrides(bob, createIdentity(NOW))));
    const error = await client.getPubkeys(identity, bob.userId).catch((e: unknown) => e);
    expect((error as ApiError).code).toBe("invalid_response");
  });

  it("passes on 'not found'", async () => {
    respond = () => json(404, { error: "not_found" });
    const error = await client.getPubkeys(identity, createIdentity(NOW).userId).catch((e: unknown) => e);
    expect((error as ApiError).status).toBe(404);
    expect((error as ApiError).code).toBe("not_found");
  });
});

describe("one-time keys", () => {
  function claimReply(
    of: StoredIdentity,
    oneTimeKey: Uint8Array,
    overrides: Record<string, unknown> = {},
    keyOverrides: Record<string, unknown> = {},
  ): Response {
    return json(200, {
      ...keysReply(of),
      one_time_key: {
        id: "AAAAAAAAAAE",
        key: crypto.toBase64(oneTimeKey),
        sig: crypto.toBase64(signOneTimeKey(of.ratchetPublicKey, oneTimeKey, of.identityPrivateKey)),
        fallback: false,
        ...keyOverrides,
      },
      ...overrides,
    });
  }

  it("claims a key with a signed POST and returns it checked", async () => {
    const bob = createIdentity(NOW);
    const oneTimeKey = crypto.randomBytes(32);
    respond = () => claimReply(bob, oneTimeKey, {}, { fallback: true });
    const claimed = await client.claimOneTimeKey(identity, bob.userId);
    expect(claimed).toEqual({
      userId: bob.userId,
      identityPublicKey: bob.identityPublicKey,
      ratchetPublicKey: bob.ratchetPublicKey,
      keyEpoch: 1,
      oneTimeKey,
      fallback: true,
    });
    expect(seen[0]!.method).toBe("POST");
    expect(seen[0]!.url).toBe(`/api/users/${bob.userId}/keys/claim`);
    expect(signatureIsValid(seen[0]!, `/users/${bob.userId}/keys/claim`)).toBe(true);
  });

  it.each(BAD_KEYS)("rejects a claim with %s", async (_name, overrides) => {
    const bob = createIdentity(NOW);
    respond = () => claimReply(bob, crypto.randomBytes(32), overrides(bob, createIdentity(NOW)));
    const error = await client.claimOneTimeKey(identity, bob.userId).catch((e: unknown) => e);
    expect((error as ApiError).code).toBe("invalid_response");
  });

  it.each([
    ["a one-time key the server swapped in", () => ({ key: crypto.toBase64(crypto.randomBytes(32)) })],
    ["a one-time key signed by someone else", () => ({ sig: crypto.toBase64(crypto.randomBytes(64)) })],
    ["a one-time key of the wrong length", () => ({ key: "AAAA" })],
    ["a missing fallback flag", () => ({ fallback: undefined })],
  ])("rejects a claim with %s", async (_name, keyOverrides) => {
    const bob = createIdentity(NOW);
    respond = () => claimReply(bob, crypto.randomBytes(32), {}, keyOverrides());
    const error = await client.claimOneTimeKey(identity, bob.userId).catch((e: unknown) => e);
    expect((error as ApiError).code).toBe("invalid_response");
  });

  it("rejects a one-time key signed for a different ratchet key of the same user", async () => {
    // A genuine signature by Bob, but tying the key to some other (older) ratchet key.
    const bob = createIdentity(NOW);
    const oneTimeKey = crypto.randomBytes(32);
    const sig = signOneTimeKey(crypto.randomBytes(32), oneTimeKey, bob.identityPrivateKey);
    respond = () => claimReply(bob, oneTimeKey, {}, { sig: crypto.toBase64(sig) });
    const error = await client.claimOneTimeKey(identity, bob.userId).catch((e: unknown) => e);
    expect((error as ApiError).code).toBe("invalid_response");
  });

  it("rejects a claim reply with no one-time key", async () => {
    const bob = createIdentity(NOW);
    respond = () => json(200, keysReply(bob));
    const error = await client.claimOneTimeKey(identity, bob.userId).catch((e: unknown) => e);
    expect((error as ApiError).code).toBe("invalid_response");
  });

  it("passes on 'no one-time keys'", async () => {
    respond = () => json(409, { error: "no_one_time_keys" });
    const error = await client.claimOneTimeKey(identity, createIdentity(NOW).userId).catch((e: unknown) => e);
    expect((error as ApiError).code).toBe("no_one_time_keys");
  });

  it("counts my keys", async () => {
    respond = () => json(200, { count: 12, has_fallback: true });
    expect(await client.countOneTimeKeys(identity)).toEqual({ count: 12, hasFallback: true });
    expect(seen[0]!.url).toBe("/api/keys/count");
    expect(signatureIsValid(seen[0]!, "/keys/count")).toBe(true);
  });

  it.each([
    ["a negative count", { count: -1, has_fallback: false }],
    ["a count that is text", { count: "3", has_fallback: false }],
    ["no fallback flag", { count: 3 }],
  ])("rejects a count reply with %s", async (_name, reply) => {
    respond = () => json(200, reply);
    const error = await client.countOneTimeKeys(identity).catch((e: unknown) => e);
    expect((error as ApiError).code).toBe("invalid_response");
  });

  it("uploads keys and a fallback key, each signed together with my ratchet key", async () => {
    respond = () => json(200, { count: 2, has_fallback: true });
    const keys = [
      { id: "AAAAAAAAAAA", key: crypto.randomBytes(32) },
      { id: "AAAAAAAAAAE", key: crypto.randomBytes(32) },
    ];
    const fallback = { id: "AAAAAAAAAAI", key: crypto.randomBytes(32) };
    expect(await client.uploadOneTimeKeys(identity, keys, fallback)).toEqual({ count: 2, hasFallback: true });

    expect(seen[0]!.method).toBe("POST");
    expect(seen[0]!.url).toBe("/api/keys/one-time");
    expect(signatureIsValid(seen[0]!, "/keys/one-time")).toBe(true);
    const body = JSON.parse(seen[0]!.body!) as {
      keys: { id: string; key: string; sig: string }[];
      fallback: { id: string; key: string; sig: string };
    };
    expect(body.keys.map((k) => k.id)).toEqual(["AAAAAAAAAAA", "AAAAAAAAAAE"]);
    expect(body.fallback.id).toBe("fallback-AAAAAAAAAAI");
    for (const [sent, original] of [...body.keys.map((k, i) => [k, keys[i]!] as const), [body.fallback, fallback] as const]) {
      expect(sent.key).toBe(crypto.toBase64(original.key));
      expect(
        verifyOneTimeKey(identity.ratchetPublicKey, original.key, crypto.fromBase64(sent.sig), identity.identityPublicKey),
      ).toBe(true);
    }
  });

  it("labels the fallback key's id so it cannot clash with a one-time key's", async () => {
    // The library numbers the two kinds separately: both first keys are "AAAAAAAAAAA".
    respond = () => json(200, { count: 1, has_fallback: true });
    const key = { id: "AAAAAAAAAAA", key: crypto.randomBytes(32) };
    await client.uploadOneTimeKeys(identity, [key], { id: "AAAAAAAAAAA", key: crypto.randomBytes(32) });
    const body = JSON.parse(seen[0]!.body!) as { keys: { id: string }[]; fallback: { id: string } };
    expect(body.keys[0]!.id).toBe("AAAAAAAAAAA");
    expect(body.fallback.id).toBe("fallback-AAAAAAAAAAA");
  });

  it("leaves out the fallback key when there is none to send", async () => {
    respond = () => json(200, { count: 1, has_fallback: true });
    await client.uploadOneTimeKeys(identity, [{ id: "AAAAAAAAAAA", key: crypto.randomBytes(32) }]);
    expect(JSON.parse(seen[0]!.body!)).not.toHaveProperty("fallback");
  });
});

describe("messages", () => {
  const MESSAGE_ID = "3f2b8c1e-5d4a-4b6f-9e7a-0c1d2e3f4a5b";

  function inboxEntry(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      message_id: MESSAGE_ID,
      from: createIdentity(NOW).userId,
      v: 2,
      type: 0,
      ciphertext: crypto.toBase64(crypto.randomBytes(40)),
      created_at: "2027-01-15T08:00:00.000Z",
      cursor: `1800000000000000_${MESSAGE_ID}`,
      ...overrides,
    };
  }

  it("sends the envelope unchanged and returns the server's message id", async () => {
    const envelope = {
      v: 2 as const,
      to: createIdentity(NOW).userId,
      type: 1 as const,
      ciphertext: crypto.toBase64(crypto.randomBytes(40)),
    };
    respond = () => json(201, { message_id: MESSAGE_ID, created_at: "2027-01-15T08:00:00.000Z" });
    expect(await client.sendMessage(identity, envelope)).toEqual({ messageId: MESSAGE_ID });
    expect(seen[0]!.method).toBe("POST");
    expect(seen[0]!.url).toBe("/api/messages");
    expect(JSON.parse(seen[0]!.body!)).toEqual(envelope);
    expect(signatureIsValid(seen[0]!, "/messages")).toBe(true);
  });

  it("rejects a send reply without a proper message id", async () => {
    respond = () => json(201, { message_id: "nope" });
    const envelope = { v: 2 as const, to: "x", type: 1 as const, ciphertext: "z" };
    const error = await client.sendMessage(identity, envelope).catch((e: unknown) => e);
    expect((error as ApiError).code).toBe("invalid_response");
  });

  it("fetches the inbox and converts each entry", async () => {
    const entry = inboxEntry();
    respond = () => json(200, [entry, { ...entry, type: 1 }]);
    const items = await client.fetchInbox(identity);
    expect(items[0]).toEqual({
      messageId: MESSAGE_ID,
      from: entry.from,
      type: 0,
      ciphertext: entry.ciphertext,
      createdAt: entry.created_at,
      cursor: entry.cursor,
    });
    expect(items[1]!.type).toBe(1);
    expect(seen[0]!.url).toBe("/api/messages/inbox");
    expect(signatureIsValid(seen[0]!, "/messages/inbox")).toBe(true);
  });

  it("asks for the next page with a cursor, and signs the path including it", async () => {
    respond = () => json(200, []);
    const cursor = `1800000000000000_${MESSAGE_ID}`;
    await client.fetchInbox(identity, cursor);
    expect(seen[0]!.url).toBe(`/api/messages/inbox?after=${cursor}`);
    expect(signatureIsValid(seen[0]!, `/messages/inbox?after=${cursor}`)).toBe(true);
    expect(signatureIsValid(seen[0]!, "/messages/inbox")).toBe(false);
  });

  it("refuses to put anything but a cursor into the request path", async () => {
    const error = await client.fetchInbox(identity, "1&x=../../register").catch((e: unknown) => e);
    expect((error as ApiError).code).toBe("invalid_request");
    expect(seen).toHaveLength(0);
  });

  it("returns an empty list for an empty inbox", async () => {
    respond = () => json(200, []);
    expect(await client.fetchInbox(identity)).toEqual([]);
  });

  it.each([
    ["a reply that is not a list", () => ({ not: "a list" }) as unknown],
    ["an entry with a bad message id", () => ([inboxEntry({ message_id: "../../x" })]) as unknown],
    ["an entry with a bad sender", () => ([inboxEntry({ from: "someone" })]) as unknown],
    ["an entry in the retired version 1", () => ([inboxEntry({ v: 1 })]) as unknown],
    ["an entry with no type", () => ([inboxEntry({ type: undefined })]) as unknown],
    ["an entry with an unknown type", () => ([inboxEntry({ type: 2 })]) as unknown],
    ["an entry with an empty ciphertext", () => ([inboxEntry({ ciphertext: "" })]) as unknown],
    ["an entry whose ciphertext is not base64", () => ([inboxEntry({ ciphertext: "<script>" })]) as unknown],
    ["an entry with an oversized ciphertext", () => ([inboxEntry({ ciphertext: "A".repeat(64 * 1024 + 4) })]) as unknown],
    ["an entry with a bad date", () => ([inboxEntry({ created_at: "yesterday" })]) as unknown],
    ["an entry with no cursor", () => ([inboxEntry({ cursor: undefined })]) as unknown],
    ["an entry with a malformed cursor", () => ([inboxEntry({ cursor: "next page please" })]) as unknown],
    ["an entry that is not an object", () => (["text"]) as unknown],
    ["one bad entry among good ones", () => ([inboxEntry(), inboxEntry({ from: 5 })]) as unknown],
  ])("rejects %s", async (_name, makeBody) => {
    // Built inside the test: the crypto library is not loaded yet when the table is defined.
    const body = makeBody();
    respond = () => json(200, body);
    const error = await client.fetchInbox(identity).catch((e: unknown) => e);
    expect((error as ApiError).code).toBe("invalid_response");
  });

  it("acknowledges a message", async () => {
    respond = () => new Response(null, { status: 204 });
    await client.ackMessage(identity, MESSAGE_ID);
    expect(seen[0]!.method).toBe("POST");
    expect(seen[0]!.url).toBe(`/api/messages/${MESSAGE_ID}/ack`);
    expect(seen[0]!.body).toBeUndefined();
    expect(signatureIsValid(seen[0]!, `/messages/${MESSAGE_ID}/ack`)).toBe(true);
  });

  it("refuses to build an ack path from anything but a message id", async () => {
    const error = await client.ackMessage(identity, "../register").catch((e: unknown) => e);
    expect((error as ApiError).code).toBe("invalid_request");
    expect(seen).toHaveLength(0);
  });

  it("passes on 'not found' when acknowledging", async () => {
    respond = () => json(404, { error: "not_found" });
    const error = await client.ackMessage(identity, MESSAGE_ID).catch((e: unknown) => e);
    expect((error as ApiError).code).toBe("not_found");
  });
});
