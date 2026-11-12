import * as crypto from "@messager/crypto";
import { verifyRequest } from "@messager/protocol";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createIdentity, type StoredIdentity } from "../identity.js";
import { ApiError, createApiClient, type ApiClient } from "./client.js";

const NOW = 1_800_000_000_000;

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
    for (const secret of [identity.identityPrivateKey, identity.exchangePrivateKey]) {
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
  it("posts the public keys and invite code, signed by the new identity", async () => {
    respond = () => json(201, { userID: identity.userId });
    await client.register(identity, "the-invite-code-0123456789");

    const request = seen[0]!;
    expect(request.method).toBe("POST");
    expect(request.url).toBe("/api/register");
    expect(JSON.parse(request.body!)).toEqual({
      userID: identity.userId,
      identity_pubkey: crypto.toBase64(identity.identityPublicKey),
      exchange_pubkey: crypto.toBase64(identity.exchangePublicKey),
      inviteCode: "the-invite-code-0123456789",
    });
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
