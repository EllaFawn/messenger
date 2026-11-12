import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { createApp, createBaseApp, getRawBody, installFallbackHandlers, MAX_BODY_BYTES } from "./app.js";
import { loadConfig } from "./config.js";
import { createPool } from "./db/pool.js";
import { startTestServer, type TestServer } from "./test-http.js";

let server: TestServer;

beforeAll(async () => {
  const app = createBaseApp();
  // Test-only routes to observe body handling and error handling.
  app.post("/_test/echo", (req, res) => {
    res.json({ body: req.body, rawBody: getRawBody(req).toString("utf8") });
  });
  app.get("/_test/raw", (req, res) => {
    res.json({ rawLength: getRawBody(req).length });
  });
  app.get("/_test/boom", () => {
    throw new Error("secret internal detail");
  });
  installFallbackHandlers(app);
  server = await startTestServer(app);
});

afterAll(async () => {
  await server.close();
});

afterEach(() => {
  vi.restoreAllMocks();
});

function postJson(path: string, body: string) {
  return fetch(server.url + path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });
}

describe("app skeleton", () => {
  it("answers GET /health", async () => {
    const res = await fetch(server.url + "/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok" });
  });

  it("does not advertise the framework", async () => {
    const res = await fetch(server.url + "/health");
    expect(res.headers.get("x-powered-by")).toBeNull();
  });

  it("returns JSON 404 for unknown routes", async () => {
    const res = await fetch(server.url + "/nope");
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "not_found" });
  });

  it("parses JSON and keeps the exact raw bytes for signature checks", async () => {
    const raw = '{ "b": 1,   "a": "x" }';
    const res = await postJson("/_test/echo", raw);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ body: { b: 1, a: "x" }, rawBody: raw });
  });

  it("treats a request with no body as empty raw bytes", async () => {
    const res = await fetch(server.url + "/_test/raw");
    expect(await res.json()).toEqual({ rawLength: 0 });
  });

  it("rejects malformed JSON with 400", async () => {
    const res = await postJson("/_test/echo", '{"a": ');
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_json" });
  });

  it("rejects JSON that is not an object or array with 400", async () => {
    const res = await postJson("/_test/echo", '"just a string"');
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_json" });
  });

  it("rejects bodies over the size limit with 413", async () => {
    const res = await postJson("/_test/echo", JSON.stringify({ pad: "x".repeat(MAX_BODY_BYTES) }));
    expect(res.status).toBe(413);
    expect(await res.json()).toEqual({ error: "payload_too_large" });
  });

  it("hides internal error details behind a generic 500", async () => {
    const logged = vi.spyOn(console, "error").mockImplementation(() => {});
    const res = await fetch(server.url + "/_test/boom");
    expect(res.status).toBe(500);
    const text = await res.text();
    expect(JSON.parse(text)).toEqual({ error: "internal_error" });
    expect(text).not.toContain("secret internal detail");
    expect(logged).toHaveBeenCalledOnce();
  });
});

describe("createApp", () => {
  it("serves the base routes and fallbacks", async () => {
    // The pool connects lazily; these routes never query it.
    const pool = createPool(loadConfig().databaseUrl);
    const real = await startTestServer(createApp({ pool, inviteCode: "test-invite-code-0123456789" }));
    try {
      expect((await fetch(real.url + "/health")).status).toBe(200);
      expect((await fetch(real.url + "/nope")).status).toBe(404);
    } finally {
      await real.close();
      await pool.end();
    }
  });
});
