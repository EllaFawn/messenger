import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as crypto from "@messager/crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { CONTENT_SECURITY_POLICY, createApp } from "./app.js";
import { migrate } from "./db/migrate.js";
import { createTestDatabase, type TestDatabase } from "./db/test-db.js";
import { startServer, type RunningServer } from "./server.js";
import { insertUser, makeIdentity, signedFetch, signedWsUrl, type TestIdentity } from "./test-client.js";
import { startTestServer, type TestServer } from "./test-http.js";

const INDEX_HTML = '<!doctype html><title>Messager</title><script type="module" src="/assets/app-abc123.js"></script>';

let db: TestDatabase;
let webDir: string;
let withWeb: TestServer;
let apiOnly: TestServer;
let alice: TestIdentity;

beforeAll(async () => {
  await crypto.ready;
  db = await createTestDatabase();
  await migrate(db.pool);

  // A stand-in for the built web app.
  webDir = await mkdtemp(join(tmpdir(), "messager-web-"));
  await mkdir(join(webDir, "assets"));
  await writeFile(join(webDir, "index.html"), INDEX_HTML);
  await writeFile(join(webDir, "assets", "app-abc123.js"), "console.log('app');");
  await writeFile(join(webDir, ".secret"), "do not serve");

  withWeb = await startTestServer(createApp({ pool: db.pool, webDir }));
  apiOnly = await startTestServer(createApp({ pool: db.pool }));
});

afterAll(async () => {
  await withWeb.close();
  await apiOnly.close();
  await db.drop();
  await rm(webDir, { recursive: true, force: true });
});

beforeEach(async () => {
  await db.pool.query("TRUNCATE one_time_keys, invites, messages, auth_nonces, users");
  alice = makeIdentity();
  await insertUser(db.pool, alice);
});

describe("security headers", () => {
  it.each([
    ["the page", "/"],
    ["a script", "/assets/app-abc123.js"],
    ["an API reply", "/health"],
    ["a 404", "/nope"],
    ["an auth failure", "/messages/inbox"],
  ])("are sent with %s", async (_name, path) => {
    const res = await fetch(withWeb.url + path);
    expect(res.headers.get("content-security-policy")).toBe(CONTENT_SECURITY_POLICY);
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("cross-origin-opener-policy")).toBe("same-origin");
    expect(res.headers.get("cross-origin-resource-policy")).toBe("same-origin");
    expect(res.headers.get("x-powered-by")).toBeNull();
  });

  it("are sent even when the server is not serving the web app", async () => {
    const res = await fetch(apiOnly.url + "/health");
    expect(res.headers.get("content-security-policy")).toBe(CONTENT_SECURITY_POLICY);
  });

  it("allow scripts only from this server, with no inline script, eval or remote origins", () => {
    const policy = new Map(
      CONTENT_SECURITY_POLICY.split(";").map((part) => {
        const [name, ...values] = part.trim().split(/\s+/);
        return [name!, values] as const;
      }),
    );
    expect(policy.get("default-src")).toEqual(["'none'"]);
    // 'wasm-unsafe-eval' lets the crypto library's WebAssembly load; it does not allow eval of text.
    expect(policy.get("script-src")).toEqual(["'self'", "'wasm-unsafe-eval'"]);
    expect(policy.get("connect-src")).toEqual(["'self'"]);
    expect(policy.get("frame-ancestors")).toEqual(["'none'"]);
    expect(policy.get("base-uri")).toEqual(["'none'"]);
    expect(policy.get("form-action")).toEqual(["'none'"]);
    expect(CONTENT_SECURITY_POLICY).not.toContain("unsafe-inline");
    expect(CONTENT_SECURITY_POLICY).not.toMatch(/'unsafe-eval'/);
    expect(CONTENT_SECURITY_POLICY).not.toMatch(/https?:|\*/);
  });

  it("tell browsers never to store API replies", async () => {
    const res = await signedFetch(withWeb.url, alice, "/messages/inbox", { timestamp: Date.now() });
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
  });
});

describe("serving the web app", () => {
  it("serves the page at /", async () => {
    const res = await fetch(withWeb.url + "/");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/^text\/html/);
    expect(await res.text()).toBe(INDEX_HTML);
    // The page itself is always re-checked, so a new version is picked up at once.
    expect(res.headers.get("cache-control")).toBe("no-cache");
  });

  it("serves scripts with a JavaScript type and long-lived caching", async () => {
    const res = await fetch(withWeb.url + "/assets/app-abc123.js");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/javascript/);
    expect(res.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
  });

  it.each([
    ["a hidden file", "/.secret"],
    ["a path climbing out of the folder", "/..%2f..%2fpackage.json"],
    ["an encoded climb", "/%2e%2e/%2e%2e/package.json"],
    ["a climb inside assets", "/assets/..%2f.secret"],
    ["a file that does not exist", "/assets/missing.js"],
  ])("does not serve %s", async (_name, path) => {
    const res = await fetch(withWeb.url + path);
    expect(res.status).toBe(404);
    const text = await res.text();
    expect(text).not.toContain("do not serve");
    expect(text).not.toContain("workspaces");
  });

  it("does not serve the page for POST", async () => {
    const res = await fetch(withWeb.url + "/", { method: "POST" });
    expect(res.status).toBe(404);
  });

  it("serves no page at all unless a web folder is configured", async () => {
    const res = await fetch(apiOnly.url + "/");
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "not_found" });
  });
});

describe("the /api prefix", () => {
  it("reaches the same routes as the bare paths", async () => {
    const res = await fetch(withWeb.url + "/api/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok" });
  });

  it("accepts a request signed for the path without the prefix, as the web app signs it", async () => {
    const path = `/users/${alice.userId}/pubkeys`;
    const res = await signedFetch(withWeb.url, alice, "/api" + path, {
      timestamp: Date.now(),
      signAs: { path },
    });
    expect(res.status).toBe(200);
  });

  it("rejects a request signed for the prefixed path", async () => {
    const path = `/api/users/${alice.userId}/pubkeys`;
    const res = await signedFetch(withWeb.url, alice, path, { timestamp: Date.now() });
    expect(res.status).toBe(401);
  });

  it("keeps the query string when stripping the prefix", async () => {
    const res = await signedFetch(withWeb.url, alice, "/api/messages/inbox?x=1", {
      timestamp: Date.now(),
      signAs: { path: "/messages/inbox?x=1" },
    });
    expect(res.status).toBe(200);
  });

  it("returns a JSON 404 for unknown API paths rather than the page", async () => {
    for (const path of ["/api", "/api/", "/api/nope", "/apiary"]) {
      const res = await fetch(withWeb.url + path);
      expect(res.status).toBe(404);
      expect(await res.json()).toEqual({ error: "not_found" });
    }
  });

  it("works when the web app is not being served", async () => {
    expect((await fetch(apiOnly.url + "/api/health")).status).toBe(200);
  });
});

describe("push through the /api prefix", () => {
  let running: RunningServer;

  beforeEach(async () => {
    running = await startServer({ pool: db.pool, host: "127.0.0.1", port: 0, webDir });
  });

  it("accepts the push connection at /api/ws and serves the page from the same server", async () => {
    const opened = await new Promise<boolean>((resolve) => {
      const socket = new WebSocket(signedWsUrl(running.url, alice, { path: "/api/ws" }));
      socket.addEventListener("open", () => {
        socket.close();
        resolve(true);
      });
      socket.addEventListener("error", () => resolve(false));
    });
    expect(opened).toBe(true);
    expect(await (await fetch(running.url + "/")).text()).toBe(INDEX_HTML);
    await running.close();
  });

  it("still refuses an unsigned connection at /api/ws", async () => {
    const opened = await new Promise<boolean>((resolve) => {
      const socket = new WebSocket(`${running.url.replace(/^http/, "ws")}/api/ws`);
      socket.addEventListener("open", () => resolve(true));
      socket.addEventListener("error", () => resolve(false));
    });
    expect(opened).toBe(false);
    await running.close();
  });
});
