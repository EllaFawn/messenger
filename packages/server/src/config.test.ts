import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_DATABASE_URL,
  DEFAULT_WEB_DIR,
  loadConfig,
  loadServerConfig,
  MIN_INVITE_CODE_LENGTH,
} from "./config.js";

const INVITE = "a-long-enough-invite-code-123";

describe("loadConfig", () => {
  it("defaults to the docker-compose dev database", () => {
    expect(loadConfig({}).databaseUrl).toBe(DEFAULT_DATABASE_URL);
  });

  it("uses DATABASE_URL when set", () => {
    expect(loadConfig({ DATABASE_URL: "postgres://x/y" }).databaseUrl).toBe("postgres://x/y");
  });
});

describe("loadServerConfig", () => {
  it("loads defaults when only INVITE_CODE is set", () => {
    expect(loadServerConfig({ INVITE_CODE: INVITE })).toEqual({
      databaseUrl: DEFAULT_DATABASE_URL,
      inviteCode: INVITE,
      host: "127.0.0.1",
      port: 3000,
      webDir: null,
    });
  });

  it("reads HOST and PORT", () => {
    const config = loadServerConfig({ INVITE_CODE: INVITE, HOST: "0.0.0.0", PORT: "8080" });
    expect(config.host).toBe("0.0.0.0");
    expect(config.port).toBe(8080);
  });

  it("refuses to start without an invite code", () => {
    expect(() => loadServerConfig({})).toThrow(/INVITE_CODE/);
    expect(() => loadServerConfig({ INVITE_CODE: "" })).toThrow(/INVITE_CODE/);
  });

  it("refuses an invite code that is too short to resist guessing", () => {
    const short = "x".repeat(MIN_INVITE_CODE_LENGTH - 1);
    expect(() => loadServerConfig({ INVITE_CODE: short })).toThrow(/INVITE_CODE/);
  });

  it("does not put the invite code in the error message", () => {
    try {
      loadServerConfig({ INVITE_CODE: "short-secret" });
      expect.unreachable();
    } catch (err) {
      expect((err as Error).message).not.toContain("short-secret");
    }
  });

  it.each(["abc", "0", "70000", "-1", "3000.5", ""])("refuses an invalid PORT (%s)", (port) => {
    expect(() => loadServerConfig({ INVITE_CODE: INVITE, PORT: port })).toThrow(/PORT/);
  });
});

describe("SERVE_WEB", () => {
  function withBuiltWeb<T>(run: (dir: string) => T): T {
    const dir = mkdtempSync(join(tmpdir(), "messager-web-"));
    writeFileSync(join(dir, "index.html"), "<!doctype html>");
    try {
      return run(dir);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  it("is off by default, so the server is API-only", () => {
    expect(loadServerConfig({ INVITE_CODE: INVITE }).webDir).toBeNull();
  });

  it.each(["1", "true"])("serves the built web app when set to %s", (value) => {
    withBuiltWeb((dir) => {
      expect(loadServerConfig({ INVITE_CODE: INVITE, SERVE_WEB: value }, dir).webDir).toBe(dir);
    });
  });

  it.each(["0", "false", ""])("stays off when set to %j", (value) => {
    expect(loadServerConfig({ INVITE_CODE: INVITE, SERVE_WEB: value }).webDir).toBeNull();
  });

  it("refuses a value it does not understand", () => {
    expect(() => loadServerConfig({ INVITE_CODE: INVITE, SERVE_WEB: "yes please" })).toThrow(/SERVE_WEB/);
  });

  it("refuses to start if the web app has not been built", () => {
    const missing = join(tmpdir(), "messager-web-does-not-exist");
    expect(() => loadServerConfig({ INVITE_CODE: INVITE, SERVE_WEB: "1" }, missing)).toThrow(
      /npm run build -w @messager\/web/,
    );
  });

  it("looks for the build in the web package by default", () => {
    expect(DEFAULT_WEB_DIR.replaceAll("\\", "/")).toMatch(/packages\/web\/dist$/);
  });
});
