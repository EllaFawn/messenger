import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_DATABASE_URL,
  DEFAULT_WEB_DIR,
  loadConfig,
  loadServerConfig,
} from "./config.js";


describe("loadConfig", () => {
  it("defaults to the docker-compose dev database", () => {
    expect(loadConfig({}).databaseUrl).toBe(DEFAULT_DATABASE_URL);
  });

  it("uses DATABASE_URL when set", () => {
    expect(loadConfig({ DATABASE_URL: "postgres://x/y" }).databaseUrl).toBe("postgres://x/y");
  });
});

describe("loadServerConfig", () => {
  it("loads defaults when nothing is set", () => {
    expect(loadServerConfig({})).toEqual({
      databaseUrl: DEFAULT_DATABASE_URL,
      host: "127.0.0.1",
      port: 3000,
      webDir: null,
    });
  });

  it("reads HOST and PORT", () => {
    const config = loadServerConfig({ HOST: "0.0.0.0", PORT: "8080" });
    expect(config.host).toBe("0.0.0.0");
    expect(config.port).toBe(8080);
  });

  it("no longer needs or reads INVITE_CODE: invites are per person and live in the database", () => {
    const config = loadServerConfig({ INVITE_CODE: "some-old-shared-code-0000000" });
    expect(JSON.stringify(config)).not.toContain("some-old-shared-code");
    expect(Object.keys(config).sort()).toEqual(["databaseUrl", "host", "port", "webDir"]);
  });

  it.each(["abc", "0", "70000", "-1", "3000.5", ""])("refuses an invalid PORT (%s)", (port) => {
    expect(() => loadServerConfig({ PORT: port })).toThrow(/PORT/);
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
    expect(loadServerConfig({}).webDir).toBeNull();
  });

  it.each(["1", "true"])("serves the built web app when set to %s", (value) => {
    withBuiltWeb((dir) => {
      expect(loadServerConfig({ SERVE_WEB: value }, dir).webDir).toBe(dir);
    });
  });

  it.each(["0", "false", ""])("stays off when set to %j", (value) => {
    expect(loadServerConfig({ SERVE_WEB: value }).webDir).toBeNull();
  });

  it("refuses a value it does not understand", () => {
    expect(() => loadServerConfig({ SERVE_WEB: "yes please" })).toThrow(/SERVE_WEB/);
  });

  it("refuses to start if the web app has not been built", () => {
    const missing = join(tmpdir(), "messager-web-does-not-exist");
    expect(() => loadServerConfig({ SERVE_WEB: "1" }, missing)).toThrow(
      /npm run build -w @messager\/web/,
    );
  });

  it("looks for the build in the web package by default", () => {
    expect(DEFAULT_WEB_DIR.replaceAll("\\", "/")).toMatch(/packages\/web\/dist$/);
  });
});
