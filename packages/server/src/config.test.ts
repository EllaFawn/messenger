import { describe, expect, it } from "vitest";
import { DEFAULT_DATABASE_URL, loadConfig, loadServerConfig, MIN_INVITE_CODE_LENGTH } from "./config.js";

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
