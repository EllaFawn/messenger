import type { IncomingMessage } from "node:http";
import { describe, expect, it } from "vitest";
import { clientIp, RateLimiter } from "./rate-limit.js";

function limiter(limit: number, windowMs: number, maxKeys?: number) {
  let now = 1_000_000;
  const instance = new RateLimiter({ limit, windowMs }, () => now, maxKeys);
  return { instance, advance: (ms: number) => (now += ms) };
}

describe("RateLimiter", () => {
  it("allows up to the limit, then refuses", () => {
    const { instance } = limiter(3, 60_000);
    expect([1, 2, 3, 4, 5].map(() => instance.take("a").allowed)).toEqual([true, true, true, false, false]);
  });

  it("says how long to wait, rounded up to whole seconds", () => {
    const { instance, advance } = limiter(2, 60_000);
    instance.take("a");
    instance.take("a");
    const refused = instance.take("a");
    expect(refused).toEqual({ allowed: false, retryAfterSeconds: 30 });
    advance(29_500);
    expect(instance.take("a")).toEqual({ allowed: false, retryAfterSeconds: 1 });
  });

  it("lets requests through again as time passes, at the steady rate", () => {
    const { instance, advance } = limiter(2, 60_000);
    instance.take("a");
    instance.take("a");
    advance(30_000);
    expect(instance.take("a").allowed).toBe(true);
    expect(instance.take("a").allowed).toBe(false);
  });

  it("never saves up more than the limit, however long the wait", () => {
    const { instance, advance } = limiter(2, 60_000);
    advance(10 * 60_000);
    expect([1, 2, 3].map(() => instance.take("a").allowed)).toEqual([true, true, false]);
  });

  it("counts each key separately", () => {
    const { instance } = limiter(1, 60_000);
    expect(instance.take("a").allowed).toBe(true);
    expect(instance.take("b").allowed).toBe(true);
    expect(instance.take("a").allowed).toBe(false);
  });

  it("can check without spending", () => {
    const { instance } = limiter(1, 60_000);
    expect(instance.check("a").allowed).toBe(true);
    expect(instance.check("a").allowed).toBe(true);
    instance.take("a");
    expect(instance.check("a")).toEqual({ allowed: false, retryAfterSeconds: 60 });
  });

  it("forgets keys that have fully recovered, so memory does not grow without bound", () => {
    const { instance, advance } = limiter(2, 60_000);
    for (let i = 0; i < 500; i++) instance.take(`key-${i}`);
    expect(instance.size).toBe(500);
    advance(61_000);
    instance.take("another");
    expect(instance.size).toBe(1);
  });

  it("holds at most the configured number of keys, dropping the oldest", () => {
    const { instance } = limiter(1, 60_000, 100);
    for (let i = 0; i < 250; i++) instance.take(`key-${i}`);
    expect(instance.size).toBeLessThanOrEqual(100);
    // The most recent key is still being limited.
    expect(instance.take("key-249").allowed).toBe(false);
  });

  it("refuses a nonsensical rule", () => {
    expect(() => new RateLimiter({ limit: 0, windowMs: 1000 })).toThrow();
    expect(() => new RateLimiter({ limit: 5, windowMs: 0 })).toThrow();
  });
});

describe("clientIp", () => {
  function request(remoteAddress: string | undefined, forwardedFor?: string | string[]): IncomingMessage {
    return {
      socket: { remoteAddress },
      headers: forwardedFor === undefined ? {} : { "x-forwarded-for": forwardedFor },
    } as unknown as IncomingMessage;
  }

  it("uses the connection's address when no proxy is trusted", () => {
    expect(clientIp(request("203.0.113.9"), 0)).toBe("203.0.113.9");
  });

  it("ignores X-Forwarded-For when no proxy is trusted, so a client cannot pick its own address", () => {
    expect(clientIp(request("203.0.113.9", "1.2.3.4"), 0)).toBe("203.0.113.9");
  });

  it("takes the address our one trusted proxy reported", () => {
    expect(clientIp(request("10.0.0.1", "198.51.100.7"), 1)).toBe("198.51.100.7");
  });

  it("is not fooled by extra entries the client put in front", () => {
    // The client sent "1.2.3.4"; our proxy appended the real address.
    expect(clientIp(request("10.0.0.1", "1.2.3.4, 198.51.100.7"), 1)).toBe("198.51.100.7");
  });

  it("counts back the right number of trusted proxies", () => {
    expect(clientIp(request("10.0.0.1", "1.2.3.4, 198.51.100.7, 10.0.0.2"), 2)).toBe("198.51.100.7");
  });

  it("handles the header arriving as several lines", () => {
    expect(clientIp(request("10.0.0.1", ["1.2.3.4", "198.51.100.7"]), 1)).toBe("198.51.100.7");
  });

  it("falls back to the connection's address when the header is missing or too short", () => {
    expect(clientIp(request("10.0.0.1"), 1)).toBe("10.0.0.1");
    expect(clientIp(request("10.0.0.1", "198.51.100.7"), 2)).toBe("10.0.0.1");
    expect(clientIp(request("10.0.0.1", " , "), 1)).toBe("10.0.0.1");
  });

  it("treats the IPv4-mapped form of an address as the same address", () => {
    expect(clientIp(request("::ffff:203.0.113.9"), 0)).toBe("203.0.113.9");
  });

  it("returns a fixed placeholder when the address is unknown", () => {
    expect(clientIp(request(undefined), 0)).toBe("unknown");
  });
});
