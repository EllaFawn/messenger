import type { IncomingMessage } from "node:http";

export interface RateRule {
  /** How many requests are allowed in a burst, and per window on average. */
  limit: number;
  windowMs: number;
}

export type RateDecision = { allowed: true } | { allowed: false; retryAfterSeconds: number };

interface Bucket {
  tokens: number;
  updatedAt: number;
}

const DEFAULT_MAX_KEYS = 50_000;

/**
 * A token bucket per key, held in memory. Each key may make `limit` requests
 * at once and then earns them back steadily over `windowMs`.
 *
 * In memory is enough because the server is a single process. Running
 * several behind a load balancer would need a shared store instead.
 */
export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly refillPerMs: number;
  private lastPrunedAt = 0;

  constructor(
    private readonly rule: RateRule,
    private readonly now: () => number = Date.now,
    private readonly maxKeys: number = DEFAULT_MAX_KEYS,
  ) {
    if (!(rule.limit >= 1) || !(rule.windowMs > 0)) {
      throw new Error("a rate rule needs a limit of at least 1 and a positive window");
    }
    this.refillPerMs = rule.limit / rule.windowMs;
  }

  /** Number of keys currently remembered. */
  get size(): number {
    return this.buckets.size;
  }

  private currentTokens(key: string, now: number): number {
    const bucket = this.buckets.get(key);
    if (bucket === undefined) return this.rule.limit;
    return Math.min(this.rule.limit, bucket.tokens + (now - bucket.updatedAt) * this.refillPerMs);
  }

  private refusal(tokens: number): RateDecision {
    return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((1 - tokens) / this.refillPerMs / 1000)) };
  }

  /** Whether a request would be allowed right now, without counting one. */
  check(key: string): RateDecision {
    const tokens = this.currentTokens(key, this.now());
    return tokens >= 1 ? { allowed: true } : this.refusal(tokens);
  }

  /** Counts one request against the key and says whether it is allowed. */
  take(key: string): RateDecision {
    const now = this.now();
    this.prune(now);
    const tokens = this.currentTokens(key, now);
    if (tokens < 1) {
      return this.refusal(tokens);
    }
    // Re-inserting keeps the map ordered by most recent use, which is what eviction relies on.
    this.buckets.delete(key);
    this.buckets.set(key, { tokens: tokens - 1, updatedAt: now });
    while (this.buckets.size > this.maxKeys) {
      const oldest = this.buckets.keys().next().value;
      if (oldest === undefined) break;
      this.buckets.delete(oldest);
    }
    return { allowed: true };
  }

  /** Drops keys whose bucket has refilled completely: they behave exactly like a key never seen. */
  private prune(now: number): void {
    if (now - this.lastPrunedAt < this.rule.windowMs) return;
    this.lastPrunedAt = now;
    for (const [key, bucket] of this.buckets) {
      if (bucket.tokens + (now - bucket.updatedAt) * this.refillPerMs >= this.rule.limit) {
        this.buckets.delete(key);
      }
    }
  }
}

/**
 * The address of whoever is making the request.
 *
 * With `trustedProxies` 0 this is the connection's own address and
 * X-Forwarded-For is ignored, since any client can send that header. Behind
 * a reverse proxy, each proxy appends the address it saw, so the entry our
 * outermost trusted proxy wrote is `trustedProxies` from the end; anything
 * further left came from the client and is not believed.
 */
export function clientIp(req: IncomingMessage, trustedProxies: number): string {
  const direct = normalise(req.socket.remoteAddress);
  if (trustedProxies <= 0) return direct;

  const header = req.headers["x-forwarded-for"];
  const entries = (Array.isArray(header) ? header.join(",") : (header ?? ""))
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "");
  const reported = entries[entries.length - trustedProxies];
  return reported === undefined ? direct : normalise(reported);
}

function normalise(address: string | undefined): string {
  if (address === undefined || address === "") return "unknown";
  return address.startsWith("::ffff:") ? address.slice(7) : address;
}
