import type { RequestHandler, Response } from "express";
import { clientIp, RateLimiter, type RateDecision, type RateRule } from "./rate-limit.js";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

/** One rule per kind of request. See the M2 design, section 4. */
export interface RateLimits {
  /** Registration attempts, per client address. */
  register: RateRule;
  /** Requests that fail authentication, per client address. Once exceeded, that address is refused entirely. */
  failedAuth: RateRule;
  /** WebSocket connection attempts, per client address. */
  wsUpgrade: RateRule;
  /** Messages sent, per sender. */
  sendMessage: RateRule;
  /** Public-key lookups, per caller. */
  keyLookup: RateRule;
  /** Every other signed request, per caller. */
  signed: RateRule;
  /**
   * One-time keys claimed, per caller and target together. Each claim uses
   * up one of the target's keys, so this stops one user draining another's supply.
   */
  keyClaim: RateRule;
}

export const DEFAULT_RATE_LIMITS: RateLimits = {
  register: { limit: 5, windowMs: HOUR },
  failedAuth: { limit: 30, windowMs: MINUTE },
  wsUpgrade: { limit: 20, windowMs: MINUTE },
  sendMessage: { limit: 60, windowMs: MINUTE },
  keyLookup: { limit: 30, windowMs: MINUTE },
  signed: { limit: 300, windowMs: MINUTE },
  keyClaim: { limit: 10, windowMs: HOUR },
};

export type Limiters = { [K in keyof RateLimits]: RateLimiter };

export function createLimiters(limits: RateLimits = DEFAULT_RATE_LIMITS, now?: () => number): Limiters {
  return {
    register: new RateLimiter(limits.register, now),
    failedAuth: new RateLimiter(limits.failedAuth, now),
    wsUpgrade: new RateLimiter(limits.wsUpgrade, now),
    sendMessage: new RateLimiter(limits.sendMessage, now),
    keyLookup: new RateLimiter(limits.keyLookup, now),
    signed: new RateLimiter(limits.signed, now),
    keyClaim: new RateLimiter(limits.keyClaim, now),
  };
}

/** What routes need to apply limits. Both are optional: with no limiters, nothing is limited. */
export interface LimitDeps {
  limiters?: Limiters;
  /** How many reverse proxies in front of the server to believe for the client's address. */
  trustedProxies?: number;
}

export function tooManyRequests(res: Response, decision: RateDecision): void {
  if (!decision.allowed) {
    res.setHeader("Retry-After", String(decision.retryAfterSeconds));
  }
  res.status(429).json({ error: "rate_limited" });
}

/** Limits a route by the caller's network address. For routes that have no authenticated caller yet. */
export function limitByIp(pick: (limiters: Limiters) => RateLimiter, deps: LimitDeps): RequestHandler {
  return (req, res, next) => {
    if (deps.limiters === undefined) {
      next();
      return;
    }
    const decision = pick(deps.limiters).take(clientIp(req, deps.trustedProxies ?? 0));
    if (decision.allowed) next();
    else tooManyRequests(res, decision);
  };
}

/** Limits a route by the authenticated user. Must come after requireSignedRequest. */
export function limitByCaller(pick: (limiters: Limiters) => RateLimiter, deps: LimitDeps): RequestHandler {
  return (_req, res, next) => {
    if (deps.limiters === undefined) {
      next();
      return;
    }
    const userId: unknown = res.locals.userId;
    if (typeof userId !== "string") {
      throw new Error("limitByCaller used on a route without requireSignedRequest");
    }
    const decision = pick(deps.limiters).take(userId);
    if (decision.allowed) next();
    else tooManyRequests(res, decision);
  };
}

/**
 * Counts every response that ends in 401 against the client's address, and
 * turns that address away once it has failed too often. This bounds how
 * fast anyone can guess at signatures or make the server look users up.
 */
export function guardFailedAuth(deps: LimitDeps): RequestHandler {
  return (req, res, next) => {
    const limiter = deps.limiters?.failedAuth;
    if (limiter === undefined) {
      next();
      return;
    }
    const ip = clientIp(req, deps.trustedProxies ?? 0);
    const decision = limiter.check(ip);
    if (!decision.allowed) {
      tooManyRequests(res, decision);
      return;
    }
    res.on("finish", () => {
      if (res.statusCode === 401) limiter.take(ip);
    });
    next();
  };
}
