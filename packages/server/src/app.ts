import express, { type ErrorRequestHandler, type Express, type Request } from "express";
import type { Pool } from "./db/pool.js";

/** Requests are small JSON envelopes; anything larger is rejected before parsing. */
export const MAX_BODY_BYTES = 16 * 1024;

export interface AppDeps {
  pool: Pool;
  /** M1: single static invite code required by POST /register. */
  inviteCode: string;
  /** Clock in unix ms; injectable for tests. */
  now?: () => number;
}

const EMPTY = Buffer.alloc(0);
const rawBodies = new WeakMap<object, Buffer>();

/**
 * The exact bytes of the request body as received. Request signatures cover
 * a hash of these bytes, so they must not be re-serialized from parsed JSON.
 */
export function getRawBody(req: Request): Buffer {
  return rawBodies.get(req) ?? EMPTY;
}

/** Body parsing and routes that need no dependencies. Add routes, then call installFallbackHandlers. */
export function createBaseApp(): Express {
  const app = express();
  app.disable("x-powered-by");
  app.use(
    express.json({
      limit: MAX_BODY_BYTES,
      strict: true,
      verify: (req, _res, buf) => {
        rawBodies.set(req, buf);
      },
    }),
  );

  app.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  return app;
}

/** JSON 404 and error responses. Must be installed after all routes. */
export function installFallbackHandlers(app: Express): void {
  app.use((_req, res) => {
    res.status(404).json({ error: "not_found" });
  });

  const onError: ErrorRequestHandler = (err, _req, res, _next) => {
    const type = (err as { type?: string }).type;
    if (type === "entity.too.large") {
      res.status(413).json({ error: "payload_too_large" });
      return;
    }
    if (type === "entity.parse.failed") {
      res.status(400).json({ error: "invalid_json" });
      return;
    }
    // Never echo internal error details to the client.
    console.error(err);
    res.status(500).json({ error: "internal_error" });
  };
  app.use(onError);
}

export function createApp(_deps: AppDeps): Express {
  const app = createBaseApp();
  installFallbackHandlers(app);
  return app;
}
