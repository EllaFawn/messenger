import express, { type ErrorRequestHandler, type Express } from "express";
import type { Pool } from "./db/pool.js";
import { getRawBody, rememberRawBody } from "./raw-body.js";
import { messagesRouter } from "./routes/messages.js";
import { registerRouter } from "./routes/register.js";
import { usersRouter } from "./routes/users.js";

export { getRawBody };

/** Requests are small JSON envelopes; anything larger is rejected before parsing. */
export const MAX_BODY_BYTES = 16 * 1024;

export interface AppDeps {
  pool: Pool;
  /** M1: single static invite code required by POST /register. */
  inviteCode: string;
  /** Clock in unix ms; injectable for tests. */
  now?: () => number;
  /** Called with the recipient's userID after a message is stored. */
  onMessageStored?: (toUserId: string) => void;
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
        rememberRawBody(req, buf);
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

export function createApp(deps: AppDeps): Express {
  const app = createBaseApp();
  app.use(registerRouter(deps));
  app.use(usersRouter(deps));
  app.use(messagesRouter(deps));
  installFallbackHandlers(app);
  return app;
}
