import { sep } from "node:path";
import express, { type ErrorRequestHandler, type Express } from "express";
import type { Pool } from "./db/pool.js";
import { getRawBody, rememberRawBody } from "./raw-body.js";
import { messagesRouter } from "./routes/messages.js";
import { registerRouter } from "./routes/register.js";
import { usersRouter } from "./routes/users.js";

export { getRawBody };

/** Requests are small JSON envelopes; anything larger is rejected before parsing. */
export const MAX_BODY_BYTES = 16 * 1024;

/** The web app reaches the API under this prefix, on the same origin as the page. */
export const API_PREFIX = "/api";

/**
 * Limits what a page from this server may do, so that an injected script has
 * as little reach as possible: scripts, styles, images and connections only
 * from this server; no inline script; no eval of text; no framing.
 * 'wasm-unsafe-eval' allows compiling WebAssembly (the crypto library) and
 * nothing else.
 */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self'",
  "img-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

export interface AppDeps {
  pool: Pool;
  /** M1: single static invite code required by POST /register. */
  inviteCode: string;
  /** Clock in unix ms; injectable for tests. */
  now?: () => number;
  /** Called with the recipient's userID after a message is stored. */
  onMessageStored?: (toUserId: string) => void;
  /** Folder holding the built web app. If set, the server serves it alongside the API. */
  webDir?: string;
}

/** Removes the /api prefix from a request path, or returns null if it has none. */
export function stripApiPrefix(url: string): string | null {
  if (url.startsWith(`${API_PREFIX}/`)) {
    return url.slice(API_PREFIX.length);
  }
  return null;
}

/** Body parsing and routes that need no dependencies. Add routes, then call installFallbackHandlers. */
export function createBaseApp(): Express {
  const app = express();
  app.disable("x-powered-by");

  app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", CONTENT_SECURITY_POLICY);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    // API replies are never stored by the browser; static files override this below.
    res.setHeader("Cache-Control", "no-store");

    // /api/register is handled exactly as /register, which is also the path
    // the client signs. The dev server's proxy does the same rewrite.
    const stripped = stripApiPrefix(req.url);
    if (stripped !== null) {
      req.url = stripped;
      req.originalUrl = stripped;
      res.locals.viaApiPrefix = true;
    }
    next();
  });
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
  if (deps.webDir !== undefined) {
    const serveWeb = express.static(deps.webDir, {
      dotfiles: "ignore",
      index: "index.html",
      redirect: false,
      setHeaders: (res, filePath) => {
        // Built assets have a content hash in their name, so they can be cached for good.
        const hashedAsset = filePath.includes(`${sep}assets${sep}`);
        res.setHeader("Cache-Control", hashedAsset ? "public, max-age=31536000, immutable" : "no-cache");
      },
    });
    // Anything under /api is an API call and never falls through to a web file.
    app.use((req, res, next) => (res.locals.viaApiPrefix === true ? next() : serveWeb(req, res, next)));
  }
  installFallbackHandlers(app);
  return app;
}
