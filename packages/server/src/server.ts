import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createApp } from "./app.js";
import { sweepExpiredNonces } from "./auth/nonce-store.js";
import type { Pool } from "./db/pool.js";
import { createLimiters, DEFAULT_RATE_LIMITS, type RateLimits } from "./limits.js";
import { sweepExpiredMessages } from "./routes/messages.js";
import { createPushHub, type PushOptions } from "./push.js";

export interface StartServerOptions {
  pool: Pool;
  host: string;
  /** 0 picks a free port. */
  port: number;
  sweepIntervalMs?: number;
  /** Folder holding the built web app, to serve it from this same server. */
  webDir?: string | null;
  /** Overrides the default rate limits. */
  rateLimits?: RateLimits;
  /** How many reverse proxies in front of the server to believe for the client's address. Default 0. */
  trustedProxies?: number;
  push?: PushOptions;
}

export interface RunningServer {
  url: string;
  /** Open push (WebSocket) connections, across all users. */
  pushConnectionCount(): number;
  /** Stops accepting requests and stops the sweeper. Does not close the pool. */
  close(): Promise<void>;
}

const DEFAULT_SWEEP_INTERVAL_MS = 60_000;

/**
 * Deletes expired request nonces and uncollected old messages on a timer.
 * Returns a function that stops it.
 */
export function startNonceSweeper(pool: Pool, intervalMs: number): () => void {
  const timer = setInterval(() => {
    sweepExpiredNonces(pool, new Date()).catch((err: unknown) => {
      console.error("nonce sweep failed:", err);
    });
    sweepExpiredMessages(pool, new Date()).catch((err: unknown) => {
      console.error("message sweep failed:", err);
    });
  }, intervalMs);
  // Do not keep the process alive just for the sweeper.
  timer.unref();
  return () => clearInterval(timer);
}

export async function startServer(options: StartServerOptions): Promise<RunningServer> {
  // A running server is always rate limited; only the bare app (used in tests) can be built without.
  const limits = {
    limiters: createLimiters(options.rateLimits ?? DEFAULT_RATE_LIMITS),
    trustedProxies: options.trustedProxies ?? 0,
  };
  const push = createPushHub({ pool: options.pool, ...limits }, options.push);
  const app = createApp({
    pool: options.pool,
    ...limits,
    onMessageStored: push.notify,
    webDir: options.webDir ?? undefined,
  });

  const server: Server = await new Promise((resolve, reject) => {
    const s = app.listen(options.port, options.host, (err?: Error) => (err ? reject(err) : resolve(s)));
  });
  server.on("upgrade", push.handleUpgrade);
  const stopSweeper = startNonceSweeper(options.pool, options.sweepIntervalMs ?? DEFAULT_SWEEP_INTERVAL_MS);
  const { port } = server.address() as AddressInfo;

  return {
    url: `http://${options.host}:${port}`,
    pushConnectionCount: push.connectionCount,
    close() {
      stopSweeper();
      push.close();
      return new Promise((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
        server.closeAllConnections();
      });
    },
  };
}
