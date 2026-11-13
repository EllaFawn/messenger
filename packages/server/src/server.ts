import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createApp } from "./app.js";
import { sweepExpiredNonces } from "./auth/nonce-store.js";
import type { Pool } from "./db/pool.js";
import { createPushHub } from "./push.js";

export interface StartServerOptions {
  pool: Pool;
  inviteCode: string;
  host: string;
  /** 0 picks a free port. */
  port: number;
  sweepIntervalMs?: number;
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
 * Deletes expired request nonces on a timer so auth_nonces stays small.
 * Returns a function that stops it.
 */
export function startNonceSweeper(pool: Pool, intervalMs: number): () => void {
  const timer = setInterval(() => {
    sweepExpiredNonces(pool, new Date()).catch((err: unknown) => {
      console.error("nonce sweep failed:", err);
    });
  }, intervalMs);
  // Do not keep the process alive just for the sweeper.
  timer.unref();
  return () => clearInterval(timer);
}

export async function startServer(options: StartServerOptions): Promise<RunningServer> {
  const push = createPushHub({ pool: options.pool });
  const app = createApp({
    pool: options.pool,
    inviteCode: options.inviteCode,
    onMessageStored: push.notify,
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
