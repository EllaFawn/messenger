import type { IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
import { WebSocketServer, type WebSocket } from "ws";
import {
  parseSignedValues,
  recordNonce,
  verifySignatureOver,
  type AuthDeps,
} from "./auth/signed-request.js";

/** The only path that accepts a WebSocket. */
export const PUSH_PATH = "/ws";
export const MAX_PUSH_CONNECTIONS_PER_USER = 5;
/** Clients never send anything, so there is no reason to accept more than a tiny frame. */
const MAX_INCOMING_BYTES = 256;
const HEARTBEAT_INTERVAL_MS = 30_000;
/** The whole event. It carries no sender, id or content: the client just re-checks its inbox. */
const NEW_MESSAGE_EVENT = JSON.stringify({ type: "new_message" });
const EMPTY_BODY = new Uint8Array(0);

export interface PushHub {
  /** Nudges every open connection of this user. Does nothing if they have none. */
  notify(userId: string): void;
  /** Handler for the HTTP server's "upgrade" event. */
  handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void;
  connectionCount(): number;
  /** Closes every connection and stops the heartbeat. */
  close(): void;
}

function refuse(socket: Duplex, status: 401 | 404 | 429): void {
  const reason = { 401: "Unauthorized", 404: "Not Found", 429: "Too Many Requests" }[status];
  socket.end(`HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
  socket.destroy();
}

/**
 * Real-time "you have a new message" nudges. The inbox stays the source of
 * truth: a missed nudge only delays delivery until the client next checks.
 *
 * A connection is authenticated before it is accepted, with the same signed
 * scheme as the REST API (method GET, path /ws, empty body). Browsers cannot
 * set headers on a WebSocket, so the four values travel as query parameters;
 * the nonce makes each connection URL single-use.
 */
export function createPushHub(deps: AuthDeps): PushHub {
  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_INCOMING_BYTES });
  const connections = new Map<string, Set<WebSocket>>();
  const alive = new WeakSet<WebSocket>();

  function remove(userId: string, ws: WebSocket): void {
    const set = connections.get(userId);
    if (set === undefined) return;
    set.delete(ws);
    if (set.size === 0) connections.delete(userId);
  }

  function accept(userId: string, ws: WebSocket): void {
    let set = connections.get(userId);
    if (set === undefined) {
      set = new Set();
      connections.set(userId, set);
    }
    set.add(ws);
    alive.add(ws);

    ws.on("pong", () => alive.add(ws));
    // Clients only listen. Anything they send is a protocol violation.
    ws.on("message", () => ws.close(1008, "unexpected message"));
    ws.on("close", () => remove(userId, ws));
    ws.on("error", () => ws.terminate());
  }

  async function authenticate(req: IncomingMessage): Promise<string | null> {
    const url = new URL(req.url ?? "", "http://localhost");
    const headers = parseSignedValues({
      userId: url.searchParams.get("user"),
      timestamp: url.searchParams.get("ts"),
      nonce: url.searchParams.get("nonce"),
      signature: url.searchParams.get("sig"),
    });
    if (headers === null) return null;

    const user = await deps.pool.query<{ identity_pubkey: Buffer }>(
      "SELECT identity_pubkey FROM users WHERE user_id = $1",
      [headers.userId],
    );
    const row = user.rows[0];
    if (row === undefined) return null;

    // Signature first, then the nonce - the same order as REST requests.
    const target = { method: "GET", path: PUSH_PATH, rawBody: EMPTY_BODY };
    if (!(await verifySignatureOver(target, headers, new Uint8Array(row.identity_pubkey), deps))) return null;
    if (!(await recordNonce(headers, deps))) return null;
    return headers.userId;
  }

  function handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void {
    socket.on("error", () => socket.destroy());

    let pathname: string;
    try {
      pathname = new URL(req.url ?? "", "http://localhost").pathname;
    } catch {
      refuse(socket, 404);
      return;
    }
    if (req.method !== "GET" || pathname !== PUSH_PATH) {
      refuse(socket, 404);
      return;
    }

    authenticate(req).then(
      (userId) => {
        if (userId === null) {
          refuse(socket, 401);
          return;
        }
        if ((connections.get(userId)?.size ?? 0) >= MAX_PUSH_CONNECTIONS_PER_USER) {
          refuse(socket, 429);
          return;
        }
        wss.handleUpgrade(req, socket, head, (ws) => accept(userId, ws));
      },
      (err: unknown) => {
        console.error("push upgrade failed:", err);
        socket.destroy();
      },
    );
  }

  // Drops connections whose other end has silently gone away.
  const heartbeat = setInterval(() => {
    for (const set of connections.values()) {
      for (const ws of set) {
        if (!alive.has(ws)) {
          ws.terminate();
          continue;
        }
        alive.delete(ws);
        ws.ping();
      }
    }
  }, HEARTBEAT_INTERVAL_MS);
  heartbeat.unref();

  return {
    notify(userId) {
      for (const ws of connections.get(userId) ?? []) {
        if (ws.readyState === ws.OPEN) {
          ws.send(NEW_MESSAGE_EVENT);
        }
      }
    },
    handleUpgrade,
    connectionCount() {
      let total = 0;
      for (const set of connections.values()) total += set.size;
      return total;
    },
    close() {
      clearInterval(heartbeat);
      for (const set of connections.values()) {
        for (const ws of set) {
          ws.close(1001, "server shutting down");
          // Do not wait indefinitely for a client that never answers the close.
          setTimeout(() => ws.terminate(), 1000).unref();
        }
      }
      wss.close();
    },
  };
}
