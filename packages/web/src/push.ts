import * as crypto from "@messager/crypto";
import { signRequest } from "@messager/protocol";
import type { StoredIdentity } from "./identity.js";

const INITIAL_RETRY_MS = 1000;
const MAX_RETRY_MS = 30_000;
const EMPTY_BODY = new Uint8Array(0);

/** The parts of a browser WebSocket this module uses; lets tests supply a fake. */
export interface PushSocket {
  onopen: (() => void) | null;
  onmessage: ((event: { data: unknown }) => void) | null;
  onclose: (() => void) | null;
  onerror: (() => void) | null;
  close(): void;
}

export interface PushOptions {
  me: StoredIdentity;
  /** The server has something new: fetch the inbox. */
  onNewMessage: () => void;
  /** The connection (re)opened: fetch the inbox once, in case something arrived while it was down. */
  onConnected?: () => void;
  /** e.g. "wss://host/api". Defaults to this page's own origin. */
  baseUrl?: string;
  createSocket?: (url: string) => PushSocket;
  now?: () => number;
}

/** ws:// or wss:// on this page's own origin, through the same /api prefix as every other request. */
function defaultBaseUrl(): string {
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${location.host}/api`;
}

/** Wraps the browser's WebSocket in the small interface above. */
function browserSocket(url: string): PushSocket {
  const ws = new WebSocket(url);
  const wrapper: PushSocket = {
    onopen: null,
    onmessage: null,
    onclose: null,
    onerror: null,
    close: () => ws.close(),
  };
  ws.addEventListener("open", () => wrapper.onopen?.());
  ws.addEventListener("message", (event) => wrapper.onmessage?.({ data: event.data }));
  ws.addEventListener("close", () => wrapper.onclose?.());
  ws.addEventListener("error", () => wrapper.onerror?.());
  return wrapper;
}

/**
 * A browser cannot set headers on a WebSocket, so the same four signed
 * values used for REST requests go in the query string. The signature covers
 * GET /ws with an empty body, and the nonce makes the URL single-use.
 */
export function buildPushUrl(me: StoredIdentity, baseUrl: string, timestamp: number): string {
  const nonce = crypto.toBase64(crypto.randomBytes(16));
  const signature = signRequest(
    { method: "GET", path: "/ws", rawBody: EMPTY_BODY, timestamp, nonce },
    me.identityPrivateKey,
  );
  const params = new URLSearchParams({
    user: me.userId,
    ts: String(timestamp),
    nonce,
    sig: crypto.toBase64(signature),
  });
  return `${baseUrl}/ws?${params.toString()}`;
}

function isNewMessageEvent(data: unknown): boolean {
  if (typeof data !== "string") return false;
  try {
    const parsed: unknown = JSON.parse(data);
    return typeof parsed === "object" && parsed !== null && (parsed as { type?: unknown }).type === "new_message";
  } catch {
    return false;
  }
}

/**
 * Keeps a push connection open, reconnecting with increasing delays when it
 * drops. The events carry no content - they only say "check your inbox" -
 * so nothing received here is ever trusted or displayed.
 *
 * Returns a function that stops it for good.
 */
export function connectPush(options: PushOptions): () => void {
  const baseUrl = options.baseUrl ?? defaultBaseUrl();
  const createSocket = options.createSocket ?? browserSocket;
  const now = options.now ?? Date.now;

  let stopped = false;
  let socket: PushSocket | null = null;
  let retryTimer: ReturnType<typeof setTimeout> | null = null;
  let retryDelay = INITIAL_RETRY_MS;

  function scheduleReconnect(): void {
    if (stopped || retryTimer !== null) return;
    const delay = retryDelay;
    retryDelay = Math.min(retryDelay * 2, MAX_RETRY_MS);
    retryTimer = setTimeout(() => {
      retryTimer = null;
      open();
    }, delay);
  }

  function open(): void {
    if (stopped) return;
    let current: PushSocket;
    try {
      // Signed afresh for every attempt: each URL works once and only for a minute.
      current = createSocket(buildPushUrl(options.me, baseUrl, now()));
    } catch {
      scheduleReconnect();
      return;
    }
    socket = current;

    current.onopen = () => {
      if (stopped || socket !== current) return;
      retryDelay = INITIAL_RETRY_MS;
      options.onConnected?.();
    };
    current.onmessage = (event) => {
      if (stopped || socket !== current) return;
      if (isNewMessageEvent(event.data)) options.onNewMessage();
    };
    const onGone = () => {
      if (socket !== current) return;
      socket = null;
      // After an error the socket may still be half open; make sure it is gone.
      current.close();
      scheduleReconnect();
    };
    current.onclose = onGone;
    current.onerror = onGone;
  }

  open();

  return () => {
    stopped = true;
    if (retryTimer !== null) {
      clearTimeout(retryTimer);
      retryTimer = null;
    }
    socket?.close();
    socket = null;
  };
}
