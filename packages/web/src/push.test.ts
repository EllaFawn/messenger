import * as crypto from "@messager/crypto";
import { verifyRequest } from "@messager/protocol";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createIdentity, type StoredIdentity } from "./identity.js";
import { buildPushUrl, connectPush, type PushSocket } from "./push.js";

const NOW = 1_800_000_000_000;

class FakeSocket implements PushSocket {
  static created: FakeSocket[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  closed = false;
  constructor(readonly url: string) {
    FakeSocket.created.push(this);
  }
  close(): void {
    this.closed = true;
  }
}

let me: StoredIdentity;
let newMessages: number;
let connects: number;
let stop: () => void;

beforeAll(async () => {
  await crypto.ready;
});

beforeEach(() => {
  vi.useFakeTimers();
  FakeSocket.created = [];
  me = createIdentity(NOW);
  newMessages = 0;
  connects = 0;
  stop = connectPush({
    me,
    baseUrl: "ws://example.test/api",
    createSocket: (url) => new FakeSocket(url),
    now: () => NOW,
    onNewMessage: () => (newMessages += 1),
    onConnected: () => (connects += 1),
  });
});

afterEach(() => {
  stop();
  vi.useRealTimers();
});

const latest = () => FakeSocket.created.at(-1)!;

describe("buildPushUrl", () => {
  it("carries a signature the server will accept for GET /ws", () => {
    const url = new URL(buildPushUrl(me, "ws://example.test/api", NOW));
    expect(url.pathname).toBe("/api/ws");
    expect(url.searchParams.get("user")).toBe(me.userId);
    expect(url.searchParams.get("ts")).toBe(String(NOW));
    const nonce = url.searchParams.get("nonce")!;
    expect(nonce).toMatch(/^[A-Za-z0-9+/]{22}==$/);
    expect(
      verifyRequest(
        { method: "GET", path: "/ws", rawBody: new Uint8Array(0), timestamp: NOW, nonce },
        me.identityPublicKey,
        crypto.fromBase64(url.searchParams.get("sig")!),
      ),
    ).toBe(true);
  });

  it("uses a fresh nonce every time", () => {
    const a = new URL(buildPushUrl(me, "ws://example.test/api", NOW)).searchParams.get("nonce");
    const b = new URL(buildPushUrl(me, "ws://example.test/api", NOW)).searchParams.get("nonce");
    expect(a).not.toBe(b);
  });

  it("never includes private key material", () => {
    const url = decodeURIComponent(buildPushUrl(me, "ws://example.test/api", NOW));
    expect(url).not.toContain(crypto.toBase64(me.identityPrivateKey));
    expect(url).not.toContain(crypto.toBase64(me.identityPrivateKey.slice(0, 32)));
    expect(url).not.toContain(crypto.toBase64(me.exchangePrivateKey));
  });
});

describe("connectPush", () => {
  it("connects straight away and reports when the connection opens", () => {
    expect(FakeSocket.created).toHaveLength(1);
    expect(connects).toBe(0);
    latest().onopen!();
    expect(connects).toBe(1);
  });

  it("calls back for a new-message event", () => {
    latest().onopen!();
    latest().onmessage!({ data: '{"type":"new_message"}' });
    expect(newMessages).toBe(1);
  });

  it.each([
    ["an unknown event type", '{"type":"something_else"}'],
    ["text that is not JSON", "new_message"],
    ["JSON that is not an object", '"new_message"'],
    ["null", "null"],
    ["binary data", new Uint8Array([1, 2, 3])],
  ])("ignores %s", (_name, data) => {
    latest().onopen!();
    latest().onmessage!({ data });
    expect(newMessages).toBe(0);
  });

  it("reconnects after the connection drops, with a newly signed URL", () => {
    const first = latest();
    first.onopen!();
    first.onclose!();
    expect(FakeSocket.created).toHaveLength(1);
    vi.advanceTimersByTime(1000);
    expect(FakeSocket.created).toHaveLength(2);
    expect(latest().url).not.toBe(first.url);
  });

  it("waits longer after each failed attempt, up to a limit", () => {
    const delays: number[] = [];
    for (let attempt = 0; attempt < 8; attempt++) {
      const before = FakeSocket.created.length;
      latest().onclose!();
      let waited = 0;
      while (FakeSocket.created.length === before) {
        vi.advanceTimersByTime(500);
        waited += 500;
      }
      delays.push(waited);
    }
    expect(delays).toEqual([1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000]);
  });

  it("goes back to a short wait once a connection succeeds", () => {
    latest().onclose!();
    vi.advanceTimersByTime(1000);
    latest().onclose!();
    vi.advanceTimersByTime(2000);
    latest().onopen!();
    latest().onclose!();
    vi.advanceTimersByTime(1000);
    expect(FakeSocket.created).toHaveLength(4);
  });

  it("reports each reconnection, so missed messages can be fetched", () => {
    latest().onopen!();
    latest().onclose!();
    vi.advanceTimersByTime(1000);
    latest().onopen!();
    expect(connects).toBe(2);
  });

  it("schedules only one reconnect when error and close both fire", () => {
    latest().onerror!();
    latest().onclose!();
    vi.advanceTimersByTime(1000);
    expect(FakeSocket.created).toHaveLength(2);
  });

  it("stops for good: closes the socket, cancels reconnects and ignores late events", () => {
    const socket = latest();
    socket.onopen!();
    stop();
    expect(socket.closed).toBe(true);
    socket.onclose?.();
    socket.onmessage?.({ data: '{"type":"new_message"}' });
    vi.advanceTimersByTime(60_000);
    expect(FakeSocket.created).toHaveLength(1);
    expect(newMessages).toBe(0);
  });

  it("stops a pending reconnect", () => {
    latest().onclose!();
    stop();
    vi.advanceTimersByTime(60_000);
    expect(FakeSocket.created).toHaveLength(1);
  });

  it("keeps trying if creating the socket throws", () => {
    stop();
    FakeSocket.created = [];
    let calls = 0;
    stop = connectPush({
      me,
      baseUrl: "ws://example.test/api",
      createSocket: (url) => {
        calls += 1;
        if (calls === 1) throw new Error("blocked");
        return new FakeSocket(url);
      },
      now: () => NOW,
      onNewMessage: () => undefined,
    });
    expect(FakeSocket.created).toHaveLength(0);
    vi.advanceTimersByTime(1000);
    expect(FakeSocket.created).toHaveLength(1);
  });
});
