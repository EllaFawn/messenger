import type { IncomingMessage } from "node:http";

const EMPTY = Buffer.alloc(0);
const rawBodies = new WeakMap<object, Buffer>();

/** Called by the JSON body parser with the bytes exactly as received. */
export function rememberRawBody(req: IncomingMessage, body: Buffer): void {
  rawBodies.set(req, body);
}

/**
 * The exact bytes of the request body as received. Request signatures cover
 * a hash of these bytes, so they must not be re-serialized from parsed JSON.
 */
export function getRawBody(req: IncomingMessage): Buffer {
  return rawBodies.get(req) ?? EMPTY;
}
