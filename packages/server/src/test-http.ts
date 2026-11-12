import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Express } from "express";

export interface TestServer {
  /** Base URL, e.g. http://127.0.0.1:54321 */
  url: string;
  close(): Promise<void>;
}

/** Serves the app on a random local port so tests make real HTTP requests. */
export async function startTestServer(app: Express): Promise<TestServer> {
  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
        server.closeAllConnections();
      }),
  };
}
