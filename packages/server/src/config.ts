import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/** Where `npm run build -w @messager/web` puts the built web app. */
export const DEFAULT_WEB_DIR = fileURLToPath(new URL("../../web/dist", import.meta.url));

/** Matches the Postgres service in docker-compose.yml. Local development only. */
export const DEFAULT_DATABASE_URL = "postgres://messager:messager@127.0.0.1:5432/messager";

export interface Config {
  databaseUrl: string;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  return {
    databaseUrl: env.DATABASE_URL || DEFAULT_DATABASE_URL,
  };
}

export interface ServerConfig extends Config {
  host: string;
  port: number;
  /** Folder of the built web app to serve, or null to serve the API only. */
  webDir: string | null;
}

/** Settings needed to run the HTTP server. Throws with a clear message if any is missing or invalid. */
export function loadServerConfig(
  env: NodeJS.ProcessEnv = process.env,
  builtWebDir: string = DEFAULT_WEB_DIR,
): ServerConfig {
  const rawPort = env.PORT ?? "3000";
  const port = Number(rawPort);
  if (!/^\d+$/.test(rawPort) || port < 1 || port > 65535) {
    throw new Error("PORT must be a whole number between 1 and 65535");
  }

  const serveWeb = env.SERVE_WEB ?? "";
  if (!["", "0", "false", "1", "true"].includes(serveWeb)) {
    throw new Error("SERVE_WEB must be 1 or 0");
  }
  let webDir: string | null = null;
  if (serveWeb === "1" || serveWeb === "true") {
    if (!existsSync(join(builtWebDir, "index.html"))) {
      throw new Error(
        `SERVE_WEB is on but the web app has not been built (${builtWebDir}). Run: npm run build -w @messager/web`,
      );
    }
    webDir = builtWebDir;
  }

  return {
    ...loadConfig(env),
    webDir,
    host: env.HOST || "127.0.0.1",
    port,
  };
}
