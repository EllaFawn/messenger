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

/** Shorter codes are too easy to guess; registration has no rate limiting in M1. */
export const MIN_INVITE_CODE_LENGTH = 20;

export interface ServerConfig extends Config {
  /** M1: the single static invite code required to register. */
  inviteCode: string;
  host: string;
  port: number;
}

/** Settings needed to run the HTTP server. Throws with a clear message if any is missing or invalid. */
export function loadServerConfig(env: NodeJS.ProcessEnv = process.env): ServerConfig {
  const inviteCode = env.INVITE_CODE ?? "";
  if (inviteCode.length < MIN_INVITE_CODE_LENGTH) {
    // Never include the value itself: this message ends up in logs.
    throw new Error(
      `INVITE_CODE must be set to at least ${MIN_INVITE_CODE_LENGTH} characters. Generate one with: openssl rand -base64 24`,
    );
  }

  const rawPort = env.PORT ?? "3000";
  const port = Number(rawPort);
  if (!/^\d+$/.test(rawPort) || port < 1 || port > 65535) {
    throw new Error("PORT must be a whole number between 1 and 65535");
  }

  return {
    ...loadConfig(env),
    inviteCode,
    host: env.HOST || "127.0.0.1",
    port,
  };
}
