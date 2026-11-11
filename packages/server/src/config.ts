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
