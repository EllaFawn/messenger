# Messager

E2E encrypted 1:1 messaging, hobby prototype. Self-hosted, invite-only.

> **Prototype. No security review performed. No forward secrecy — a single
> key compromise exposes all past messages. Not for sensitive real-world
> use.**

See [`docs/superpowers/specs/2026-08-05-messager-mvp-design.md`](docs/superpowers/specs/2026-08-05-messager-mvp-design.md)
for the full design and [`SPEC.md`](SPEC.md) for the original scope notes.

## Layout

npm workspaces monorepo:

- `packages/crypto` — keygen, ECDH, HKDF, AEAD, hashing. Headless, isomorphic.
- `packages/protocol` — wire types, userID derivation, canonical request
  string, envelope encode/decode. Shared by client and server.
- `packages/server` — Express + Postgres relay.
- `packages/web` — React + Vite client.

## Dev setup

Requires Node and Docker Desktop.

```
npm install
docker compose up -d                    # start Postgres (local only, 127.0.0.1:5432)
npm run migrate -w @messager/server     # create or update the database tables
npm test
npm run typecheck
```

`npm test` needs Postgres running: the server tests create a throwaway
database for each test file and drop it afterwards, so the dev database is
never touched.

The database address comes from `DATABASE_URL`; without it, the server uses
the docker-compose dev database. See [`.env.example`](.env.example).

## Database migrations

Schema changes live in `packages/server/migrations` as numbered `.sql` files
(`001_initial.sql`, `002_...sql`) and are applied in filename order by
`npm run migrate -w @messager/server`.

To change the schema, add a new numbered file. Never edit a file that has
already been applied: the runner records a checksum for each one and refuses
to run if it has changed.
