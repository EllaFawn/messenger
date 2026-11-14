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

Workspace packages export their compiled `dist/` output (built by
`npm run typecheck`); tests resolve them to source, so no build is needed to
run tests.

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

## Running the server

```
cp .env.example .env                    # then set INVITE_CODE (openssl rand -base64 24)
npm run migrate -w @messager/server
npm run start -w @messager/server       # http://127.0.0.1:3000
```

The server refuses to start without an `INVITE_CODE` of at least 20
characters. `.env` is git-ignored; never commit it.

Routes so far:

| Route | Auth | Purpose |
|---|---|---|
| `GET /health` | none | Liveness check |
| `POST /register` | signed by the key being registered + invite code | Create an account |
| `GET /users/:userID/pubkeys` | signed | Fetch a user's public keys |
| `POST /messages` | signed | Send an encrypted message; the sender is taken from the signature |
| `GET /messages/inbox` | signed | The caller's unacknowledged messages, oldest first, up to 100 |
| `POST /messages/:id/ack` | signed, recipient only | Confirm receipt; the server deletes the message |
| `GET /ws` (WebSocket) | signed, via query parameters | Tells you at once when a message arrives; carries no content |

Signed requests carry `X-User-ID`, `X-Timestamp`, `X-Nonce` and
`X-Signature`; see design section 4.

## Running the web app

With the server running in one terminal, start the web app in another:

```
npm run dev -w @messager/web            # http://127.0.0.1:5173
```

The dev server only listens on your own machine. Requests to `/api/...` are
forwarded to the server on port 3000, so the browser talks to one address
and the server needs no cross-origin (CORS) settings.

On first visit the app asks for the invite code (the `INVITE_CODE` value in
`.env`), creates your keys in the browser, registers them and shows your
userID. The private keys are stored only in that browser's IndexedDB;
clearing the site's data deletes them for good.

Add a contact by pasting their userID; each contact shows a safety number
to compare out of band and a conversation. New messages arrive at once over a
WebSocket; a slower periodic check covers the case where that connection is down. To try it alone, use a normal window and a
private window as two separate users.

`npm run build -w @messager/web` produces the production bundle in
`packages/web/dist`.
