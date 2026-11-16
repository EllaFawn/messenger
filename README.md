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
- `e2e` — tests that run the real web-client code against the real server
  and database. The only place that imports both.

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
npm run migrate -w @messager/server
npm run start -w @messager/server       # http://127.0.0.1:3000
```

Settings are optional; see `.env.example`. `.env` is git-ignored; never
commit it.

## Invites and accounts

Nobody can register without an invite, and only the operator can create
one. These commands talk to the database directly and have no network
route, so they can only be run by someone with access to the server.

```
npm run invite -w @messager/server -- create --note "for Sam"   # optional: --expires 12h (default 7d)
npm run invite -w @messager/server -- list
npm run invite -w @messager/server -- revoke <invite id>
npm run user   -w @messager/server -- list
npm run user   -w @messager/server -- remove <userID> --yes
```

- `create` prints a code **once**. It registers one account and then stops
  working. Only its hash is stored, so it cannot be shown again.
- `list` shows each invite's id, note and whether it is unused, used (and
  by whom) or expired. It never shows a code.
- `revoke` cancels an unused invite.
- `user remove` deletes an account and its undelivered messages. The
  person's invite stays used, so they cannot come back with it.

Routes so far:

| Route | Auth | Purpose |
|---|---|---|
| `GET /health` | none | Liveness check |
| `POST /register` | signed by the key being registered + a single-use invite | Create an account |
| `GET /users/:userID/pubkeys` | signed | Fetch a user's public keys |
| `POST /messages` | signed | Send an encrypted message; the sender is taken from the signature |
| `GET /messages/inbox` | signed | The caller's unacknowledged messages, oldest first, 100 per page (`?after=<cursor>` for the next) |
| `POST /messages/:id/ack` | signed, recipient only | Confirm receipt; the server deletes the message |
| `GET /ws` (WebSocket) | signed, via query parameters | Tells you at once when a message arrives; carries no content |

Signed requests carry `X-User-ID`, `X-Timestamp`, `X-Nonce` and
`X-Signature`; see design section 4.

## Limits

A running server always applies these. Refusals are `429` with a
`Retry-After` header.

| What | Counted per | Limit |
|---|---|---|
| Registrations | client address | 5 per hour |
| Requests that fail authentication | client address | 30 per minute, then that address is refused entirely |
| Push connection attempts | client address | 20 per minute |
| Messages sent | sender | 60 per minute |
| Public-key lookups | caller | 30 per minute |
| Other signed requests | caller | 300 per minute |

- A recipient holds at most 500 undelivered messages from one sender and
  5,000 in total; undelivered messages are deleted after 30 days.
- Push connections are capped at 5 per user, 20 per client address and
  1,000 in total.
- Limits live in the server's memory, which suits a single server process.
- Behind a reverse proxy, set `TRUST_PROXY` (see `.env.example`), or every
  visitor will share the proxy's address and its limits.

## Running the web app

With the server running in one terminal, start the web app in another:

```
npm run dev -w @messager/web            # http://127.0.0.1:5173
```

The dev server only listens on your own machine. Requests to `/api/...` are
forwarded to the server on port 3000, so the browser talks to one address
and the server needs no cross-origin (CORS) settings.

On first visit the app asks for an invite code (see "Invites and accounts"
above), creates your keys in the browser, registers them and shows your
userID. The private keys are stored only in that browser's IndexedDB;
clearing the site's data deletes them for good.

Add a contact by pasting their userID; each contact shows a safety number
to compare out of band and a conversation. New messages arrive at once over a
WebSocket; a slower periodic check covers the case where that connection is down. To try it alone, use a normal window and a
private window as two separate users.

## Running it as one server

The dev server above is for working on the code. To run the app the way it
would be deployed - one server, with strict security headers - build the
web app and let the server serve it:

```
npm run build -w @messager/web
SERVE_WEB=1 npm run start -w @messager/server     # http://127.0.0.1:3000
```

(or set `SERVE_WEB=1` in `.env`). Every response carries a Content Security
Policy that only allows scripts from the server itself: no inline script, no
`eval`, no third-party origins, no framing. The dev server cannot apply this
policy, because its live-reload relies on inline scripts.

This is still plain HTTP on your own machine. HTTPS, and the
`Strict-Transport-Security` header that goes with it, belong to the
deployment work in M2.
