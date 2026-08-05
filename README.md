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

```
npm install
npm test
docker compose up -d   # Postgres, needed once packages/server lands
```
