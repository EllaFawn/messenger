# Messager — M2 Design

Status: approved for implementation planning (2026-11-16). Section 11 records the decisions taken at review.

Follows `2026-08-05-messager-mvp-design.md` (M1), which is built and merged. M1's rule still stands: M2 must be complete before the app has any user beyond the original two.

## 1. Goal and scope

Take the working M1 prototype to something a handful of invited people can use on a real server.

Decisions already made (2026-11-16):

- **Forward secrecy** comes from an existing audited ratchet library, not one we write.
- **Deployment** is a VPS, planned within about two weeks. Local development and testing must keep working unchanged.
- **Audience** is a few people, each invited individually by the operator.
- **Backup** is a passphrase-encrypted file. One device per account.

In scope, as five pieces that are built and merged separately:

| # | Piece | Size |
|---|---|---|
| P1 | Per-person invites | small |
| P2 | Rate limiting and abuse limits | small–medium |
| P3 | Forward secrecy (ratchet) | large |
| P4 | Identity backup and restore | medium |
| P5 | Deployment and server hardening | medium |

Out of scope for M2: several devices per account, group chats, hiding metadata from the server, native mobile apps, attachments, and protecting users from a server that serves altered client code (section 9).

The visual design pass comes after P1–P4, once every screen exists.

## 2. Where M1 leaves us

What exists: registration with a shared invite code, signed requests with replay protection, exchange keys signed by the identity key, contacts with pinned keys and safety numbers, encrypted send/inbox/ack, per-contact counters, WebSocket push, a strict Content Security Policy, and end-to-end tests of the real client against the real server.

What M2 must fix:

1. **No forward secrecy.** One static shared secret per pair. Anyone who obtains a private exchange key can read every past and future message of that user.
2. **One shared invite code.** It can be passed on, used any number of times, and not revoked per person.
3. **No rate limiting.** A registered user can flood the server or another user's inbox. The inbox returns 100 messages at a time, so 100 waiting messages from non-contacts hold up everything behind them.
4. **No recovery.** Clearing browser data destroys the account.
5. **Not deployable.** No HTTPS, no hardening, default database password, no backups.

## 3. P1 — Per-person invites

Status: built (`feature/per-person-invites`). As built, `revoke` takes the invite id shown by `list`, `user remove` requires `--yes`, and `user list` was added.

The operator creates one single-use invite per person from a command on the server. Nobody else can create invites.

**Data**

```sql
invites (
  code_hash   bytea PRIMARY KEY,        -- SHA-256 of the code; the code itself is never stored
  note        text NOT NULL DEFAULT '', -- operator's label, e.g. "for Sam"
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz,
  used_by     text REFERENCES users(user_id) ON DELETE SET NULL
);
```

**Operator commands** (run on the server, no network route):

```
npm run invite -w @messager/server -- create --note "for Sam" --expires 7d
npm run invite -w @messager/server -- list
npm run invite -w @messager/server -- revoke <first characters of the code hash>
npm run user   -w @messager/server -- remove <userID>
```

- `create` prints the code once: 32 random bytes, base64url. Default expiry 7 days.
- `list` shows note, state (unused / used by whom / expired) and dates. Never the code.
- `user remove` deletes an account and its undelivered messages. With single-use invites this is how one person's access is ended.

**Registration** keeps the M1 order (body, userID derivation, signatures, invite, nonce, insert) with one change: the invite is claimed and the user inserted in a single transaction.

```sql
UPDATE invites SET used_at = now(), used_by = $user
WHERE code_hash = $hash AND used_at IS NULL AND expires_at > now();
```

If no row is updated the transaction rolls back. Unknown, used and expired codes all return the same `403 invalid_invite`.

**Removed:** the `INVITE_CODE` setting. The server starts without it.

**Recovery after data loss on the server** (`registerAgain`) needs a fresh invite. That is acceptable: with backups (P5) it should never happen, and it must not become a way around single-use.

## 4. P2 — Rate limiting and abuse limits

Status: built (`feature/rate-limits`). As built, key claims (P3) are not yet limited because they do not exist yet; the inbox cursor is the creation time in microseconds plus the message id; and an address that exceeds the failed-authentication limit is refused on every route until it recovers.

One process on one server, so limits are kept in memory. No new dependency.

**Request limits** (token bucket; `429 rate_limited` with `Retry-After`):

| What | Keyed by | Starting limit |
|---|---|---|
| `POST /register` | client IP | 5 per hour |
| Any request failing authentication | client IP | 30 per minute |
| WebSocket upgrades | client IP | 20 per minute |
| `POST /messages` | sender | 60 per minute |
| Key lookups and key claims (P3) | caller | 30 per minute |
| Everything else signed | caller | 300 per minute |

Behind the reverse proxy the client IP comes from `X-Forwarded-For`; a `TRUST_PROXY` setting says how many proxies to trust. Off by default, so a direct client cannot spoof it.

**Queue limits**

- At most 500 undelivered messages per sender→recipient pair, and 5,000 per recipient. Beyond that `POST /messages` returns `429 recipient_queue_full`.
- Undelivered messages are deleted after 30 days by the existing sweeper.

**Inbox paging.** `GET /messages/inbox?after=<cursor>` returns the next page. The client pages through the whole inbox on each check, so messages it deliberately leaves on the server (unknown sender, unresolved key change) no longer block the ones behind them.

**Connection limits.** The per-user WebSocket cap exists already; add a global cap and a per-IP cap.

## 5. P3 — Forward secrecy

### 5.1 What it must provide

- **Forward secrecy:** obtaining today's keys does not reveal earlier messages.
- **Recovery after compromise:** once the two sides exchange a few messages after a compromise, the attacker is locked out again.
- **Offline start:** the first message can be sent while the recipient is offline.

All three are what the Double Ratchet with one-time prekeys provides.

### 5.2 Library choice

Checked against the npm registry on 2026-11-16:

| Option | Finding | Verdict |
|---|---|---|
| **vodozemac** (Rust, Matrix's current implementation of Olm) | No standalone npm package. Would be compiled to WebAssembly through a small wrapper we own. | **Recommended**, subject to the spike below |
| `@matrix-org/olm` 3.2.15 (libolm, C compiled to WebAssembly) | Published, Apache-2.0, 650 KB, runs in browsers. The older implementation that vodozemac replaced. | Fallback |
| `@matrix-org/matrix-sdk-crypto-wasm` 19.0.1 | Contains vodozemac, but wrapped in Matrix's whole device and room model. 9 MB. | Rejected: wrong shape |
| `@signalapp/libsignal-client` | Node-native, no browser build; AGPL-3.0. | Rejected |
| `2key-ratchet`, `@privacyresearch/libsignal-protocol-typescript` | Last published 2022 and 2025; no audit found. | Rejected |
| Writing our own | — | Rejected (decision above) |

To confirm during the spike, from primary sources, before the choice is final: the scope and date of vodozemac's independent audit, the maintenance status of libolm, and whether vodozemac's WebAssembly build has known caveats.

The wrapper would be a new package, `packages/ratchet`, exposing only what we use: create account, export public keys, generate and mark one-time keys, create outbound and inbound sessions, encrypt, decrypt, and serialise state. All cryptographic logic stays inside the library.

### 5.3 Spike first (time-boxed, before any design is final)

A throwaway branch that answers:

1. Does the chosen library build and run in a browser under our Content Security Policy? (`'wasm-unsafe-eval'` is already allowed.)
2. Can account and session state be saved to IndexedDB and restored?
3. What does it add to the bundle size and to CI (a Rust toolchain, if vodozemac)?
4. Can a second, independent run of the same test decrypt nothing from the first? (A sanity check that state is real.)

If vodozemac fails any of 1–3, fall back to `@matrix-org/olm` and repeat. The rest of this section is written to fit either.

### 5.4 Keys

- The **identity key** (Ed25519) is unchanged and stays the root: `userID = base64url(SHA-256(identity_pubkey))`, and it signs API requests.
- The static X25519 **exchange key is retired**. In its place each account has a **ratchet account** created by the library, with its own long-term Curve25519 key and a supply of one-time keys.
- The identity key signs the ratchet account's long-term key, replacing today's `exchange_sig`, and signs each batch of one-time keys. A client holding the right userID can therefore verify every key the server hands it, exactly as in M1.

Signed statements stay domain-separated (`messager/v2/ratchet-key\n…`, `messager/v2/one-time-key\n…`).

### 5.5 Server changes

```sql
ALTER TABLE users  -- replaces exchange_pubkey / exchange_sig
  ADD ratchet_pubkey bytea NOT NULL, ADD ratchet_sig bytea NOT NULL,
  ADD key_epoch integer NOT NULL DEFAULT 1;   -- see P4

one_time_keys (
  user_id   text NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  key_id    text NOT NULL,
  pubkey    bytea NOT NULL,
  sig       bytea NOT NULL,
  is_fallback boolean NOT NULL DEFAULT false,
  PRIMARY KEY (user_id, key_id)
);

ALTER TABLE messages
  ADD v smallint NOT NULL, ADD msg_type smallint NOT NULL,  -- prekey message or normal
  ALTER nonce DROP NOT NULL;   -- the ratchet carries its own
```

M1 expected no schema change here; the `nonce` column makes one necessary.

New routes, all signed:

```
POST /keys/one-time            upload a signed batch (max 100 held per user)
GET  /keys/count               how many of mine are left
POST /users/:userID/keys/claim → ratchet key + signature + one one-time key
```

`claim` deletes the one-time key it returns, atomically. When none are left it returns the user's signed **fallback key**, which is reused until replaced. Claims are rate-limited per caller→target pair so one user cannot drain another's supply.

### 5.6 Client changes

- **Sending the first message:** claim a key for the contact, verify both signatures, create an outbound session, encrypt. The envelope becomes `{ "v": 2, "to", "type", "ciphertext" }`.
- **Receiving a first message:** it creates the inbound session.
- **Session state** lives in IndexedDB, one record per contact.
- **Topping up:** on start and after each inbound session, upload more one-time keys if the server's count is low.

**The rule that must not be broken:** decrypting advances the ratchet, so a message can only ever be decrypted once. The decrypted text and the updated session state are written in **one IndexedDB transaction**, and only then is the message acknowledged. A crash at any point either leaves the message on the server and the old state on disk, or both saved.

Consequences:

- The per-contact counters are removed. The ratchet rejects replays itself, and tolerates a bounded amount of reordering.
- A redelivered message that was already stored fails to decrypt and is acknowledged and dropped, as today.
- **Lost state.** If one side's session state is gone (restored from backup, P4), its next message starts a new session with a fresh claimed key. The other side accepts a new inbound session from a contact whose signed keys verify, and uses the newest session for sending.

**Pinning and safety numbers** carry over: the pinned key is now the ratchet account's long-term key, and the safety number covers the identity key and that key.

### 5.7 Migration

A clean break. There are no real users, and no way to convert a static-key account without its private key. The migration removes existing accounts and messages, as migration 002 did; v1 envelopes and the static-ECDH code are deleted, not kept alongside. Browsers keep their identity key and register again.

### 5.8 What stays true

Message history is still stored decrypted in the browser. Forward secrecy protects past traffic from someone who later obtains keys; it does not protect history from someone who obtains the device.

## 6. P4 — Identity backup and restore

**Export** produces one file, downloaded by the browser:

```json
{ "v": 1, "kdf": "argon2id", "ops": 3, "mem": 268435456,
  "salt": "<b64>", "nonce": "<b64>", "ciphertext": "<b64>" }
```

- Key: Argon2id over the passphrase (`crypto_pwhash`, already in our libsodium build; "moderate" settings, 256 MB).
- Encryption: XChaCha20-Poly1305, as elsewhere.
- Contents: the identity key pair, contacts with their pinned keys and names, and optionally the message history.
- **Not included: ratchet session state.** Restoring old ratchet state alongside a live copy would reuse keys, which breaks the security the ratchet exists to give.

Passphrase: minimum 12 characters, entered twice, with a plain warning that a forgotten passphrase cannot be recovered.

**Restore**, offered on the sign-up screen:

1. Decrypt the file and store the identity and contacts.
2. Create a **new** ratchet account and one-time keys.
3. Replace the keys on the server.

Step 3 needs a new route, `PUT /keys/ratchet`, and relaxes M1's rule that registered keys are never replaced. The new rule: the ratchet key can be replaced only by a request signed by the identity key, carrying a signature over the new key, and with `key_epoch` exactly one higher than the stored value. The server deletes the old one-time keys in the same transaction. The old device, if it still exists, stops working.

**What contacts see.** Their client notices the ratchet key changed. Because the new key is signed by the same identity key they already pinned, this is not the M1 "possible interception" case. Recommended: show a notice in the conversation ("Sam restored their account; the safety number has changed") and keep sending, rather than block. See section 11.

## 7. P5 — Deployment and hardening

**Shape:** one small VPS running Docker Compose with three containers.

```
internet ──443──> Caddy (HTTPS, automatic certificates)
                    └──> app (Node, serves web + API + WebSocket)   [internal network only]
                           └──> Postgres                             [internal network only]
```

- `docker-compose.prod.yml` and a `Dockerfile` in the repo. The existing `docker-compose.yml` stays as the development database.
- The same file runs on a laptop for a production-like test, with Caddy issuing a local certificate for `localhost`.
- Images pinned by digest. The app runs as a non-root user with a read-only filesystem.

**HTTPS:** Caddy obtains and renews certificates. It adds `Strict-Transport-Security`. The app's own security headers are unchanged. Requires a domain name.

**Server:**

- SSH by key only; no root login; no password login.
- Firewall: 22, 80, 443 only. Postgres is never published.
- Automatic security updates.
- Secrets in an env file readable only by the deploy user; a generated database password, never the development default.

**Data:**

- Nightly `pg_dump`, encrypted, copied off the server, kept 14 days. A restore is rehearsed once before launch.
- The database holds public keys, ciphertext awaiting delivery, invite hashes and metadata. It never holds message text or private keys.

**Logs:** no request bodies, and query strings stripped (the WebSocket URL carries a signature). Short retention.

**Releases:** tagged commits only. Deploy is pull, build, migrate, restart, check `/health`; rollback is the previous tag. Written up as `docs/deploy.md`.

**Dependencies:** `npm ci` from the lockfile; Dependabot for npm, Actions and base images.

**Changing this later.** Docker Compose is packaging, not architecture: the app is one Node process that needs a Postgres URL, and nothing in the code knows it runs in a container. Moving to a managed database, a different host, or a platform service later means changing settings and the deploy document, not the app. Two things are tied to running a single app process and would need work before running several behind a load balancer: the in-memory rate limits (P2) and the in-memory list of push connections. Both would move to a shared store such as Redis. Neither is needed at this scale.

## 8. Threat model after M2

Improved:

- Past messages are protected against later key compromise.
- An invite is single-use and tied to one person; an account can be removed.
- Flooding and inbox blocking are bounded.
- Losing a browser no longer loses the identity.
- Traffic is protected in transit by HTTPS as well as end to end.

Unchanged, and accepted:

1. **The server ships the client code.** Whoever controls the server can serve a page that leaks keys. Nothing in M2 addresses this; it is the main reason the project stays "for people who trust the operator".
2. **Device compromise yields history and keys.**
3. **Metadata is visible to the server:** who talks to whom, when, and message sizes.
4. **Cross-site scripting would be serious,** reduced by the Content Security Policy and text-only rendering, not eliminated.
5. **A backup file is only as strong as its passphrase.**

The README keeps its warning: prototype, no independent security review.

## 9. Testing

- Every piece extends the end-to-end tests in `e2e/`, which run the real client against the real server.
- P1: single use, expiry, revoke, concurrent claims of one code, removed user cannot sign requests.
- P2: each limit, `Retry-After`, the spoofed-IP case with `TRUST_PROXY` off, inbox paging past held messages.
- P3: first message while the recipient is offline; many messages each way; out-of-order delivery; replay; a crash between decrypt and acknowledge; one-time keys running out; a server substituting a ratchet key or a one-time key; lost session state on one side.
- P4: round trip; wrong passphrase; altered file; restore replaces keys and the old device stops; contacts keep working after a restore.
- P5: the production Compose file is started in CI and checked for HTTPS redirect, headers and `/health`.

## 10. Build order

| Order | Branch | Piece | Depends on |
|---|---|---|---|
| 1 | `feature/per-person-invites` | P1 | — |
| 2 | `feature/rate-limits` | P2 | — |
| 3 | `chore/deploy` | P5 | P1, P2 |
| 4 | `spike/ratchet-library` (not merged) | P3 spike | — |
| 5 | `feature/ratchet-*` (several PRs) | P3 | spike |
| 6 | `feature/identity-backup` | P4 | P3 |
| 7 | `feature/ux-*` | Visual design | P1–P4 |

P1 and P2 are small, independent, and needed before anything faces the internet. P3 is the bulk of the work and the only piece with real technical uncertainty, which is why its spike can start early alongside the others. P4 follows P3 because restoring an account changes ratchet keys.

## 11. Decisions taken at review (2026-11-16)

1. **Going live.** Nobody beyond the original two users is invited until the operator judges the whole of M2 ready. The VPS may be set up and used by the original two for private testing once P1, P2 and P5 are merged; that keeps M1's rule intact.
2. **A contact restores their account:** show a notice in the conversation and keep sending (section 6). Not a block: the new key is signed by the identity key already pinned, and anyone holding the backup file and its passphrase holds that identity key anyway.
3. **Message history in a backup:** off by default, with a checkbox. The file is the most sensitive thing the app produces.
4. **Clean break at P3:** yes. Accounts and undelivered messages are wiped by the migration, as with migration 002.
5. **On the VPS:** Docker Compose. See "Changing this later" in section 7 for what a move to a larger production setup would involve.

Still to settle, inside P3: the ratchet library, decided by the spike in section 5.3.
