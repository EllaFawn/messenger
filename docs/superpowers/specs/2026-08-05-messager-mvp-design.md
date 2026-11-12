# Messager — E2E Encrypted 1:1 Messaging, MVP Design

Status: approved for implementation planning. Supersedes crypto details in `SPEC.md` where they differ (per-message signature dropped, replay counter added, invite-coded registration added).

Scope: self-hosted hobby prototype, invite-only. Two milestones with a hard gate between them.

- **M1** — two users, current VPS. Static ECDH, no forward secrecy, accepted and documented.
- **M2 gate** — before a production VPS or any user beyond the original two: Double Ratchet, per-invite codes, rate limiting, identity export, VPS hardening. Static ECDH is not acceptable past this gate.

This document specifies M1. M2 items appear only as seams M1 must leave open.

## 1. Stack

- TypeScript everywhere.
- npm workspaces monorepo:
  - `packages/crypto` — keygen, ECDH, HKDF, AEAD, hashing. Headless, isomorphic, no DOM/node-specific APIs. Test-vector tested.
  - `packages/protocol` — wire types, userID derivation, canonical request string, envelope encode/decode. Shared by client and server so signer and verifier cannot drift.
  - `packages/server` — Express + `pg`. Imports protocol + crypto (verify only).
  - `packages/web` — React + Vite. Imports protocol + crypto.
- Crypto library: `libsodium-wrappers-sumo` (audited C core via WASM; sign, scalarmult, HKDF-SHA256, XChaCha20-Poly1305).
- DB: Postgres 16 via `docker-compose.yml` for dev; same engine on VPS.
- Delivery: REST first (inbox + ack); WebSocket push added after REST works end to end. REST remains source of truth; WS carries new-message events only.

Dependency direction: `web → {crypto, protocol}`, `server → {crypto, protocol}`. Nothing imports `web` or `server`.

## 2. Identity and keys

- Identity key: Ed25519 (`crypto_sign_keypair`) — signs API requests. Not used per message.
- Exchange key: X25519 (`crypto_box_keypair`) — ECDH.
- `userID = base64url(SHA-256(identity_pubkey))` — lookup pointer, not a credential.
- Private keys live client-side in IndexedDB, never leave the browser.

## 3. Message encryption

```
ss   = crypto_scalarmult(my_x_priv, their_x_pub)
prk  = HKDF-SHA256-Extract(salt = UTF8(sort(userID_a, userID_b).join("|")), ikm = ss)
key  = HKDF-SHA256-Expand(prk, info = "messager/v1/msg/" + from_userID + ">" + to_userID, L = 32)
n    = random 24-byte nonce
AD   = UTF8("v1|" + from_userID + "|" + to_userID) || n
ct   = XChaCha20-Poly1305-ietf_encrypt(key, n, plaintext, AD)
```

- **Directional keys**: HKDF `info` includes sender→recipient order, so A→B and B→A derive different keys from the same shared secret. Removes shared-key nonce-reuse concerns.
- **AD binds routing**: ciphertext only decrypts under the claimed from/to pair; the server cannot re-route a message and have it verify.
- **No per-message Ed25519 signature.** The AEAD tag authenticates within the pair (only A and B hold the key; B knows what B sent). The server authenticates the sender at POST time via request signing. A signature would add only non-repudiation — evidence against our own users — so it is deliberately omitted. `SPEC.md` §3/§5/§6 signature fields are dropped.

Plaintext is JSON before encryption:

```json
{ "counter": 42, "text": "hello", "sentAt": 1754400000000 }
```

- **`counter`**: per-(sender→recipient) monotonic, maintained by sender, stored client-side. Recipient rejects any message whose counter ≤ last seen for that sender. Blocks server-side replay and reordering; also catches duplicate-delivery bugs.

Wire envelope (versioned for M2 coexistence):

```json
{ "v": 1, "to": "<userID>", "nonce": "<b64>", "ciphertext": "<b64>" }
```

## 4. Authentication (API request signing)

No passwords. Every authenticated request carries headers:

```
X-User-ID, X-Timestamp (unix ms), X-Nonce (16 random bytes, b64), X-Signature
```

Signature is Ed25519 over the canonical string, built identically by `protocol` on both sides:

```
v1\n{METHOD}\n{path}\n{hex(SHA-256(raw_body))}\n{timestamp}\n{nonce}
```

Server verification order:

1. `|now − timestamp| ≤ 60s`, else 401.
2. Signature verifies against the registered `identity_pubkey` for `X-User-ID`, else 401.
3. Nonce unseen: insert into `auth_nonces` (PK constraint rejects replays); rows swept after expiry.

The nonce is stored only after the signature verifies (revised during implementation; originally nonce-then-signature). Otherwise a caller with no valid key could fill `auth_nonces` with junk rows. Replay protection is unchanged: a replayed request has a valid signature and is rejected at step 3. Every failure returns the same 401 body.

**Registration bootstrap** (`POST /register`, no key on file yet):

1. Verify `userID == base64url(SHA-256(identity_pubkey))` from the body — proof the ID binds to the key.
2. Verify the request signature against the pubkey **in the body** — proof of possession.
3. Verify invite code (M1: single static code in server env; M2: per-invite codes). Compared in constant time.
4. Only then store the nonce and insert the user.

Nothing is written before the invite code passes: anyone can generate a key and sign with it, so on this route the invite code is the only scarce credential. An existing `user_id` is never overwritten (409), so registered keys cannot be replaced.

## 5. Data model

```sql
users (
  user_id          text PRIMARY KEY,
  identity_pubkey  bytea NOT NULL,
  exchange_pubkey  bytea NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now()
);

messages (
  message_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  from_user_id text NOT NULL REFERENCES users(user_id),
  to_user_id   text NOT NULL REFERENCES users(user_id),
  nonce        bytea NOT NULL,
  ciphertext   bytea NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz
);

auth_nonces (
  nonce      text PRIMARY KEY,
  user_id    text NOT NULL,
  expires_at timestamptz NOT NULL
);
```

- `delivered_at` set on inbox fetch; row **deleted on ack**. Server retains ciphertext only during the delivery window. No signature column.
- Ciphertext is an opaque blob — M2 ratchet ciphertext needs no schema change; prekey/session tables at M2 are additive.

## 6. API

```
POST /register                  { userID, identity_pubkey, exchange_pubkey, inviteCode }
GET  /users/:userID/pubkeys                                   (signed)
POST /messages                  { v, to, nonce, ciphertext }  (signed)
GET  /messages/inbox                                          (signed)
  → [{ message_id, from, v, nonce, ciphertext, created_at }] undelivered for caller
POST /messages/:id/ack                                        (signed) → deletes row (only recipient may ack)
```

Authorization: inbox returns only `to_user_id = caller`; ack verifies the row's recipient is the caller.

## 7. Client

- **Storage**: IndexedDB — identity/exchange private keys, contacts (userID + pinned pubkeys), decrypted message history, per-contact send counters and last-seen receive counters. History exists client-side only; clearing browser data destroys it. By design.
- **Contacts**: add by pasting a userID; client fetches pubkeys from the server and **pins them**. If the server ever returns different keys for a pinned contact, the UI shows a hard warning and blocks sending until the user explicitly accepts the new keys. (Trust on first use.)
- **Safety number**: `SHA-256(sort(identity_pubkey_a, identity_pubkey_b).concat())` rendered as digit groups, shown per contact. Comparing it out of band closes the malicious-server MITM hole; key pinning covers every later fetch.
- **UI**: contact list, chat view (message list + input), add-contact flow, safety-number screen, key-change warning. Minimal styling.
- **Hygiene**: strict CSP header from the server (no inline script, no remote origins); no `dangerouslySetInnerHTML` anywhere; message text rendered as text nodes only.

## 8. Testing

- `crypto`: published test vectors, not just round-trips — RFC 7748 (X25519), RFC 5869 (HKDF-SHA256), RFC 8032 (Ed25519, for request signing), libsodium XChaCha20-Poly1305-ietf vectors. Negative tests: flipped ciphertext bit fails, wrong AD fails, wrong recipient key fails, A→B key ≠ B→A key.
- `protocol`: canonical-string golden tests (same bytes from client and server builders), envelope encode/decode round-trip, userID derivation vectors.
- `server`: real HTTP requests (Node's built-in `fetch` against the app on a random local port; no `supertest`, to keep the dependency tree small) against dockerized Postgres — register happy path; bad invite code; replayed nonce rejected; stale timestamp rejected; forged signature rejected; A cannot read B's inbox; A cannot ack B's message; ack deletes.
- End-to-end: two headless clients register, exchange userIDs, send/receive/ack through a real server; counters reject a replayed envelope.

## 9. Threat model (M1, honest version)

Accepted, ranked by real-world weight at this scope:

1. **The system is exactly as secure as the VPS.** The server ships the crypto code; root on the box means silent plaintext compromise regardless of any protocol upgrade. Mitigation is operational (SSH keys only, auto-updates, firewall), not cryptographic.
2. **Device compromise yields plaintext directly** — history is stored decrypted in IndexedDB. No protocol fixes this.
3. **No forward secrecy.** One static shared secret per pair, forever. Acceptable only for M1's two informed users; M2 gate requires Double Ratchet.
4. **Metadata is plaintext to the server** (who, when, sizes). Irrelevant at two users; noted for M2+.
5. **XSS steals keys** — mitigated by CSP + text-node rendering + tiny input surface, not eliminated.

README carries: "Prototype. No security review performed. No forward secrecy — a single key compromise exposes all past messages. Not for sensitive real-world use."

## 10. Build order

1. Repo scaffold: workspaces, TS config, vitest, docker-compose, CI-less.
2. `protocol` + `crypto`, headless, vector-tested.
3. DB schema + migrations; `/register` + signed-auth middleware + nonce store.
4. Messaging REST: send / inbox / ack, integration-tested.
5. Web UI: identity creation, contacts + pinning + safety numbers, chat, IndexedDB.
6. WebSocket push (new-message notify; REST remains source of truth).
7. — M1 complete —
8. M2 gate items (separate spec when the time comes): Double Ratchet (implement Signal specs on libsodium, or audited WASM ratchet e.g. vodozemac — decide then), per-invite codes, rate limiting, identity export/import, VPS hardening checklist.
