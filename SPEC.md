# Private Encrypted Messaging Web App — Hobby MVP Spec

Scope: for-fun prototype, self-hosted, invite-only/friends-only. Not for public/real-world sensitive use. See Appendix for what changes if this ever goes public.

## 1. Goal

E2E encrypted 1:1 text messaging. Server is a dumb relay — stores ciphertext + routing metadata only, never plaintext or private keys. Modeled on Signal Protocol architecture, using audited crypto libraries rather than hand-rolled crypto.

## 2. Scope

**In:**
- 1:1 text messaging, E2E encrypted
- Account = keypair, no password
- Basic web UI

**Out (for now):**
- Groups, attachments, voice/video
- Multi-device, key recovery
- Forward secrecy / Double Ratchet (Phase 1 = static ECDH only)
- Any compliance/legal process (public launch concern, not hobby concern)

## 3. Crypto

- Identity key: Ed25519 (signing)
- Exchange key: X25519 (ECDH)
- userID = SHA-256(identity_pubkey) — a lookup pointer, not a credential
- Library: libsignal if browser/WASM support is usable at build time; otherwise libsodium.js / TweetNaCl for primitives, static ECDH scheme, no custom ratchet logic
- Flow: `shared_secret = X25519(my_priv, their_pub)` → `key = HKDF(shared_secret)` → `AEAD_encrypt(key, plaintext)` → `sign(identity_priv, ciphertext)`

Known limitation, accepted for hobby scope: no forward secrecy — a compromised key exposes past messages. Fine for two people who understand this; not fine for anyone else without upgrading to Double Ratchet first.

## 4. Auth

No passwords. Client signs requests with identity privkey; server verifies signature against registered pubkey. Possession of the privkey = identity.

## 5. Data Model

```
users:    userID (PK), identity_pubkey, exchange_pubkey, created_at
messages: message_id (PK), from_userID, to_userID, ciphertext, signature,
          created_at, delivered_at (nullable)
```

## 6. API

```
POST /register              { userID, identity_pubkey, exchange_pubkey }
GET  /users/:userID/pubkeys
POST /messages               { to, ciphertext, signature }  (signed)
GET  /messages/inbox                                        (signed)
POST /messages/:id/ack                                      (signed)
```

## 7. Stack

- Frontend: React or plain JS, minimal
- Crypto: libsignal / libsodium.js / TweetNaCl
- Backend: Node/Express, thin relay
- DB: Postgres
- Transport: WebSocket + TLS; self-hosted on existing VPS infra

## 8. Split (2 devs)

- Dev A: crypto core + auth (keygen, ECDH, sign/verify, registration)
- Dev B: relay server + UI (API, WebSocket delivery, chat interface)
- Merge point: end-to-end send/receive working between two test accounts

## 9. Build Order

1. Crypto core, headless, unit tested (test vectors, not just round-trip)
2. Account creation + signature-based auth
3. Messaging (static ECDH, no ratchet)
4. UI — bolted on last
5. (Stretch) Double Ratchet via libsignal, if you want to push further

## 10. Guardrail

Add to README: "Prototype. No security review performed. Not for sensitive real-world use." Keep invite-only — don't publicize or open registration.

## Appendix — If This Ever Goes Public

Deferred, not forgotten. Before any real users beyond your own circle:

- UK Online Safety Act duties (ToS, report mechanism, incident process) — encryption legality is currently fine in the UK but Ofcom's accredited scanning tech guidance is pending and could change this
- GDPR / UK DPA — privacy policy, lawful basis, retention limits, subject access requests
- Entity structure decision (sole trader vs ltd) — personal liability exposure, especially given OSA's personal criminal liability provisions for senior individuals at non-compliant platforms
- Third-party security review of the crypto module, minimum
- Dependency scanning (Dependabot/npm audit) as standing practice
- Rate limiting / abuse prevention on the relay
- Key loss UX — currently "your identity is gone," needs real user-facing handling before wider release
- Account deletion / right-to-erasure handling, aware that E2E limits what "deletion" can actually mean for the other party's copy
