/**
 * Forward-secret sessions between two users: the Double Ratchet with
 * one-time prekeys, as implemented by vodozemac (Olm).
 *
 * All cryptography happens inside the WebAssembly module built from
 * `rust/`. This file only gives it a small, typed surface: plain values in
 * and out, and no raw WebAssembly objects for callers to manage.
 */
import init, {
  Account as WasmAccount,
  initSync,
  preKeyMessageSessionId as wasmPreKeyMessageSessionId,
  Session as WasmSession,
  type PublicKey as WasmPublicKey,
} from "../wasm/messager_ratchet.js";

/** Sent until the other side has replied; carries what the recipient needs to create the session. */
export const MESSAGE_TYPE_PREKEY = 0;
export const MESSAGE_TYPE_NORMAL = 1;
export type MessageType = typeof MESSAGE_TYPE_PREKEY | typeof MESSAGE_TYPE_NORMAL;

export const RATCHET_KEY_BYTES = 32;
/** Saved state is encrypted under a key of this length. */
export const PICKLE_KEY_BYTES = 32;

export interface EncryptedMessage {
  type: MessageType;
  body: Uint8Array;
}

/** A one-time or fallback public key, with the id the owning account knows it by. */
export interface OneTimeKey {
  id: string;
  key: Uint8Array;
}

let ready: Promise<void> | null = null;

/**
 * Loads the WebAssembly module. Must have resolved before anything else here
 * is used. Safe to call more than once.
 *
 * In a browser, call it with no argument: the module is fetched from next to
 * the script. Elsewhere (tests, Node), pass the bytes of
 * `wasm/messager_ratchet_bg.wasm`.
 */
export function initRatchet(wasmBytes?: BufferSource): Promise<void> {
  if (ready === null) {
    ready =
      wasmBytes === undefined
        ? init().then(() => undefined)
        : Promise.resolve().then(() => {
            initSync({ module: wasmBytes });
          });
    // A failed load can be retried.
    ready.catch(() => {
      ready = null;
    });
  }
  return ready;
}

function takeKey(wasmKey: WasmPublicKey): OneTimeKey {
  const key = { id: wasmKey.id, key: wasmKey.key };
  wasmKey.free();
  return key;
}

function asMessageType(kind: number): MessageType {
  if (kind !== MESSAGE_TYPE_PREKEY && kind !== MESSAGE_TYPE_NORMAL) {
    throw new Error(`unknown ratchet message type ${kind}`);
  }
  return kind;
}

/** One user's long-term ratchet key and their supply of one-time keys. */
export class RatchetAccount {
  private constructor(private readonly inner: WasmAccount) {}

  /** A brand-new account with fresh keys. */
  static create(): RatchetAccount {
    return new RatchetAccount(new WasmAccount());
  }

  /** Restores an account saved with `save`. Throws if the key is wrong or the data is damaged. */
  static restore(saved: string, pickleKey: Uint8Array): RatchetAccount {
    return new RatchetAccount(WasmAccount.fromPickle(saved, pickleKey));
  }

  /** Serialises the account, encrypted under `pickleKey`. Save it again after every change. */
  save(pickleKey: Uint8Array): string {
    return this.inner.pickle(pickleKey);
  }

  /** The long-term public key other users start sessions with. 32 bytes. */
  get identityKey(): Uint8Array {
    return this.inner.identityKey();
  }

  /** The most one-time keys the account keeps; generating more discards the oldest. */
  get maxOneTimeKeys(): number {
    return this.inner.maxOneTimeKeys();
  }

  /** Generates `count` more one-time keys and returns every key not yet marked as published. */
  generateOneTimeKeys(count: number): OneTimeKey[] {
    if (!Number.isInteger(count) || count < 1 || count > this.maxOneTimeKeys) {
      throw new Error("one-time key count out of range");
    }
    this.inner.generateOneTimeKeys(count);
    return this.unpublishedOneTimeKeys();
  }

  unpublishedOneTimeKeys(): OneTimeKey[] {
    return this.inner.unpublishedOneTimeKeys().map(takeKey);
  }

  /**
   * Replaces the fallback key: the key handed out when the one-time keys
   * have run out, so a conversation can still be started.
   */
  generateFallbackKey(): OneTimeKey {
    this.inner.generateFallbackKey();
    const key = this.inner.unpublishedFallbackKey();
    if (key === undefined) {
      throw new Error("fallback key was not generated");
    }
    return takeKey(key);
  }

  /** Call once the keys returned above have been accepted by the server. */
  markKeysAsPublished(): void {
    this.inner.markKeysAsPublished();
  }

  /** Starts a session with someone, using one of their one-time (or fallback) keys from the server. */
  startSession(theirIdentityKey: Uint8Array, theirOneTimeKey: Uint8Array): RatchetSession {
    return new RatchetSession(this.inner.createOutboundSession(theirIdentityKey, theirOneTimeKey));
  }

  /**
   * Accepts someone's first message, creating the session and decrypting
   * the message. Throws unless the message was made for this account by the
   * holder of `theirIdentityKey`. The one-time key it used is consumed, so
   * save the account afterwards.
   */
  acceptSession(
    theirIdentityKey: Uint8Array,
    prekeyMessageBody: Uint8Array,
  ): { session: RatchetSession; plaintext: Uint8Array } {
    const inbound = this.inner.createInboundSession(theirIdentityKey, prekeyMessageBody);
    try {
      return { session: new RatchetSession(inbound.takeSession()), plaintext: inbound.plaintext };
    } finally {
      inbound.free();
    }
  }
}

/** One end of an encrypted conversation. */
export class RatchetSession {
  /** @internal Sessions come from RatchetAccount or RatchetSession.restore. */
  constructor(private readonly inner: WasmSession) {}

  static restore(saved: string, pickleKey: Uint8Array): RatchetSession {
    return new RatchetSession(WasmSession.fromPickle(saved, pickleKey));
  }

  /** Serialises the session, encrypted under `pickleKey`. Save it after every encrypt and decrypt. */
  save(pickleKey: Uint8Array): string {
    return this.inner.pickle(pickleKey);
  }

  get id(): string {
    return this.inner.sessionId();
  }

  /** Whether the other side has replied. Until then every message sent is a pre-key message. */
  get hasReceivedMessage(): boolean {
    return this.inner.hasReceivedMessage();
  }

  encrypt(plaintext: Uint8Array): EncryptedMessage {
    const encrypted = this.inner.encrypt(plaintext);
    try {
      return { type: asMessageType(encrypted.kind), body: encrypted.body };
    } finally {
      encrypted.free();
    }
  }

  /**
   * Decrypts a message. This advances the session and destroys the message's
   * key, so each message decrypts exactly once: store the result and the
   * saved session together, or the message is lost.
   */
  decrypt(message: EncryptedMessage): Uint8Array {
    return this.inner.decrypt(message.type, message.body);
  }
}

/**
 * The id of the session a pre-key message belongs to. A sender repeats
 * pre-key messages until they get a reply, so this tells an existing session
 * apart from a request to create a new one.
 */
export function preKeyMessageSessionId(prekeyMessageBody: Uint8Array): string {
  return wasmPreKeyMessageSessionId(prekeyMessageBody);
}
