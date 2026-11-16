/* tslint:disable */
/* eslint-disable */

/**
 * One user's long-term ratchet key and their supply of one-time keys.
 */
export class Account {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Accepts a first (pre-key) message. Fails unless it was made for this
     * account by the holder of `their_identity_key`.
     */
    createInboundSession(their_identity_key: Uint8Array | number[], prekey_message: Uint8Array | number[]): Inbound;
    /**
     * Starts a session with someone, using one of their one-time (or fallback) keys.
     */
    createOutboundSession(their_identity_key: Uint8Array | number[], their_one_time_key: Uint8Array | number[]): Session;
    /**
     * Drops the previous fallback key, once the new one has been in use long enough.
     */
    forgetOldFallbackKey(): boolean;
    static fromPickle(pickle: string, key: Uint8Array | number[]): Account;
    /**
     * Replaces the fallback key, which is used when the one-time keys have run out.
     */
    generateFallbackKey(): void;
    generateOneTimeKeys(count: number): void;
    /**
     * The long-term Curve25519 public key, 32 bytes.
     */
    identityKey(): Uint8Array;
    markKeysAsPublished(): void;
    /**
     * The most one-time keys the account will hold at once.
     */
    maxOneTimeKeys(): number;
    constructor();
    /**
     * Serialised state, encrypted under a 32-byte key.
     */
    pickle(key: Uint8Array | number[]): string;
    /**
     * The fallback key, if one was generated and is not yet marked as published.
     */
    unpublishedFallbackKey(): PublicKey | undefined;
    /**
     * One-time keys generated but not yet marked as published.
     */
    unpublishedOneTimeKeys(): PublicKey[];
}

/**
 * An encrypted message. `kind` 0 is a pre-key message (sent until the other
 * side has replied), 1 a normal one.
 */
export class Encrypted {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly body: Uint8Array;
    readonly kind: number;
}

/**
 * The result of accepting someone's first message.
 */
export class Inbound {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Hands over the new session. Can be called once.
     */
    takeSession(): Session;
    readonly plaintext: Uint8Array;
}

/**
 * A public key with the id the library knows it by.
 */
export class PublicKey {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly id: string;
    readonly key: Uint8Array;
}

/**
 * One end of an encrypted conversation between two accounts.
 */
export class Session {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Decrypts a message. Each message can be decrypted once: doing so
     * advances the session and destroys the key.
     */
    decrypt(kind: number, body: Uint8Array | number[]): Uint8Array;
    encrypt(plaintext: Uint8Array | number[]): Encrypted;
    static fromPickle(pickle: string, key: Uint8Array | number[]): Session;
    /**
     * Whether the other side has replied yet. Until then every message
     * sent is a pre-key message.
     */
    hasReceivedMessage(): boolean;
    pickle(key: Uint8Array | number[]): string;
    sessionId(): string;
}

/**
 * The id of the session a pre-key message belongs to, so a repeat of the
 * first message can be routed to the session it already created.
 */
export function preKeyMessageSessionId(prekey_message: Uint8Array | number[]): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_account_free: (a: number, b: number) => void;
    readonly __wbg_encrypted_free: (a: number, b: number) => void;
    readonly __wbg_inbound_free: (a: number, b: number) => void;
    readonly __wbg_publickey_free: (a: number, b: number) => void;
    readonly __wbg_session_free: (a: number, b: number) => void;
    readonly account_createInboundSession: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly account_createOutboundSession: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly account_forgetOldFallbackKey: (a: number) => number;
    readonly account_fromPickle: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly account_generateFallbackKey: (a: number) => void;
    readonly account_generateOneTimeKeys: (a: number, b: number) => void;
    readonly account_identityKey: (a: number, b: number) => void;
    readonly account_markKeysAsPublished: (a: number) => void;
    readonly account_maxOneTimeKeys: (a: number) => number;
    readonly account_new: () => number;
    readonly account_pickle: (a: number, b: number, c: number, d: number) => void;
    readonly account_unpublishedFallbackKey: (a: number) => number;
    readonly account_unpublishedOneTimeKeys: (a: number, b: number) => void;
    readonly encrypted_body: (a: number, b: number) => void;
    readonly encrypted_kind: (a: number) => number;
    readonly inbound_plaintext: (a: number, b: number) => void;
    readonly inbound_takeSession: (a: number, b: number) => void;
    readonly preKeyMessageSessionId: (a: number, b: number, c: number) => void;
    readonly publickey_id: (a: number, b: number) => void;
    readonly publickey_key: (a: number, b: number) => void;
    readonly session_decrypt: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly session_encrypt: (a: number, b: number, c: number, d: number) => void;
    readonly session_fromPickle: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly session_hasReceivedMessage: (a: number) => number;
    readonly session_pickle: (a: number, b: number, c: number, d: number) => void;
    readonly session_sessionId: (a: number, b: number) => void;
    readonly __wbindgen_export: (a: number) => void;
    readonly __wbindgen_export2: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export3: (a: number, b: number) => number;
    readonly __wbindgen_export4: (a: number, b: number, c: number) => void;
    readonly __wbindgen_export5: (a: number) => void;
    readonly __wbindgen_export6: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_export7: (a: number, b: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
