import sodium from "libsodium-wrappers-sumo";

export const ready: Promise<void> = sodium.ready;

export const IDENTITY_PUBLIC_KEY_BYTES = 32;
export const EXCHANGE_KEY_BYTES = 32;
export const AEAD_KEY_BYTES = 32;
export const AEAD_NONCE_BYTES = 24;
export const HASH_BYTES = 32;

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** Ed25519 identity keypair — signs API requests, never used per-message. */
export function generateIdentityKeyPair(): KeyPair {
  const kp = sodium.crypto_sign_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

/** Deterministic identity keypair from a 32-byte seed. Used for test vectors and key import. */
export function identityKeyPairFromSeed(seed: Uint8Array): KeyPair {
  const kp = sodium.crypto_sign_seed_keypair(seed);
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

/** X25519 exchange keypair — used for ECDH. */
export function generateExchangeKeyPair(): KeyPair {
  const kp = sodium.crypto_box_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

export function scalarMult(myPrivateKey: Uint8Array, theirPublicKey: Uint8Array): Uint8Array {
  return sodium.crypto_scalarmult(myPrivateKey, theirPublicKey);
}

// crypto_kdf_hkdf_sha256_{extract,expand} are declared in this wrapper build's
// constants but not exported as callable functions, so HKDF (RFC 5869) is
// implemented directly on top of the HMAC-SHA256 streaming API instead.
const HASH_LEN = 32;

function hmacSha256(key: Uint8Array, ...parts: Uint8Array[]): Uint8Array {
  const state = sodium.crypto_auth_hmacsha256_init(key);
  for (const part of parts) {
    sodium.crypto_auth_hmacsha256_update(state, part);
  }
  return sodium.crypto_auth_hmacsha256_final(state);
}

export function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  return hmacSha256(salt, ikm);
}

export function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const n = Math.ceil(length / HASH_LEN);
  if (n > 255) {
    throw new Error("hkdfExpand: requested length exceeds HKDF-SHA256 maximum (255 * 32 bytes)");
  }
  const okm = new Uint8Array(n * HASH_LEN);
  let t: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  for (let i = 1; i <= n; i++) {
    t = hmacSha256(prk, t, info, new Uint8Array([i]));
    okm.set(t, (i - 1) * HASH_LEN);
  }
  return okm.slice(0, length);
}

export function sha256(data: Uint8Array): Uint8Array {
  return sodium.crypto_hash_sha256(data);
}

export function randomBytes(length: number): Uint8Array {
  return sodium.randombytes_buf(length);
}

export function sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array {
  return sodium.crypto_sign_detached(message, privateKey);
}

export function verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  return sodium.crypto_sign_verify_detached(signature, message, publicKey);
}

/** Combined-mode XChaCha20-Poly1305-ietf: returns ciphertext with the 16-byte tag appended. */
export function aeadEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  ad: Uint8Array,
): Uint8Array {
  return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, null, nonce, key);
}

/** Throws if authentication fails. */
export function aeadDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  ad: Uint8Array,
): Uint8Array {
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, ad, nonce, key);
}

export function toHex(bytes: Uint8Array): string {
  return sodium.to_hex(bytes);
}

export function fromHex(hex: string): Uint8Array {
  return sodium.from_hex(hex);
}

export function toBase64(bytes: Uint8Array): string {
  return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL);
}

export function fromBase64(b64: string): Uint8Array {
  return sodium.from_base64(b64, sodium.base64_variants.ORIGINAL);
}

export function toBase64Url(bytes: Uint8Array): string {
  return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
}

export function fromBase64Url(b64url: string): Uint8Array {
  return sodium.from_base64(b64url, sodium.base64_variants.URLSAFE_NO_PADDING);
}

export function utf8Encode(text: string): Uint8Array {
  return sodium.from_string(text);
}

export function utf8Decode(bytes: Uint8Array): string {
  return sodium.to_string(bytes);
}
