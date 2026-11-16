//! A thin WebAssembly wrapper around vodozemac's Olm implementation
//! (the Double Ratchet with one-time prekeys).
//!
//! It contains no cryptography of its own. Every function is a direct call
//! into the audited library, with types converted for JavaScript. Keep it
//! that way: anything cleverer belongs in TypeScript, where it is tested.

use vodozemac::olm::{
    Account as OlmAccount, AccountPickle, OlmMessage, PreKeyMessage, Session as OlmSession, SessionConfig,
    SessionPickle,
};
use vodozemac::Curve25519PublicKey;
use wasm_bindgen::prelude::*;

/// The standard, audited configuration (8-byte message authentication tag).
/// The full-length variant is behind an "experimental" flag upstream and is
/// deliberately not used.
fn config() -> SessionConfig {
    SessionConfig::version_1()
}

fn err<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

fn key32(key: &[u8], what: &str) -> Result<[u8; 32], JsError> {
    key.try_into().map_err(|_| JsError::new(&format!("{what} must be 32 bytes")))
}

fn public_key(bytes: &[u8]) -> Result<Curve25519PublicKey, JsError> {
    Curve25519PublicKey::from_slice(bytes).map_err(err)
}

/// A public key with the id the library knows it by.
#[wasm_bindgen]
pub struct PublicKey {
    id: String,
    key: Vec<u8>,
}

#[wasm_bindgen]
impl PublicKey {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.id.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn key(&self) -> Vec<u8> {
        self.key.clone()
    }
}

/// An encrypted message. `kind` 0 is a pre-key message (sent until the other
/// side has replied), 1 a normal one.
#[wasm_bindgen]
pub struct Encrypted {
    kind: usize,
    body: Vec<u8>,
}

#[wasm_bindgen]
impl Encrypted {
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> usize {
        self.kind
    }
    #[wasm_bindgen(getter)]
    pub fn body(&self) -> Vec<u8> {
        self.body.clone()
    }
}

/// The result of accepting someone's first message.
#[wasm_bindgen]
pub struct Inbound {
    session: Option<Session>,
    plaintext: Vec<u8>,
}

#[wasm_bindgen]
impl Inbound {
    #[wasm_bindgen(getter)]
    pub fn plaintext(&self) -> Vec<u8> {
        self.plaintext.clone()
    }

    /// Hands over the new session. Can be called once.
    #[wasm_bindgen(js_name = takeSession)]
    pub fn take_session(&mut self) -> Result<Session, JsError> {
        self.session.take().ok_or_else(|| JsError::new("session already taken"))
    }
}

/// One user's long-term ratchet key and their supply of one-time keys.
#[wasm_bindgen]
pub struct Account {
    inner: OlmAccount,
}

#[wasm_bindgen]
impl Account {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Account {
        Account { inner: OlmAccount::new() }
    }

    /// The long-term Curve25519 public key, 32 bytes.
    #[wasm_bindgen(js_name = identityKey)]
    pub fn identity_key(&self) -> Vec<u8> {
        self.inner.curve25519_key().to_bytes().to_vec()
    }

    /// The most one-time keys the account will hold at once.
    #[wasm_bindgen(js_name = maxOneTimeKeys)]
    pub fn max_one_time_keys(&self) -> usize {
        self.inner.max_number_of_one_time_keys()
    }

    #[wasm_bindgen(js_name = generateOneTimeKeys)]
    pub fn generate_one_time_keys(&mut self, count: usize) {
        self.inner.generate_one_time_keys(count);
    }

    /// One-time keys generated but not yet marked as published.
    #[wasm_bindgen(js_name = unpublishedOneTimeKeys)]
    pub fn unpublished_one_time_keys(&self) -> Vec<PublicKey> {
        let mut keys: Vec<PublicKey> = self
            .inner
            .one_time_keys()
            .into_iter()
            .map(|(id, key)| PublicKey { id: id.to_base64(), key: key.to_bytes().to_vec() })
            .collect();
        keys.sort_by(|a, b| a.id.cmp(&b.id));
        keys
    }

    /// Replaces the fallback key, which is used when the one-time keys have run out.
    #[wasm_bindgen(js_name = generateFallbackKey)]
    pub fn generate_fallback_key(&mut self) {
        self.inner.generate_fallback_key();
    }

    /// The fallback key, if one was generated and is not yet marked as published.
    #[wasm_bindgen(js_name = unpublishedFallbackKey)]
    pub fn unpublished_fallback_key(&self) -> Option<PublicKey> {
        self.inner
            .fallback_key()
            .into_iter()
            .next()
            .map(|(id, key)| PublicKey { id: id.to_base64(), key: key.to_bytes().to_vec() })
    }

    /// Drops the previous fallback key, once the new one has been in use long enough.
    #[wasm_bindgen(js_name = forgetOldFallbackKey)]
    pub fn forget_old_fallback_key(&mut self) -> bool {
        self.inner.forget_fallback_key()
    }

    #[wasm_bindgen(js_name = markKeysAsPublished)]
    pub fn mark_keys_as_published(&mut self) {
        self.inner.mark_keys_as_published();
    }

    /// Starts a session with someone, using one of their one-time (or fallback) keys.
    #[wasm_bindgen(js_name = createOutboundSession)]
    pub fn create_outbound_session(&self, their_identity_key: &[u8], their_one_time_key: &[u8]) -> Result<Session, JsError> {
        let inner = self
            .inner
            .create_outbound_session(config(), public_key(their_identity_key)?, public_key(their_one_time_key)?)
            .map_err(err)?;
        Ok(Session { inner })
    }

    /// Accepts a first (pre-key) message. Fails unless it was made for this
    /// account by the holder of `their_identity_key`.
    #[wasm_bindgen(js_name = createInboundSession)]
    pub fn create_inbound_session(&mut self, their_identity_key: &[u8], prekey_message: &[u8]) -> Result<Inbound, JsError> {
        let prekey = PreKeyMessage::from_bytes(prekey_message).map_err(err)?;
        let result = self.inner.create_inbound_session(config(), public_key(their_identity_key)?, &prekey).map_err(err)?;
        Ok(Inbound { session: Some(Session { inner: result.session }), plaintext: result.plaintext })
    }

    /// Serialised state, encrypted under a 32-byte key.
    pub fn pickle(&self, key: &[u8]) -> Result<String, JsError> {
        Ok(self.inner.pickle().encrypt(&key32(key, "pickle key")?))
    }

    #[wasm_bindgen(js_name = fromPickle)]
    pub fn from_pickle(pickle: &str, key: &[u8]) -> Result<Account, JsError> {
        let pickle = AccountPickle::from_encrypted(pickle, &key32(key, "pickle key")?).map_err(err)?;
        Ok(Account { inner: OlmAccount::from_pickle(pickle) })
    }
}

impl Default for Account {
    fn default() -> Self {
        Self::new()
    }
}

/// One end of an encrypted conversation between two accounts.
#[wasm_bindgen]
pub struct Session {
    inner: OlmSession,
}

#[wasm_bindgen]
impl Session {
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Encrypted, JsError> {
        let (kind, body) = self.inner.encrypt(plaintext).map_err(err)?.to_parts();
        Ok(Encrypted { kind, body })
    }

    /// Decrypts a message. Each message can be decrypted once: doing so
    /// advances the session and destroys the key.
    pub fn decrypt(&mut self, kind: usize, body: &[u8]) -> Result<Vec<u8>, JsError> {
        let message = OlmMessage::from_parts(kind, body).map_err(err)?;
        self.inner.decrypt(&message).map_err(err)
    }

    #[wasm_bindgen(js_name = sessionId)]
    pub fn session_id(&self) -> String {
        self.inner.session_id()
    }

    /// Whether the other side has replied yet. Until then every message
    /// sent is a pre-key message.
    #[wasm_bindgen(js_name = hasReceivedMessage)]
    pub fn has_received_message(&self) -> bool {
        self.inner.has_received_message()
    }

    pub fn pickle(&self, key: &[u8]) -> Result<String, JsError> {
        Ok(self.inner.pickle().encrypt(&key32(key, "pickle key")?))
    }

    #[wasm_bindgen(js_name = fromPickle)]
    pub fn from_pickle(pickle: &str, key: &[u8]) -> Result<Session, JsError> {
        let pickle = SessionPickle::from_encrypted(pickle, &key32(key, "pickle key")?).map_err(err)?;
        Ok(Session { inner: OlmSession::from_pickle(pickle) })
    }
}

/// The id of the session a pre-key message belongs to, so a repeat of the
/// first message can be routed to the session it already created.
#[wasm_bindgen(js_name = preKeyMessageSessionId)]
pub fn pre_key_message_session_id(prekey_message: &[u8]) -> Result<String, JsError> {
    Ok(PreKeyMessage::from_bytes(prekey_message).map_err(err)?.session_id())
}
