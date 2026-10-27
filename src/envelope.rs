//! Authenticated-encryption envelope shared by every packet after Phase 0.
//!
//! Phase 0 yields the ML-KEM-768 secret `K_auth`. Two directional keys
//! come from it, one for client-to-server packets and one for
//! server-to-client packets. Every packet body is sealed with
//! XChaCha20-Poly1305 under the key of its direction.
//!
//! Request nonces are deterministic. They are the 24-byte nonce of the cookie
//! with the direction, kind and index of the request mixed into the last
//! three bytes. A resent request is therefore byte-identical. Response nonces
//! are fresh random bytes, one per reply.
//!
//! A request nonce repeats only for the same cookie, kind and index. The
//! client-to-server key comes from the `K_auth` sealed in that cookie, and the
//! server picks a fresh random cookie nonce for every cookie. For one cookie,
//! kind and index an honest client has exactly one plaintext: nothing for a
//! u-chunk, and the residue `s mod f_i` of its one public key for v-residue
//! `i`. So the same key and nonce never seal two different plaintexts. Only
//! the holder of `K_auth` can seal under this key, so a client that breaks
//! this rule harms only its own session.

use crate::auth::AuthSecret;
use crate::error::{Error, Result};
use chacha20poly1305::{
    Tag, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use zeroize::Zeroizing;

pub const NONCE_BYTES: usize = 24;
pub const TAG_BYTES: usize = 16;
pub const KEY_BYTES: usize = 32;

const CLIENT_TO_SERVER_CONTEXT: &str = "HQCLethe 2026-10 client-to-server key v1";
const SERVER_TO_CLIENT_CONTEXT: &str = "HQCLethe 2026-10 server-to-client key v1";

pub type Nonce = [u8; NONCE_BYTES];
pub type Key = Zeroizing<[u8; KEY_BYTES]>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    ClientToServer = 0,
    ServerToClient = 1,
}

/// The two directional keys derived from `K_auth`.
pub struct SessionKeys {
    pub client_to_server: Key,
    pub server_to_client: Key,
}

impl SessionKeys {
    pub fn derive(k_auth: &AuthSecret) -> Self {
        Self {
            client_to_server: Zeroizing::new(blake3::derive_key(
                CLIENT_TO_SERVER_CONTEXT,
                &k_auth[..],
            )),
            server_to_client: Zeroizing::new(blake3::derive_key(
                SERVER_TO_CLIENT_CONTEXT,
                &k_auth[..],
            )),
        }
    }

    pub fn key(&self, direction: Direction) -> &Key {
        match direction {
            Direction::ClientToServer => &self.client_to_server,
            Direction::ServerToClient => &self.server_to_client,
        }
    }
}

pub fn request_nonce(cookie_nonce: &[u8], kind: u8, index: u8) -> Nonce {
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&cookie_nonce[..NONCE_BYTES]);
    nonce[NONCE_BYTES - 3] ^= Direction::ClientToServer as u8;
    nonce[NONCE_BYTES - 2] ^= kind;
    nonce[NONCE_BYTES - 1] ^= index;
    nonce
}

/// Encrypts `buf` in place and returns the tag.
pub fn seal(key: &Key, nonce: &Nonce, aad: &[u8], buf: &mut [u8]) -> Result<[u8; TAG_BYTES]> {
    let cipher = XChaCha20Poly1305::new((&**key).into());
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(nonce), aad, buf)
        .map_err(|_| Error::EncryptionError)?;
    Ok(tag.into())
}

/// Decrypts `buf` in place. On failure the content of `buf` is unspecified.
pub fn open(key: &Key, nonce: &Nonce, aad: &[u8], buf: &mut [u8], tag: &[u8]) -> Result<()> {
    if tag.len() != TAG_BYTES {
        return Err(Error::DecryptionError);
    }
    let cipher = XChaCha20Poly1305::new((&**key).into());
    cipher
        .decrypt_in_place_detached(XNonce::from_slice(nonce), aad, buf, Tag::from_slice(tag))
        .map_err(|_| Error::DecryptionError)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> SessionKeys {
        SessionKeys::derive(&Zeroizing::new([5u8; 32]))
    }

    #[test]
    fn directional_keys_differ() {
        let keys = keys();
        assert_ne!(*keys.client_to_server, *keys.server_to_client);
    }

    #[test]
    fn seal_then_open_roundtrips_and_rejects_every_bit_flip() {
        let keys = keys();
        let key = keys.key(Direction::ServerToClient);
        let nonce = [9u8; NONCE_BYTES];
        let mut buf = *b"payload bytes";
        let tag = seal(key, &nonce, b"aad", &mut buf).unwrap();

        let mut ok = buf;
        open(key, &nonce, b"aad", &mut ok, &tag).unwrap();
        assert_eq!(&ok, b"payload bytes");

        for bit in 0..buf.len() * 8 {
            let mut bad = buf;
            bad[bit / 8] ^= 1 << (bit % 8);
            assert!(open(key, &nonce, b"aad", &mut bad, &tag).is_err());
        }
        let mut wrong_aad = buf;
        assert!(open(key, &nonce, b"aae", &mut wrong_aad, &tag).is_err());
        let mut wrong_dir = buf;
        let other = keys.key(Direction::ClientToServer);
        assert!(open(other, &nonce, b"aad", &mut wrong_dir, &tag).is_err());
    }

    #[test]
    fn request_nonce_is_deterministic_and_distinct_per_kind_and_index() {
        let cookie_nonce = [3u8; NONCE_BYTES];
        let nonce = |kind, index| request_nonce(&cookie_nonce, kind, index);
        assert_eq!(nonce(1, 2), nonce(1, 2));
        assert_ne!(nonce(1, 2), nonce(1, 3));
        assert_ne!(nonce(1, 2), nonce(2, 2));
    }

    #[test]
    fn request_nonce_never_repeats_over_every_kind_and_index() {
        let cookie_nonce = [0xA5u8; NONCE_BYTES];
        let mut seen = std::collections::HashSet::new();
        for kind in 0..8u8 {
            for index in 0..=u8::MAX {
                assert!(seen.insert(request_nonce(&cookie_nonce, kind, index)));
            }
        }
    }
}
