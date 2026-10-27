use crate::auth::{
    AUTH_SECRET_BYTES, AUTH_TAG_BYTES, AuthLevel, AuthSecret, ServerPublicKey, ServerSecretKey,
    auth_tag, bind_secret, verify_auth_tag,
};
use crate::error::{Error, Result};
use crate::traits::EntropyProvider;
use std::sync::Arc;
use zeroize::Zeroizing;

pub struct ServerProof {
    pub tag: Vec<u8>,
    pub session_secret: Vec<u8>,
}

/// The server side of authentication. The server calls `accept` once per
/// Phase-0 hello and `prove` once per completed key upload.
pub trait ServerAuth {
    /// Length of the client's auth request inside the hello.
    fn request_bytes(&self) -> usize;

    /// Length of the tag the server appends to the ciphertext.
    fn tag_bytes(&self) -> usize;

    /// The expensive step. Recovers `K_auth` from the auth request. Returns
    /// `None` for a request of the wrong length.
    fn accept(&self, request: &[u8]) -> Option<AuthSecret>;

    fn prove(&self, k_auth: &AuthSecret, transcript: &[u8], hqc_secret: &[u8]) -> ServerProof;
}

pub trait ClientAuth {
    fn request_bytes(&self) -> usize;

    fn tag_bytes(&self) -> usize;

    /// Called once when the client is built. Returns the auth request.
    fn begin(&mut self) -> Vec<u8>;

    /// The secret that `begin` produced. The packet keys derive from it.
    fn k_auth(&self) -> AuthSecret;

    /// Checks the server's tag. Returns the session secret that replaces
    /// the plain HQC secret.
    fn verify(&self, transcript: &[u8], tag: &[u8], hqc_secret: &[u8]) -> Result<Vec<u8>>;
}

#[derive(Clone, Copy, Default)]
pub struct NoAuth;

fn no_auth_secret() -> AuthSecret {
    Zeroizing::new([0u8; AUTH_SECRET_BYTES])
}

impl ServerAuth for NoAuth {
    fn request_bytes(&self) -> usize {
        0
    }

    fn tag_bytes(&self) -> usize {
        0
    }

    fn accept(&self, _request: &[u8]) -> Option<AuthSecret> {
        Some(no_auth_secret())
    }

    fn prove(&self, _k_auth: &AuthSecret, _transcript: &[u8], hqc_secret: &[u8]) -> ServerProof {
        ServerProof {
            tag: Vec::new(),
            session_secret: hqc_secret.to_vec(),
        }
    }
}

impl ClientAuth for NoAuth {
    fn request_bytes(&self) -> usize {
        0
    }

    fn tag_bytes(&self) -> usize {
        0
    }

    fn begin(&mut self) -> Vec<u8> {
        Vec::new()
    }

    fn k_auth(&self) -> AuthSecret {
        no_auth_secret()
    }

    fn verify(&self, _transcript: &[u8], _tag: &[u8], hqc_secret: &[u8]) -> Result<Vec<u8>> {
        Ok(hqc_secret.to_vec())
    }
}

/// Static ML-KEM-768 authentication, the same mechanism as the
/// stateless server (`crate::auth`).
pub struct MlKemServerAuth<S: AuthLevel> {
    secret_key: ServerSecretKey<S>,
}

impl<S: AuthLevel> Clone for MlKemServerAuth<S> {
    fn clone(&self) -> Self {
        Self::new(self.secret_key.clone())
    }
}

impl<S: AuthLevel> MlKemServerAuth<S> {
    pub fn new(secret_key: ServerSecretKey<S>) -> Self {
        Self { secret_key }
    }
}

impl<S: AuthLevel> ServerAuth for MlKemServerAuth<S> {
    fn request_bytes(&self) -> usize {
        crate::auth::auth_ciphertext_bytes::<S>()
    }

    fn tag_bytes(&self) -> usize {
        AUTH_TAG_BYTES
    }

    fn accept(&self, request: &[u8]) -> Option<AuthSecret> {
        self.secret_key.decapsulate(request).ok()
    }

    fn prove(&self, k_auth: &AuthSecret, transcript: &[u8], hqc_secret: &[u8]) -> ServerProof {
        ServerProof {
            tag: auth_tag(k_auth, transcript).to_vec(),
            session_secret: bind_secret(hqc_secret, k_auth).to_vec(),
        }
    }
}

pub struct MlKemClientAuth<S: AuthLevel> {
    server_key: Arc<ServerPublicKey<S>>,
    secret: Option<AuthSecret>,
}

impl<S: AuthLevel> MlKemClientAuth<S> {
    pub fn new(server_key: Arc<ServerPublicKey<S>>) -> Self {
        Self {
            server_key,
            secret: None,
        }
    }
}

impl<S: AuthLevel> ClientAuth for MlKemClientAuth<S> {
    fn request_bytes(&self) -> usize {
        crate::auth::auth_ciphertext_bytes::<S>()
    }

    fn tag_bytes(&self) -> usize {
        AUTH_TAG_BYTES
    }

    fn begin(&mut self) -> Vec<u8> {
        let (ciphertext, secret) = self.server_key.encapsulate();
        self.secret = Some(secret);
        ciphertext.as_slice().to_vec()
    }

    fn k_auth(&self) -> AuthSecret {
        self.secret.clone().expect("begin runs before k_auth")
    }

    fn verify(&self, transcript: &[u8], tag: &[u8], hqc_secret: &[u8]) -> Result<Vec<u8>> {
        let k_auth = self
            .secret
            .as_ref()
            .ok_or(Error::ServerAuthenticationFailed)?;
        let tag: &[u8; AUTH_TAG_BYTES] = tag
            .try_into()
            .map_err(|_| Error::ServerAuthenticationFailed)?;
        if !verify_auth_tag(k_auth, transcript, tag) {
            return Err(Error::ServerAuthenticationFailed);
        }
        Ok(bind_secret(hqc_secret, k_auth).to_vec())
    }
}

/// Flood tool only. Sends a random auth request of the right length. The
/// server must still run the ML-KEM decapsulation to find out the
/// request is bad. Never accepts a server reply.
pub struct RandomRequestAuth<E> {
    request_bytes: usize,
    entropy: E,
    secret: AuthSecret,
}

impl<E: EntropyProvider> RandomRequestAuth<E> {
    pub fn new(request_bytes: usize, entropy: E) -> Self {
        Self {
            request_bytes,
            entropy,
            secret: Zeroizing::new([0u8; AUTH_SECRET_BYTES]),
        }
    }
}

impl<E: EntropyProvider> ClientAuth for RandomRequestAuth<E> {
    fn request_bytes(&self) -> usize {
        self.request_bytes
    }

    fn tag_bytes(&self) -> usize {
        AUTH_TAG_BYTES
    }

    fn begin(&mut self) -> Vec<u8> {
        let mut request = vec![0u8; self.request_bytes];
        self.entropy.random_bytes(&mut request);
        self.entropy.random_bytes(&mut self.secret[..]);
        request
    }

    fn k_auth(&self) -> AuthSecret {
        self.secret.clone()
    }

    fn verify(&self, _transcript: &[u8], _tag: &[u8], _hqc_secret: &[u8]) -> Result<Vec<u8>> {
        Err(Error::ServerAuthenticationFailed)
    }
}

impl ClientAuth for Box<dyn ClientAuth> {
    fn request_bytes(&self) -> usize {
        (**self).request_bytes()
    }

    fn tag_bytes(&self) -> usize {
        (**self).tag_bytes()
    }

    fn begin(&mut self) -> Vec<u8> {
        (**self).begin()
    }

    fn k_auth(&self) -> AuthSecret {
        (**self).k_auth()
    }

    fn verify(&self, transcript: &[u8], tag: &[u8], hqc_secret: &[u8]) -> Result<Vec<u8>> {
        (**self).verify(transcript, tag, hqc_secret)
    }
}
