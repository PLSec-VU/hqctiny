use crate::error::{Error, Result};
use crate::hqc::{Hqc1, Hqc3, Hqc5};
use crate::limits::MAX_AUTH_CT_BYTES;
use crate::protocol::AuthCtBuf;
use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};
use libcrux_ml_kem::{ENCAPS_SEED_SIZE, KEY_GENERATION_SEED_SIZE};
use rand::Rng;
use std::marker::PhantomData;
use zeroize::Zeroizing;

const AUTH_KEY_CONTEXT: &str = "HQCLethe 2026-10 server auth key v1";
const AUTH_TAG_CONTEXT: &str = "HQCLethe 2026-10 server auth tag v1";
const JOINT_SECRET_CONTEXT: &str = "HQCLethe 2026-10 joint secret v1";

pub const AUTH_SECRET_BYTES: usize = 32;
pub const AUTH_TAG_BYTES: usize = 32;

pub type AuthSecret = Zeroizing<[u8; AUTH_SECRET_BYTES]>;

pub trait AuthKem {
    type SecretKey: Send + Sync;

    const PUBLIC_KEY_BYTES: usize;
    const SECRET_KEY_BYTES: usize;
    const CIPHERTEXT_BYTES: usize;

    fn keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>);
    fn encapsulate(pk: &[u8]) -> (AuthCtBuf, AuthSecret);
    fn load_secret_key(sk: &[u8]) -> Option<Self::SecretKey>;
    fn decapsulate(ct: &[u8], sk: &Self::SecretKey) -> AuthSecret;
}

/// Names the KEM paired with an HQC level.
pub trait AuthLevel: 'static {
    type Kem: AuthKem;
}

/// ML-KEM-768 from libcrux. Decapsulation works on fixed-size arrays and
/// never touches the heap.
pub struct MlKem768;

impl AuthKem for MlKem768 {
    type SecretKey = MlKem768PrivateKey;

    const PUBLIC_KEY_BYTES: usize = 1184;
    const SECRET_KEY_BYTES: usize = 2400;
    const CIPHERTEXT_BYTES: usize = 1088;

    fn keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
        let mut seed = Zeroizing::new([0u8; KEY_GENERATION_SEED_SIZE]);
        rand::rng().fill_bytes(&mut seed[..]);
        let keys = mlkem768::generate_key_pair(*seed);
        (keys.pk().to_vec(), Zeroizing::new(keys.sk().to_vec()))
    }

    fn encapsulate(pk: &[u8]) -> (AuthCtBuf, AuthSecret) {
        let public =
            MlKem768PublicKey::try_from(pk).expect("pinned public key has the declared size");
        assert!(
            mlkem768::validate_public_key(&public),
            "pinned public key is valid"
        );
        let mut seed = Zeroizing::new([0u8; ENCAPS_SEED_SIZE]);
        rand::rng().fill_bytes(&mut seed[..]);
        let (ct, shared) = mlkem768::encapsulate(&public, *seed);
        let ct = AuthCtBuf::from_slice(ct.as_slice(), Error::SerializationError)
            .expect("ciphertext fits MAX_AUTH_CT_BYTES");
        (ct, Zeroizing::new(shared))
    }

    fn load_secret_key(sk: &[u8]) -> Option<MlKem768PrivateKey> {
        let secret = MlKem768PrivateKey::try_from(sk).ok()?;
        mlkem768::portable::validate_private_key_only(&secret).then_some(secret)
    }

    fn decapsulate(ct: &[u8], sk: &MlKem768PrivateKey) -> AuthSecret {
        let ct = MlKem768Ciphertext::try_from(ct).expect("ciphertext has the declared length");
        Zeroizing::new(mlkem768::decapsulate(sk, &ct))
    }
}

impl AuthLevel for Hqc1 {
    type Kem = MlKem768;
}
impl AuthLevel for Hqc3 {
    type Kem = MlKem768;
}
impl AuthLevel for Hqc5 {
    type Kem = MlKem768;
}

const _: () = assert!(MlKem768::CIPHERTEXT_BYTES == MAX_AUTH_CT_BYTES);

pub fn auth_ciphertext_bytes<S: AuthLevel>() -> usize {
    S::Kem::CIPHERTEXT_BYTES
}

/// The server's long-term ML-KEM public key, pinned by the client.
pub struct ServerPublicKey<S: AuthLevel> {
    bytes: Vec<u8>,
    _level: PhantomData<fn() -> S>,
}

impl<S: AuthLevel> ServerPublicKey<S> {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() != S::Kem::PUBLIC_KEY_BYTES {
            return Err(Error::InvalidAuthKey);
        }
        Ok(Self {
            bytes,
            _level: PhantomData,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the ciphertext for the Phase-0 request and the shared secret
    /// only the holder of the matching secret key can recompute.
    pub fn encapsulate(&self) -> (AuthCtBuf, AuthSecret) {
        S::Kem::encapsulate(&self.bytes)
    }
}

/// The server's long-term ML-KEM secret key. Fixed size, loaded once.
pub struct ServerSecretKey<S: AuthLevel> {
    bytes: Zeroizing<Vec<u8>>,
    loaded: <S::Kem as AuthKem>::SecretKey,
    _level: PhantomData<fn() -> S>,
}

impl<S: AuthLevel> Clone for ServerSecretKey<S> {
    fn clone(&self) -> Self {
        Self::from_bytes(self.bytes.to_vec()).expect("a loaded key loads again")
    }
}

impl<S: AuthLevel> ServerSecretKey<S> {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let bytes = Zeroizing::new(bytes);
        if bytes.len() != S::Kem::SECRET_KEY_BYTES {
            return Err(Error::InvalidAuthKey);
        }
        let loaded = S::Kem::load_secret_key(&bytes).ok_or(Error::InvalidAuthKey)?;
        Ok(Self {
            bytes,
            loaded,
            _level: PhantomData,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Holds no per-client state. A wrong-length ciphertext is the only error:
    /// ML-KEM decapsulation otherwise returns a pseudorandom secret.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<AuthSecret> {
        if ct.len() != S::Kem::CIPHERTEXT_BYTES {
            return Err(Error::SerializationError);
        }
        Ok(S::Kem::decapsulate(ct, &self.loaded))
    }
}

pub struct ServerKeypair<S: AuthLevel> {
    pub public: ServerPublicKey<S>,
    pub secret: ServerSecretKey<S>,
}

impl<S: AuthLevel> ServerKeypair<S> {
    /// Slow: ML-KEM-768 key generation is fast.
    pub fn generate() -> Self {
        let (pk, sk) = S::Kem::keypair();
        Self {
            public: ServerPublicKey::from_bytes(pk).expect("keypair has the declared pk size"),
            secret: ServerSecretKey::from_bytes(sk.to_vec())
                .expect("keypair has the declared sk size"),
        }
    }
}

/// One keypair per level for the whole process, so tests and benchmarks pay
/// ML-KEM key generation once. A deployed server loads its key from a file.
pub fn shared_keypair<S: AuthLevel>() -> &'static ServerKeypair<S> {
    use std::any::{Any, TypeId};
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    static CACHE: OnceLock<Mutex<HashMap<TypeId, &'static (dyn Any + Send + Sync)>>> =
        OnceLock::new();
    let mut cache = CACHE.get_or_init(Default::default).lock().unwrap();
    let entry = cache.entry(TypeId::of::<S>()).or_insert_with(|| {
        let keys: &'static ServerKeypair<S> = Box::leak(Box::new(ServerKeypair::<S>::generate()));
        keys
    });
    entry
        .downcast_ref()
        .expect("cache entry matches its TypeId")
}

pub fn ciphertext_digest(auth_ct: &[u8]) -> [u8; 32] {
    *blake3::hash(auth_ct).as_bytes()
}

/// Folds the ML-KEM secret into the HQC secret. Session and transcript
/// keys derive from the result, so neither is computable without both.
pub fn bind_secret(k_hqc: &[u8], k_auth: &AuthSecret) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key(JOINT_SECRET_CONTEXT);
    hasher.update(&[k_hqc.len() as u8]);
    hasher.update(k_hqc);
    hasher.update(&k_auth[..]);
    Zeroizing::new(*hasher.finalize().as_bytes())
}

fn auth_tag_key(k_auth: &AuthSecret) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(AUTH_KEY_CONTEXT, &k_auth[..]))
}

pub fn auth_tag(k_auth: &AuthSecret, transcript: &[u8]) -> [u8; AUTH_TAG_BYTES] {
    let key = auth_tag_key(k_auth);
    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(AUTH_TAG_CONTEXT.as_bytes());
    hasher.update(transcript);
    *hasher.finalize().as_bytes()
}

pub fn verify_auth_tag(k_auth: &AuthSecret, transcript: &[u8], tag: &[u8; AUTH_TAG_BYTES]) -> bool {
    blake3::Hash::from_bytes(auth_tag(k_auth, transcript)) == blake3::Hash::from_bytes(*tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kem_roundtrip<S: AuthLevel>() {
        let keys = ServerKeypair::<S>::generate();
        let (ct, client_secret) = keys.public.encapsulate();
        assert_eq!(ct.len(), S::Kem::CIPHERTEXT_BYTES);
        let server_secret = keys.secret.decapsulate(&ct).unwrap();
        assert_eq!(*client_secret, *server_secret);
    }

    #[test]
    fn kem_roundtrip_hqc1() {
        kem_roundtrip::<Hqc1>();
    }

    #[test]
    fn kem_roundtrip_hqc3() {
        kem_roundtrip::<Hqc3>();
    }

    #[test]
    fn kem_roundtrip_hqc5() {
        kem_roundtrip::<Hqc5>();
    }

    #[test]
    fn wrong_secret_key_gives_unrelated_secret() {
        let honest = ServerKeypair::<Hqc1>::generate();
        let other = ServerKeypair::<Hqc1>::generate();
        let (ct, client_secret) = honest.public.encapsulate();
        let other_secret = other.secret.decapsulate(&ct).unwrap();
        assert_ne!(*client_secret, *other_secret);
    }

    #[test]
    fn wrong_length_ciphertext_is_rejected() {
        let keys = ServerKeypair::<Hqc1>::generate();
        assert!(keys.secret.decapsulate(&[0u8; 5]).is_err());
    }

    #[test]
    fn auth_tag_depends_on_secret_and_transcript() {
        let k = Zeroizing::new([1u8; 32]);
        let k2 = Zeroizing::new([2u8; 32]);
        let tag = auth_tag(&k, b"transcript");
        assert!(verify_auth_tag(&k, b"transcript", &tag));
        assert!(!verify_auth_tag(&k2, b"transcript", &tag));
        assert!(!verify_auth_tag(&k, b"transcripu", &tag));
    }

    #[test]
    fn bound_secret_depends_on_both_inputs() {
        let a = Zeroizing::new([1u8; 32]);
        let b = Zeroizing::new([2u8; 32]);
        assert_ne!(*bind_secret(&[7; 16], &a), *bind_secret(&[7; 16], &b));
        assert_ne!(*bind_secret(&[7; 16], &a), *bind_secret(&[8; 16], &a));
    }
}
