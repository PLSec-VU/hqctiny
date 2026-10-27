use crate::auth::{self, AuthSecret, ServerSecretKey};
use crate::crt;
use crate::encoding::{
    self, GAMMA_BYTES, Header, Kind, RequestView, SALT_BYTES, cookie_len, cookie_plaintext_len,
    uchunk_payload_len,
};
use crate::envelope::{NONCE_BYTES, Nonce, SessionKeys};
use crate::error::{Error, Result};
use crate::hqc::{HqcScheme, HqcSharedSecretParameters};
use crate::limits::{
    MAX_COOKIE_PLAINTEXT_BYTES, MAX_PARAM_SECURITY_BYTES, MAX_REQUEST_PAYLOAD_BYTES,
    PUZZLE_MAX_AGE_SECS,
};
use crate::puzzle::{self, Challenge, NONCE_BYTES as PUZZLE_NONCE_BYTES, PeerAddress};
use crate::replay::{Fingerprint, FingerprintKey, ReplayFilter, ReplaySizing};
use crate::traits::*;
use chacha20poly1305::{
    Tag, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use std::cell::RefCell;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use std::sync::{Arc, RwLock, RwLockWriteGuard};

const COOKIE_AAD: &[u8] = &[];
const PUZZLES_OFF: u8 = 0;
use zeroize::{Zeroize, Zeroizing};

/// Two-slot cookie-key ring. Rotation `r` writes a fresh key into slot
/// `r % 2` and then makes it the active slot, so a cookie issued under the
/// previous key stays decryptable for exactly one more rotation before its
/// slot is overwritten. The replay filter starts a new generation at every
/// rotation, so it remembers a request for as long as its cookie opens.
struct CookieKeys {
    rotations: AtomicU32,
    rotating: std::sync::Mutex<()>,
    keys: [RwLock<Option<[u8; 32]>>; 2],
}

impl CookieKeys {
    fn active_slot(rotations: u32) -> u8 {
        (rotations % 2) as u8
    }

    fn publish_rotations_while_key_is_locked(
        &self,
        _new_key: &RwLockWriteGuard<'_, Option<[u8; 32]>>,
        rotations: u32,
    ) {
        self.rotations.store(rotations, Ordering::Release);
    }
}

pub struct Server<SCHEME, SStore, E>
where
    SCHEME: HqcScheme,
    SStore: SessionStore,
    E: EntropyProvider,
{
    pub session_store: SStore,
    pub entropy_provider: E,
    cookie_keys: Arc<CookieKeys>,
    auth_key: Arc<ServerSecretKey<SCHEME>>,
    puzzle_difficulty: Arc<AtomicU8>,
    puzzle_max_age_secs: u32,
    clock: Arc<dyn Clock>,
    replay: Option<RefCell<ReplayFilter>>,
    // `fn() -> SCHEME` rather than `SCHEME` so PhantomData's Send/Sync stay
    // unconditional — SCHEME is a zero-sized marker type, never touched by
    // value, but a bare `PhantomData<SCHEME>` would still force SCHEME: Send
    // onto the rotation thread in hqclethe-server that clones Server across it.
    _phantom: std::marker::PhantomData<fn() -> SCHEME>,
}

impl<SCHEME, SStore, E> Clone for Server<SCHEME, SStore, E>
where
    SCHEME: HqcScheme,
    SStore: SessionStore + Clone,
    E: EntropyProvider + Clone,
{
    fn clone(&self) -> Self {
        Self {
            session_store: self.session_store.clone(),
            entropy_provider: self.entropy_provider.clone(),
            cookie_keys: self.cookie_keys.clone(),
            auth_key: self.auth_key.clone(),
            puzzle_difficulty: self.puzzle_difficulty.clone(),
            puzzle_max_age_secs: self.puzzle_max_age_secs,
            clock: self.clock.clone(),
            replay: self
                .replay
                .as_ref()
                .map(|filter| RefCell::new(filter.borrow().empty_like())),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<SCHEME, SStore, E> Server<SCHEME, SStore, E>
where
    SCHEME: HqcScheme,
    SStore: SessionStore,
    E: EntropyProvider,
{
    pub fn new(
        session_store: SStore,
        entropy_provider: E,
        auth_key: ServerSecretKey<SCHEME>,
    ) -> Self {
        let mut k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        entropy_provider.random_bytes(&mut k0);
        entropy_provider.random_bytes(&mut k1);
        Self {
            session_store,
            entropy_provider,
            cookie_keys: Arc::new(CookieKeys {
                rotations: AtomicU32::new(0),
                rotating: std::sync::Mutex::new(()),
                keys: [RwLock::new(Some(k0)), RwLock::new(Some(k1))],
            }),
            auth_key: Arc::new(auth_key),
            puzzle_difficulty: Arc::new(AtomicU8::new(PUZZLES_OFF)),
            puzzle_max_age_secs: PUZZLE_MAX_AGE_SECS,
            clock: Arc::new(SystemClock),
            replay: None,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn with_puzzle_difficulty(self, difficulty: u8) -> Self {
        self.set_puzzle_difficulty(difficulty);
        self
    }

    pub fn with_puzzle_max_age_secs(mut self, secs: u32) -> Self {
        self.puzzle_max_age_secs = secs;
        self
    }

    pub fn with_replay_filter(mut self, sizing: ReplaySizing) -> Self {
        let mut key: FingerprintKey = Default::default();
        self.entropy_provider.random_bytes(&mut key);
        self.replay = Some(RefCell::new(ReplayFilter::new(sizing, key)));
        self
    }

    pub fn replay_sizing(&self) -> Option<ReplaySizing> {
        self.replay.as_ref().map(|filter| *filter.borrow().sizing())
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Takes effect for the next request, on every clone of this server.
    pub fn set_puzzle_difficulty(&self, difficulty: u8) {
        self.puzzle_difficulty.store(difficulty, Ordering::Relaxed);
    }

    pub fn puzzle_difficulty(&self) -> u8 {
        self.puzzle_difficulty.load(Ordering::Relaxed)
    }

    /// Rotates the cookie-encryption key: generates a fresh key, writes it
    /// into the currently-inactive slot, and makes that slot active. Call
    /// this every `limits::COOKIE_ROTATION_SECS` seconds from the
    /// deployment's own timer/thread; it is the only key-management API the
    /// server exposes.
    pub fn rotate(&self) -> u8 {
        let _one_rotation_at_a_time = self.cookie_keys.rotating.lock().unwrap();
        let next_rotations = self.cookie_rotations().wrapping_add(1);
        let next_idx = CookieKeys::active_slot(next_rotations);
        let mut new_key = [0u8; 32];
        self.entropy_provider.random_bytes(&mut new_key);
        let mut slot = self.cookie_keys.keys[next_idx as usize].write().unwrap();
        *slot = Some(new_key);
        self.cookie_keys
            .publish_rotations_while_key_is_locked(&slot, next_rotations);
        next_idx
    }

    pub fn cookie_rotations(&self) -> u32 {
        self.cookie_keys.rotations.load(Ordering::Acquire)
    }

    fn current_key_index(&self) -> u8 {
        CookieKeys::active_slot(self.cookie_rotations())
    }

    fn get_key(&self, index: u8) -> Option<[u8; 32]> {
        if index > 1 {
            return None;
        }
        *self.cookie_keys.keys[index as usize].read().unwrap()
    }

    /// Writes `nonce(24) || AEAD-ciphertext(plaintext) || tag(16)` into `dst`
    /// through `AeadInPlace`, so encrypting a cookie never allocates. Returns
    /// the key index the cookie is sealed under.
    fn encrypt_cookie(&self, plaintext: &[u8], nonce: &Nonce, dst: &mut [u8]) -> Result<u8> {
        let key_index = self.current_key_index();
        let key = self.get_key(key_index).ok_or(Error::EncryptionError)?;

        let total = NONCE_BYTES + plaintext.len() + 16;
        let dst = dst.get_mut(..total).ok_or(Error::EncryptionError)?;
        let (nonce_bytes, body) = dst.split_at_mut(NONCE_BYTES);
        nonce_bytes.copy_from_slice(nonce);
        let (ciphertext, tag_out) = body.split_at_mut(plaintext.len());
        ciphertext.copy_from_slice(plaintext);

        let cipher = XChaCha20Poly1305::new(&key.into());
        let tag = cipher
            .encrypt_in_place_detached(XNonce::from_slice(nonce_bytes), COOKIE_AAD, ciphertext)
            .map_err(|_| Error::EncryptionError)?;
        tag_out.copy_from_slice(&tag);
        Ok(key_index)
    }

    /// Decrypts in place into a fixed-size stack buffer via `AeadInPlace`,
    /// rather than the `Aead` trait's `Vec`-returning `decrypt`. `Zeroizing`
    /// because callers reject requests between decrypting and consuming the
    /// cookie, on paths an attacker picks.
    fn decrypt_cookie(
        &self,
        cookie: &[u8],
        key_index: u8,
    ) -> Result<Zeroizing<[u8; MAX_COOKIE_PLAINTEXT_BYTES]>> {
        let pt_len = cookie_plaintext_len::<SCHEME>();
        if cookie.len() != cookie_len::<SCHEME>() {
            return Err(Error::InvalidCookieLength);
        }

        let key = self.get_key(key_index).ok_or(Error::SessionExpired)?;

        let nonce_bytes = &cookie[..NONCE_BYTES];
        let tag_start = NONCE_BYTES + pt_len;
        let tag = Tag::from_slice(&cookie[tag_start..]);

        let mut buf = Zeroizing::new([0u8; MAX_COOKIE_PLAINTEXT_BYTES]);
        buf[..pt_len].copy_from_slice(&cookie[NONCE_BYTES..tag_start]);

        let cipher = XChaCha20Poly1305::new(&key.into());
        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(nonce_bytes),
                COOKIE_AAD,
                &mut buf[..pt_len],
                tag,
            )
            .map_err(|_| Error::DecryptionError)?;

        Ok(buf)
    }

    fn fresh_nonce(&self) -> Nonce {
        let mut nonce = [0u8; NONCE_BYTES];
        self.entropy_provider.random_bytes(&mut nonce);
        nonce
    }

    pub fn handle_packet(&self, peer: IpAddr, request: &[u8], out: &mut [u8]) -> Result<usize> {
        match Header::decode(request)?.kind {
            Kind::Handshake => self.handle_handshake(peer, request, out),
            Kind::SolvedHandshake => self.handle_solved_handshake(peer, request, out),
            Kind::Challenge => Err(Error::SerializationError),
            Kind::UChunk => self.handle_uchunk(request, out),
            Kind::VResidue => self.handle_vresidue(request, out),
        }
    }

    pub fn handle_handshake(&self, peer: IpAddr, request: &[u8], out: &mut [u8]) -> Result<usize> {
        let view = encoding::parse_handshake_request::<SCHEME>(request)?;
        if self.puzzle_difficulty() != PUZZLES_OFF {
            return self.issue_challenge(&puzzle::peer_address(peer), out);
        }
        let request_digest = crate::kdf::request_digest(view.body);
        let coins = HandshakeCoins::fresh::<SCHEME>(&self.entropy_provider);
        self.complete_handshake(&view, &request_digest, &coins, out)
    }

    pub fn handle_solved_handshake(
        &self,
        peer: IpAddr,
        request: &[u8],
        out: &mut [u8],
    ) -> Result<usize> {
        let solved = encoding::parse_solved_handshake_request::<SCHEME>(request)?;
        let challenge_key = self.read_challenge_key(solved.key_index)?;
        let request_digest =
            self.verify_puzzle_solution(&puzzle::peer_address(peer), &solved, &challenge_key)?;
        self.admit_solved_handshake(&solved.challenge, challenge_key.admission_rotations)?;
        let coins = HandshakeCoins::derived(
            &challenge_key.coins_key(),
            &solved.challenge.nonce,
            &request_digest,
        );
        self.complete_handshake(&solved.request, &request_digest, &coins, out)
    }

    fn read_challenge_key(&self, key_index: u8) -> Result<ChallengeKey> {
        let admission_rotations = self.cookie_rotations();
        let cookie_key = self.get_key(key_index).ok_or(Error::SessionExpired)?;
        Ok(ChallengeKey {
            cookie_key: Zeroizing::new(cookie_key),
            admission_rotations,
        })
    }

    fn puzzle_mac_key(&self, key_index: u8) -> Result<puzzle::MacKey> {
        let cookie_key = self.get_key(key_index).ok_or(Error::SessionExpired)?;
        Ok(puzzle::mac_key(&cookie_key))
    }

    fn issue_challenge(&self, peer: &PeerAddress, out: &mut [u8]) -> Result<usize> {
        let key_index = self.current_key_index();
        let mac_key = self.puzzle_mac_key(key_index)?;
        let mut nonce = [0u8; PUZZLE_NONCE_BYTES];
        self.entropy_provider.random_bytes(&mut nonce);
        let challenge = Challenge::issue(
            &mac_key,
            peer,
            nonce,
            self.puzzle_difficulty(),
            self.clock.unix_seconds(),
        );
        encoding::write_challenge_response(out, key_index, &challenge, peer)
    }

    fn verify_puzzle_solution(
        &self,
        peer: &PeerAddress,
        solved: &encoding::SolvedHandshakeView<'_>,
        challenge_key: &ChallengeKey,
    ) -> Result<puzzle::Digest> {
        let required = self.puzzle_difficulty();
        let challenge = &solved.challenge;
        if challenge.difficulty < required {
            return Err(Error::InsufficientPuzzleDifficulty);
        }
        if !puzzle::is_fresh(
            challenge.timestamp,
            self.clock.unix_seconds(),
            self.puzzle_max_age_secs,
        ) {
            return Err(Error::StalePuzzle);
        }
        if !challenge.is_authentic(&challenge_key.mac_key(), peer) {
            return Err(Error::InvalidPuzzleMac);
        }
        let request_digest = crate::kdf::request_digest(solved.request.body);
        if !puzzle::is_solution(challenge, peer, &request_digest, solved.counter) {
            return Err(Error::InvalidPuzzleSolution);
        }
        Ok(request_digest)
    }

    fn complete_handshake(
        &self,
        view: &encoding::HandshakeRequestView<'_>,
        request_digest: &puzzle::Digest,
        coins: &HandshakeCoins,
        out: &mut [u8],
    ) -> Result<usize> {
        let k_auth = self.auth_key.decapsulate(view.auth_ct)?;

        let m = coins.m::<SCHEME>();
        let salt = &coins.salt;

        let ss_params = SCHEME::derive_shared_secret(m, salt, view.hash_ek_kem);
        let theta = ss_params.theta();

        let k_joint = auth::bind_secret(ss_params.K(), &k_auth);
        let mut k_session = crate::kdf::derive_session_key(&*k_joint);
        let mut k_transcript = crate::kdf::derive_transcript_key(&*k_joint);

        self.session_store.save_session(k_session);
        k_session.zeroize();

        let layout = CookieLayout::of::<SCHEME>();
        let mut plaintext = [0u8; MAX_COOKIE_PLAINTEXT_BYTES];
        plaintext[layout.theta()].copy_from_slice(theta);
        plaintext[layout.m()].copy_from_slice(m);
        plaintext[layout.h_seed()].copy_from_slice(view.h_seed);
        plaintext[layout.k_auth()].copy_from_slice(&k_auth[..]);

        let payload_len = encoding::handshake_response_payload_len::<SCHEME>();
        let payload = encoding::response_payload_mut(out, payload_len);
        let cookie_bytes = cookie_len::<SCHEME>();
        let sealed = self.encrypt_cookie(
            &plaintext[..layout.len],
            &coins.cookie_nonce,
            &mut payload[..cookie_bytes],
        );
        plaintext.zeroize();
        let key_index = sealed?;

        let transcript = crate::kdf::compute_transcript(request_digest, salt, key_index);
        let gamma = crate::kdf::confirmation_tag(&k_transcript, &transcript);
        k_transcript.zeroize();
        payload[cookie_bytes..cookie_bytes + SALT_BYTES].copy_from_slice(salt);
        payload[cookie_bytes + SALT_BYTES..cookie_bytes + SALT_BYTES + GAMMA_BYTES]
            .copy_from_slice(&gamma);

        let keys = SessionKeys::derive(&k_auth);
        encoding::finish_response(
            out,
            Header::response(Kind::Handshake, key_index, 0),
            payload_len,
            request_digest,
            &keys.server_to_client,
            &self.fresh_nonce(),
        )
    }

    fn open_request<'a>(&self, request: &'a [u8], kind: Kind) -> Result<OpenedRequest<'a>> {
        let view = encoding::parse_request::<SCHEME>(request)?;
        if view.header.kind != kind {
            return Err(Error::SerializationError);
        }
        let cookie = self.decrypt_cookie(view.cookie, view.header.key_index)?;
        let layout = CookieLayout::of::<SCHEME>();
        let k_auth: AuthSecret = Zeroizing::new(
            cookie[layout.k_auth()]
                .try_into()
                .map_err(|_| Error::InvalidCookie)?,
        );
        let keys = SessionKeys::derive(&k_auth);
        let mut payload = [0u8; MAX_REQUEST_PAYLOAD_BYTES];
        let payload_len = encoding::open_request(&view, &keys.client_to_server, &mut payload)?;
        self.admit_request(&view)?;
        Ok(OpenedRequest {
            view,
            cookie,
            keys,
            payload,
            payload_len,
        })
    }

    fn admit_request(&self, view: &RequestView<'_>) -> Result<()> {
        self.admit(self.cookie_rotations(), |filter| {
            filter.fingerprint(
                view.cookie_nonce(),
                view.header.kind as u8,
                view.header.index,
            )
        })
    }

    fn admit_solved_handshake(&self, challenge: &Challenge, cookie_rotations: u32) -> Result<()> {
        self.admit(cookie_rotations, |filter| {
            filter.challenge_fingerprint(&challenge.nonce)
        })
    }

    fn admit(
        &self,
        cookie_rotations: u32,
        fingerprint_of: impl FnOnce(&ReplayFilter) -> Fingerprint,
    ) -> Result<()> {
        let Some(filter) = &self.replay else {
            return Ok(());
        };
        let mut filter = filter.borrow_mut();
        let fingerprint = fingerprint_of(&filter);
        if filter.admit(&fingerprint, cookie_rotations).is_admitted() {
            Ok(())
        } else {
            Err(Error::ReplayedRequest)
        }
    }

    pub fn handle_uchunk(&self, request: &[u8], out: &mut [u8]) -> Result<usize> {
        let opened = self.open_request(request, Kind::UChunk)?;
        let chunk_index = opened.view.header.index as usize;
        let layout = CookieLayout::of::<SCHEME>();

        let chunk_len = uchunk_payload_len::<SCHEME>(chunk_index);
        let start = chunk_index * encoding::UCHUNK_MAX_BYTES;
        SCHEME::compute_u_window(
            &opened.cookie[layout.h_seed()],
            &opened.cookie[layout.theta()],
            start,
            encoding::response_payload_mut(out, chunk_len),
        );
        encoding::finish_response(
            out,
            Header::response(Kind::UChunk, 0, chunk_index as u8),
            chunk_len,
            &[],
            &opened.keys.server_to_client,
            &self.fresh_nonce(),
        )
    }

    pub fn handle_vresidue(&self, request: &[u8], out: &mut [u8]) -> Result<usize> {
        let opened = self.open_request(request, Kind::VResidue)?;
        let index = opened.view.header.index;
        let modulus = SCHEME::CRT_MODULI[index as usize];
        let payload = &opened.payload[..opened.payload_len];
        if !crt::params::residue_is_canonical(payload, modulus) {
            return Err(Error::SerializationError);
        }
        let layout = CookieLayout::of::<SCHEME>();

        let mut s_residue = [0u64; crt::MAX_RESIDUE_WORDS];
        crt::params::words_from_residue_bytes(
            &payload[..modulus.residue_bytes()],
            modulus,
            &mut s_residue,
        );
        let mut residue = [0u64; crt::MAX_RESIDUE_WORDS];
        crt::server::masked_residue::<SCHEME>(
            &opened.cookie[layout.theta()],
            &opened.cookie[layout.m()],
            modulus,
            &s_residue,
            &mut residue,
        );
        let reply_len = modulus.residue_bytes();
        crt::params::residue_bytes_from_words(
            &residue,
            modulus,
            encoding::response_payload_mut(out, reply_len),
        );
        encoding::finish_response(
            out,
            Header::response(Kind::VResidue, 0, index),
            reply_len,
            &[],
            &opened.keys.server_to_client,
            &self.fresh_nonce(),
        )
    }
}

struct ChallengeKey {
    cookie_key: Zeroizing<[u8; 32]>,
    admission_rotations: u32,
}

impl ChallengeKey {
    fn mac_key(&self) -> puzzle::MacKey {
        puzzle::mac_key(&self.cookie_key)
    }

    fn coins_key(&self) -> puzzle::CoinsKey {
        puzzle::coins_key(&self.cookie_key)
    }
}

const HANDSHAKE_COINS_BYTES: usize = MAX_PARAM_SECURITY_BYTES + SALT_BYTES + NONCE_BYTES;

struct HandshakeCoins {
    m: [u8; MAX_PARAM_SECURITY_BYTES],
    salt: [u8; SALT_BYTES],
    cookie_nonce: Nonce,
}

impl HandshakeCoins {
    fn fresh<S: HqcScheme>(entropy: &impl EntropyProvider) -> Self {
        let mut coins = Self {
            m: [0; MAX_PARAM_SECURITY_BYTES],
            salt: [0; SALT_BYTES],
            cookie_nonce: [0; NONCE_BYTES],
        };
        entropy.random_bytes(&mut coins.m[..S::PARAM_SECURITY_BYTES]);
        entropy.random_bytes(&mut coins.salt);
        entropy.random_bytes(&mut coins.cookie_nonce);
        coins
    }

    fn derived(
        key: &puzzle::CoinsKey,
        challenge_nonce: &[u8; PUZZLE_NONCE_BYTES],
        request_digest: &puzzle::Digest,
    ) -> Self {
        let mut stream = Zeroizing::new([0u8; HANDSHAKE_COINS_BYTES]);
        puzzle::fill_handshake_coins(key, challenge_nonce, request_digest, &mut stream[..]);
        let (m, rest) = stream.split_at(MAX_PARAM_SECURITY_BYTES);
        let (salt, cookie_nonce) = rest.split_at(SALT_BYTES);
        Self {
            m: m.try_into().expect("split at the m length"),
            salt: salt.try_into().expect("split at the salt length"),
            cookie_nonce: cookie_nonce.try_into().expect("the rest is the nonce"),
        }
    }

    fn m<S: HqcScheme>(&self) -> &[u8] {
        &self.m[..S::PARAM_SECURITY_BYTES]
    }
}

impl Drop for HandshakeCoins {
    fn drop(&mut self) {
        self.m.zeroize();
    }
}

struct OpenedRequest<'a> {
    view: RequestView<'a>,
    cookie: Zeroizing<[u8; MAX_COOKIE_PLAINTEXT_BYTES]>,
    keys: SessionKeys,
    payload: [u8; MAX_REQUEST_PAYLOAD_BYTES],
    payload_len: usize,
}

impl Drop for OpenedRequest<'_> {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}

/// Byte ranges of `theta || m || h_seed || k_auth` in the cookie plaintext.
struct CookieLayout {
    m_len: usize,
    len: usize,
}

impl CookieLayout {
    fn of<S: HqcScheme>() -> Self {
        Self {
            m_len: S::PARAM_SECURITY_BYTES,
            len: cookie_plaintext_len::<S>(),
        }
    }

    fn theta(&self) -> std::ops::Range<usize> {
        0..32
    }

    fn m(&self) -> std::ops::Range<usize> {
        32..32 + self.m_len
    }

    fn h_seed(&self) -> std::ops::Range<usize> {
        self.m().end..self.m().end + 32
    }

    fn k_auth(&self) -> std::ops::Range<usize> {
        self.h_seed().end..self.len
    }
}
