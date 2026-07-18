use crate::blinding;
use crate::encoding::public_eval_limbs;
use crate::error::{Error, Result};
use crate::hqc::{HqcMessageParameters, HqcScheme, HqcSharedSecretParameters};
use crate::limits::{MAX_COOKIE_PLAINTEXT_BYTES, MAX_PARAM_SECURITY_BYTES, MAX_VEC_N_SIZE_64};
use crate::math::gf2_9009::Gf2_9009;
use crate::math::segmentation::{evaluate_poly_at_generator, evaluate_sparse_poly_at_generator};
use crate::protocol::*;
use crate::traits::*;
use chacha20poly1305::{
    Tag, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use std::sync::{Arc, RwLock};
use zeroize::Zeroize;

/// Two-slot cookie-key ring. Rotating writes a fresh key into the inactive
/// slot and flips the active pointer, so a cookie issued under the previous
/// key stays decryptable for exactly one more rotation before its slot is
/// overwritten.
struct CookieKeys {
    current_idx: RwLock<u8>,
    keys: [RwLock<Option<[u8; 32]>>; 2],
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
    pub fn new(session_store: SStore, entropy_provider: E) -> Self {
        let mut k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        entropy_provider.random_bytes(&mut k0);
        entropy_provider.random_bytes(&mut k1);
        Self {
            session_store,
            entropy_provider,
            cookie_keys: Arc::new(CookieKeys {
                current_idx: RwLock::new(0),
                keys: [RwLock::new(Some(k0)), RwLock::new(Some(k1))],
            }),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Rotates the cookie-encryption key: generates a fresh key, writes it
    /// into the currently-inactive slot, and makes that slot active. Call
    /// this on a fixed interval (every 90 seconds) from the deployment's
    /// own timer/thread — it's the only key-management API the server
    /// exposes.
    pub fn rotate(&self) -> u8 {
        let mut idx_guard = self.cookie_keys.current_idx.write().unwrap();
        let next_idx = (*idx_guard + 1) % 2;
        let mut new_key = [0u8; 32];
        self.entropy_provider.random_bytes(&mut new_key);
        *self.cookie_keys.keys[next_idx as usize].write().unwrap() = Some(new_key);
        *idx_guard = next_idx;
        next_idx
    }

    fn current_key_index(&self) -> u8 {
        *self.cookie_keys.current_idx.read().unwrap()
    }

    fn get_key(&self, index: u8) -> Option<[u8; 32]> {
        if index > 1 {
            return None;
        }
        *self.cookie_keys.keys[index as usize].read().unwrap()
    }

    /// Builds `nonce(24) || AEAD-ciphertext(plaintext) || tag(16)` directly
    /// in a stack buffer via `AeadInPlace`, rather than the `Aead` trait's
    /// `Vec`-returning `encrypt`, so encrypting a cookie never allocates.
    fn encrypt_cookie(&self, plaintext: &[u8], merkle_root: &[u8; 32]) -> Result<(CookieBuf, u8)> {
        let key_index = self.current_key_index();
        let key = self.get_key(key_index).ok_or(Error::EncryptionError)?;

        let mut nonce_bytes = [0u8; 24];
        self.entropy_provider.random_bytes(&mut nonce_bytes);

        let total = 24 + plaintext.len() + 16;
        let mut buf = [0u8; crate::limits::MAX_COOKIE_BYTES];
        buf[..24].copy_from_slice(&nonce_bytes);
        buf[24..24 + plaintext.len()].copy_from_slice(plaintext);

        let cipher = XChaCha20Poly1305::new(&key.into());
        let tag = cipher
            .encrypt_in_place_detached(
                XNonce::from_slice(&nonce_bytes),
                merkle_root,
                &mut buf[24..24 + plaintext.len()],
            )
            .map_err(|_| Error::EncryptionError)?;
        buf[24 + plaintext.len()..total].copy_from_slice(&tag);

        let cookie = CookieBuf::from_slice(&buf[..total], Error::EncryptionError)?;
        Ok((cookie, key_index))
    }

    /// Decrypts in place into a fixed-size stack buffer via `AeadInPlace`,
    /// rather than the `Aead` trait's `Vec`-returning `decrypt`. Returns
    /// the buffer plus the actual plaintext length (`theta || m`, at most
    /// `MAX_COOKIE_PLAINTEXT_BYTES`).
    fn decrypt_cookie(
        &self,
        cookie: &[u8],
        key_index: u8,
        merkle_root: &[u8; 32],
    ) -> Result<([u8; MAX_COOKIE_PLAINTEXT_BYTES], usize)> {
        if cookie.len() < 24 + 16 {
            return Err(Error::InvalidCookieLength);
        }
        let pt_len = cookie.len() - 24 - 16;
        if pt_len > MAX_COOKIE_PLAINTEXT_BYTES {
            return Err(Error::InvalidCookieLength);
        }

        let key = self.get_key(key_index).ok_or(Error::SessionExpired)?;

        let nonce_bytes = &cookie[..24];
        let tag_start = 24 + pt_len;
        let tag = Tag::from_slice(&cookie[tag_start..]);

        let mut buf = [0u8; MAX_COOKIE_PLAINTEXT_BYTES];
        buf[..pt_len].copy_from_slice(&cookie[24..tag_start]);

        let cipher = XChaCha20Poly1305::new(&key.into());
        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(nonce_bytes),
                merkle_root,
                &mut buf[..pt_len],
                tag,
            )
            .map_err(|_| Error::DecryptionError)?;

        Ok((buf, pt_len))
    }

    pub fn handle_handshake(&self, req: HandshakeRequest) -> Result<HandshakeResponse> {
        let sec_bytes = SCHEME::PARAM_SECURITY_BYTES;
        let mut m_buf = [0u8; MAX_PARAM_SECURITY_BYTES];
        let m = &mut m_buf[..sec_bytes];
        self.entropy_provider.random_bytes(m);

        let mut salt = [0u8; 16];
        self.entropy_provider.random_bytes(&mut salt);

        let ss_params = SCHEME::derive_shared_secret(m, &salt, &req.hash_ek_kem);
        let theta = ss_params.theta();

        let mut k_session = crate::kdf::derive_session_key(ss_params.K());
        let mut k_transcript = crate::kdf::derive_transcript_key(ss_params.K());

        self.session_store.save_session(k_session);
        k_session.zeroize();

        let pt_len = 32 + sec_bytes;
        let mut plaintext = [0u8; MAX_COOKIE_PLAINTEXT_BYTES];
        plaintext[..32].copy_from_slice(theta);
        plaintext[32..pt_len].copy_from_slice(m);
        m_buf.zeroize();

        let result = self
            .encrypt_cookie(&plaintext[..pt_len], &req.merkle_root)
            .map(|(cookie, key_index)| {
                let transcript = crate::kdf::compute_transcript(
                    &req.hash_ek_kem,
                    &req.merkle_root,
                    &salt,
                    key_index,
                );
                let mac = crate::kdf::confirmation_tag(&k_transcript, &transcript);
                HandshakeResponse {
                    cookie,
                    salt,
                    key_index,
                    mac,
                }
            });
        plaintext.zeroize();
        k_transcript.zeroize();
        result
    }

    pub fn handle_point_request(&self, req: PointRequest) -> Result<PointResponse> {
        let points_num = SCHEME::POINTS_NUM;

        if req.point_index == 0 || req.point_index as usize > points_num {
            return Err(Error::InvalidPointIndex);
        }

        // Validate merkle_root using cookie's AAD
        let (mut plaintext, pt_len) =
            self.decrypt_cookie(&req.cookie, req.key_index, &req.merkle_root)?;
        if pt_len != 32 + SCHEME::PARAM_SECURITY_BYTES {
            return Err(Error::InvalidCookie);
        }

        // Validate Merkle proof for the public evaluation point
        let leaf_bytes = serialize_point_leaf(req.point_index, req.point_type, &req.public_eval);
        let leaf_hash = Blake3Algorithm::hash(&leaf_bytes);

        let index = match req.point_type {
            PointType::U => (req.point_index as usize - 1) * 2,
            PointType::V => (req.point_index as usize - 1) * 2 + 1,
        };
        let total_leaves = SCHEME::POINTS_NUM * 2;
        if !crate::merkle::verify_proof(
            &req.merkle_root,
            index,
            leaf_hash,
            &req.witness,
            total_leaves,
        ) {
            return Err(Error::MerkleVerificationFailed);
        }

        let mut theta = [0u8; 32];
        theta.copy_from_slice(&plaintext[..32]);
        let m = &plaintext[32..pt_len];

        let n = SCHEME::PARAM_N;
        let n_words = SCHEME::VEC_N_SIZE_64;
        let num_deltas = blinding::num_kernel_deltas(n);
        let power = req.point_index;
        // Bound shared by public_eval (wire-limited) and every evaluation
        // result below (degree < w + POINTS_NUM*(num_blocks-1), see
        // `evaluate_poly_at_generator`'s doc comment) — lets the one full
        // field multiply per branch run on ~eff_words limbs instead of 141.
        let eff_words = public_eval_limbs::<SCHEME>();

        // The quotient masks and kernel deltas of u and v must be mutually
        // independent (HQCLethe.v samples them separately); a shared mask
        // would cancel in u XOR v and leak the message.
        let eval = match req.point_type {
            PointType::U => {
                let msg_params = SCHEME::partial_message_encaps(m, &theta);

                // r1/r2 are fixed-weight (omega_r ones out of n bits): scanning
                // set bits is cheaper than a dense block-by-block evaluation.
                let mut r2_xi = Gf2_9009::zero();
                evaluate_sparse_poly_at_generator(msg_params.r2(), power, &mut r2_xi);

                let mut mask_poly_buf = [0u64; MAX_VEC_N_SIZE_64];
                let mask_poly = &mut mask_poly_buf[..n_words];
                blinding::generate_quotient_mask(&theta, b"quotient mask u", n, mask_poly);
                let mut mask_xi = Gf2_9009::zero();
                evaluate_poly_at_generator(mask_poly, power, &mut mask_xi);

                let mut r1_xi = Gf2_9009::zero();
                evaluate_sparse_poly_at_generator(msg_params.r1(), power, &mut r1_xi);

                let mut u_xi = r1_xi;
                let mut term_u = req.public_eval;
                term_u.mul_bounded(&r2_xi, eff_words);
                u_xi.add(&term_u);

                let mut term_mask = mask_xi;
                crate::math::modulus_points::mul_by_modulus_point::<SCHEME>(
                    &mut term_mask,
                    req.point_index as usize,
                );
                u_xi.add(&term_mask);

                u_xi.add(&blinding::evaluate_kernel_deltas_at_generator(
                    &theta,
                    b"kernel deltas u",
                    num_deltas,
                    power as usize,
                ));
                u_xi
            }
            PointType::V => {
                // partial_message_encaps_v samples only r2 and e; r1 is last in the XOF
                // stream and unused for V-type responses.
                let msg_params = SCHEME::partial_message_encaps_v(m, &theta);

                let mut r2_xi = Gf2_9009::zero();
                evaluate_sparse_poly_at_generator(msg_params.r2(), power, &mut r2_xi);

                let mut scratch_buf = [0u64; MAX_VEC_N_SIZE_64];
                let scratch = &mut scratch_buf[..n_words];
                blinding::generate_quotient_mask(&theta, b"quotient mask v", n, scratch);
                let mut mask_xi = Gf2_9009::zero();
                evaluate_poly_at_generator(scratch, power, &mut mask_xi);

                // Reuse the scratch buffer for k_encoded: mask_poly evaluation is
                // complete so the buffer contents no longer matter.
                scratch.fill(0);
                SCHEME::code_encode(scratch, m);
                let mut k_xi = Gf2_9009::zero();
                evaluate_poly_at_generator(scratch, power, &mut k_xi);

                // e is fixed-weight (omega_e ones), same sparse fast path as r1/r2.
                let mut e_xi = Gf2_9009::zero();
                evaluate_sparse_poly_at_generator(msg_params.e(), power, &mut e_xi);

                let mut t_xi = Gf2_9009::zero();
                blinding::evaluate_truncate_mask_at_generator(
                    &theta,
                    b"truncate mask",
                    n,
                    SCHEME::PARAM_N1N2,
                    power,
                    &mut t_xi,
                );

                let mut v_xi = k_xi;
                let mut term_v = req.public_eval;
                term_v.mul_bounded(&r2_xi, eff_words);
                v_xi.add(&term_v);
                v_xi.add(&e_xi);
                v_xi.add(&t_xi);

                let mut term_mask = mask_xi;
                crate::math::modulus_points::mul_by_modulus_point::<SCHEME>(
                    &mut term_mask,
                    req.point_index as usize,
                );
                v_xi.add(&term_mask);

                v_xi.add(&blinding::evaluate_kernel_deltas_at_generator(
                    &theta,
                    b"kernel deltas v",
                    num_deltas,
                    power as usize,
                ));
                v_xi
            }
        };

        theta.zeroize();
        plaintext.zeroize();

        Ok(PointResponse {
            point_index: req.point_index,
            point_type: req.point_type,
            eval,
        })
    }
}
