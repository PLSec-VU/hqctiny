use crate::blinding;
use crate::encoding::public_eval_limbs;
use crate::error::{Error, Result};
use crate::hqc::{HqcMessageParameters, HqcScheme, HqcSharedSecretParameters};
use crate::math::gf2_9009::Gf2_9009;
use crate::math::segmentation::{evaluate_poly_at_generator, evaluate_sparse_poly_at_generator};
use crate::protocol::*;
use crate::traits::*;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use zeroize::Zeroize;

pub struct Server<SCHEME, SStore, E, KProvider>
where
    SCHEME: HqcScheme,
    SStore: SessionStore,
    E: EntropyProvider,
    KProvider: CookieKeyProvider,
{
    pub session_store: SStore,
    pub entropy_provider: E,
    pub key_provider: KProvider,
    _phantom: std::marker::PhantomData<SCHEME>,
}

impl<SCHEME, SStore, E, KProvider> Server<SCHEME, SStore, E, KProvider>
where
    SCHEME: HqcScheme,
    SStore: SessionStore,
    E: EntropyProvider,
    KProvider: CookieKeyProvider,
{
    pub fn new(session_store: SStore, entropy_provider: E, key_provider: KProvider) -> Self {
        Self {
            session_store,
            entropy_provider,
            key_provider,
            _phantom: std::marker::PhantomData,
        }
    }

    fn encrypt_cookie(&self, plaintext: &[u8], merkle_root: &[u8; 32]) -> Result<(Vec<u8>, u8)> {
        let key_index = self.key_provider.current_key_index();
        let key = self
            .key_provider
            .get_key(key_index)
            .ok_or(Error::EncryptionError)?;

        let mut nonce = [0u8; 24];
        self.entropy_provider.random_bytes(&mut nonce);

        let cipher = XChaCha20Poly1305::new(&key.into());
        let payload = chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad: merkle_root,
        };
        let ct = cipher
            .encrypt(XNonce::from_slice(&nonce), payload)
            .map_err(|_| Error::EncryptionError)?;

        let mut cookie = vec![0u8; 24 + ct.len()];
        cookie[..24].copy_from_slice(&nonce);
        cookie[24..].copy_from_slice(&ct);
        Ok((cookie, key_index))
    }

    fn decrypt_cookie(
        &self,
        cookie: &[u8],
        key_index: u8,
        merkle_root: &[u8; 32],
    ) -> Result<Vec<u8>> {
        if cookie.len() < 24 {
            return Err(Error::InvalidCookieLength);
        }

        let key = self
            .key_provider
            .get_key(key_index)
            .ok_or(Error::SessionExpired)?;
        let (nonce_bytes, ct_bytes) = cookie.split_at(24);
        let cipher = XChaCha20Poly1305::new(&key.into());
        let payload = chacha20poly1305::aead::Payload {
            msg: ct_bytes,
            aad: merkle_root,
        };
        let pt = cipher
            .decrypt(XNonce::from_slice(nonce_bytes), payload)
            .map_err(|_| Error::DecryptionError)?;
        Ok(pt)
    }

    pub fn handle_handshake(&self, req: HandshakeRequest) -> Result<HandshakeResponse> {
        let mut m = vec![0u8; SCHEME::PARAM_SECURITY_BYTES];
        self.entropy_provider.random_bytes(&mut m);

        let mut salt = [0u8; 16];
        self.entropy_provider.random_bytes(&mut salt);

        let ss_params = SCHEME::derive_shared_secret(&m, &salt, &req.hash_ek_kem);
        let theta = ss_params.theta();
        let k_session = ss_params.K();

        let mut k_session_32 = [0u8; 32];
        let copy_len = k_session.len().min(32);
        k_session_32[..copy_len].copy_from_slice(&k_session[..copy_len]);

        self.session_store.save_session(k_session_32);
        k_session_32.zeroize();

        let mut plaintext = vec![0u8; 32 + SCHEME::PARAM_SECURITY_BYTES];
        plaintext[..32].copy_from_slice(theta);
        plaintext[32..].copy_from_slice(&m);
        m.zeroize();

        let result =
            self.encrypt_cookie(&plaintext, &req.merkle_root)
                .map(|(cookie, key_index)| HandshakeResponse {
                    cookie,
                    salt,
                    key_index,
                });
        plaintext.zeroize();
        result
    }

    pub fn handle_point_request(&self, req: PointRequest) -> Result<PointResponse> {
        let points_num = SCHEME::POINTS_NUM;

        if req.point_index == 0 || req.point_index as usize > points_num {
            return Err(Error::InvalidPointIndex);
        }

        // Validate merkle_root using cookie's AAD
        let mut plaintext = self.decrypt_cookie(&req.cookie, req.key_index, &req.merkle_root)?;
        if plaintext.len() != 32 + SCHEME::PARAM_SECURITY_BYTES {
            return Err(Error::InvalidCookie);
        }

        // Validate Merkle proof for the public evaluation point
        let leaf_bytes = serialize_point_leaf(req.point_index, req.point_type, &req.public_eval);
        let leaf_hash = Blake3Algorithm::hash(&leaf_bytes);
        let proof = rs_merkle::MerkleProof::<Blake3Algorithm>::from_bytes(&req.witness)
            .map_err(|_| Error::InvalidWitness)?;

        let index = match req.point_type {
            PointType::U => (req.point_index as usize - 1) * 2,
            PointType::V => (req.point_index as usize - 1) * 2 + 1,
        };
        let total_leaves = SCHEME::POINTS_NUM * 2;
        if !proof.verify(req.merkle_root, &[index], &[leaf_hash], total_leaves) {
            return Err(Error::MerkleVerificationFailed);
        }

        let mut theta = [0u8; 32];
        theta.copy_from_slice(&plaintext[..32]);
        let m = &plaintext[32..];

        let n = SCHEME::PARAM_N;
        let n_words = n.div_ceil(64);
        let num_deltas = blinding::num_kernel_deltas(n);
        let power = req.point_index;
        // Bound shared by public_eval (wire-limited) and every evaluation
        // result below (degree < w + POINTS_NUM*(num_blocks-1), see
        // `evaluate_poly_at_generator`'s doc comment) — lets the one full
        // field multiply per branch run on ~eff_words limbs instead of 141.
        let eff_words = public_eval_limbs::<SCHEME>();

        // The quotient masks and kernel deltas of u and v must be mutually
        // independent (HQCTiny.v samples them separately); a shared mask
        // would cancel in u XOR v and leak the message.
        let eval = match req.point_type {
            PointType::U => {
                let msg_params = SCHEME::partial_message_encaps(m, &theta);

                // r1/r2 are fixed-weight (omega_r ones out of n bits): scanning
                // set bits is cheaper than a dense block-by-block evaluation.
                let mut r2_xi = Gf2_9009::zero();
                evaluate_sparse_poly_at_generator(msg_params.r2(), power, &mut r2_xi);

                let mut mask_poly = vec![0u64; n_words];
                blinding::generate_quotient_mask(&theta, b"quotient mask u", n, &mut mask_poly);
                let mut mask_xi = Gf2_9009::zero();
                evaluate_poly_at_generator(&mask_poly, power, &mut mask_xi);

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

                let mut mask_poly = vec![0u64; n_words];
                blinding::generate_quotient_mask(&theta, b"quotient mask v", n, &mut mask_poly);
                let mut mask_xi = Gf2_9009::zero();
                evaluate_poly_at_generator(&mask_poly, power, &mut mask_xi);

                let mut k_encoded = vec![0u64; SCHEME::VEC_N_SIZE_64];
                SCHEME::code_encode(&mut k_encoded, m);
                let mut k_xi = Gf2_9009::zero();
                evaluate_poly_at_generator(&k_encoded, power, &mut k_xi);

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
