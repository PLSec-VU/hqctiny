use crate::error::{Error, Result};
use crate::hqc::{HqcMessageParameters, HqcScheme, HqcSharedSecretParameters};
use crate::math::gf2_8984::Gf2_8984;
use crate::math::hqc_bridge;
use crate::math::segmentation::{evaluate_at_generator, split};
use crate::traits::*;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};

pub struct Server<SCHEME, SStore, E, Time>
where
    SCHEME: HqcScheme,
    SStore: SessionStore,
    E: EntropyProvider,
    Time: TimeProvider,
{
    pub session_store: SStore,
    pub entropy_provider: E,
    pub time_provider: Time,
    pub server_key: [u8; 32],
    pub timeout: u64,
    _phantom: std::marker::PhantomData<SCHEME>,
}

impl<SCHEME, SStore, E, Time> Server<SCHEME, SStore, E, Time>
where
    SCHEME: HqcScheme,
    SStore: SessionStore,
    E: EntropyProvider,
    Time: TimeProvider,
{
    pub fn new(
        session_store: SStore,
        entropy_provider: E,
        time_provider: Time,
        server_key: [u8; 32],
        timeout: u64,
    ) -> Self {
        Self {
            session_store,
            entropy_provider,
            time_provider,
            server_key,
            timeout,
            _phantom: std::marker::PhantomData,
        }
    }

    fn encrypt_cookie(&self, plaintext: &[u8], timestamp: u64) -> Result<Vec<u8>> {
        let mut derived_key = [0u8; 32];
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.server_key);
        hasher.update(&timestamp.to_le_bytes());
        let mut xof = hasher.finalize_xof();
        xof.fill(&mut derived_key);

        let mut nonce = [0u8; 24];
        self.entropy_provider.random_bytes(&mut nonce);

        let cipher = XChaCha20Poly1305::new(&derived_key.into());
        let ct = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .map_err(|_| Error::EncryptionError)?;

        let mut cookie = vec![0u8; 24 + ct.len()];
        cookie[..24].copy_from_slice(&nonce);
        cookie[24..].copy_from_slice(&ct);
        Ok(cookie)
    }

    fn decrypt_cookie(&self, cookie: &[u8], timestamp: u64) -> Result<Vec<u8>> {
        if cookie.len() < 24 {
            return Err(Error::InvalidCookieLength);
        }

        let mut derived_key = [0u8; 32];
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.server_key);
        hasher.update(&timestamp.to_le_bytes());
        let mut xof = hasher.finalize_xof();
        xof.fill(&mut derived_key);

        let (nonce_bytes, ct_bytes) = cookie.split_at(24);
        let cipher = XChaCha20Poly1305::new(&derived_key.into());
        let pt = cipher
            .decrypt(XNonce::from_slice(nonce_bytes), ct_bytes)
            .map_err(|_| Error::DecryptionError)?;
        Ok(pt)
    }

    pub fn handle_handshake(&self, req: HandshakeRequest) -> Result<HandshakeResponse> {
        let now = self.time_provider.current_time();

        let ts = req.timestamp;
        if ts < now.saturating_sub(self.timeout) {
            return Err(Error::TimestampTooOld);
        }
        if let Some((stored_ts, _)) = self.session_store.get_session(&req.hash_ek_kem)
            && ts <= stored_ts
        {
            return Err(Error::TimestampNotIncreasing);
        }

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

        self.session_store
            .save_session(&req.hash_ek_kem, ts, k_session_32);

        let mut plaintext = vec![0u8; 32 + SCHEME::PARAM_SECURITY_BYTES];
        plaintext[..32].copy_from_slice(theta);
        plaintext[32..].copy_from_slice(&m);

        let cookie = self.encrypt_cookie(&plaintext, ts)?;

        Ok(HandshakeResponse { cookie, salt })
    }

    pub fn handle_point_request(&self, req: PointRequest) -> Result<PointResponse> {
        let now = self.time_provider.current_time();
        let points_num = SCHEME::POINTS_NUM;

        if req.point_index == 0 || req.point_index as usize > points_num {
            return Err(Error::InvalidPointIndex);
        }

        if now.saturating_sub(req.handshake_timestamp) > self.timeout {
            return Err(Error::SessionExpired);
        }

        let plaintext = self.decrypt_cookie(&req.cookie, req.handshake_timestamp)?;
        if plaintext.len() != 32 + SCHEME::PARAM_SECURITY_BYTES {
            return Err(Error::InvalidCookie);
        }
        let mut theta = [0u8; 32];
        theta.copy_from_slice(&plaintext[..32]);
        let m = &plaintext[32..];

        let msg_params = SCHEME::partial_message_encaps(m, &theta);
        let r2_poly = msg_params.r2();
        let e_poly = msg_params.e();
        let r1_poly = msg_params.r1();

        let n = SCHEME::PARAM_N;
        let n_words = n.div_ceil(64);
        let mut mask_poly = vec![0u64; n_words];
        hqc_bridge::generate_mask(&theta, b"quotient mask", n, &mut mask_poly);

        let r2_blocks = split(r2_poly);
        let e_blocks = split(e_poly);
        let mask_blocks = split(&mask_poly);

        let power = req.point_index;
        let mut r2_xi = Gf2_8984::zero();
        evaluate_at_generator(&r2_blocks, power, &mut r2_xi);

        let mut mask_xi = Gf2_8984::zero();
        evaluate_at_generator(&mask_blocks, power, &mut mask_xi);

        let eval = match req.point_type {
            PointType::U => {
                let r1_blocks = split(r1_poly);
                let mut r1_xi = Gf2_8984::zero();
                evaluate_at_generator(&r1_blocks, power, &mut r1_xi);

                let mut u_xi = r1_xi;
                let mut term_u = req.public_eval;
                term_u.mul(&r2_xi);
                u_xi.add(&term_u);

                let mut term_mask = mask_xi;
                crate::math::modulus_points::mul_by_modulus_point::<SCHEME>(
                    &mut term_mask,
                    req.point_index as usize,
                );
                u_xi.add(&term_mask);
                u_xi
            }
            PointType::V => {
                let mut k_encoded = vec![0u64; SCHEME::VEC_N_SIZE_64];
                SCHEME::code_encode(&mut k_encoded, m);

                let k_blocks = split(&k_encoded);
                let mut k_xi = Gf2_8984::zero();
                evaluate_at_generator(&k_blocks, power, &mut k_xi);

                let mut e_xi = Gf2_8984::zero();
                evaluate_at_generator(&e_blocks, power, &mut e_xi);

                // Generate truncate mask polynomial
                let mut t_poly = vec![0u64; n_words];
                hqc_bridge::generate_mask(&theta, b"truncate mask", n, &mut t_poly);

                // Clear the first PARAM_N1N2 bits of t_poly
                let n1n2 = SCHEME::PARAM_N1N2;
                let full_words = n1n2 / 64;
                let rem_bits = n1n2 % 64;
                t_poly[..full_words].fill(0);
                if rem_bits > 0 && full_words < t_poly.len() {
                    t_poly[full_words] &= !((1u64 << rem_bits) - 1);
                }

                let t_blocks = split(&t_poly);
                let mut t_xi = Gf2_8984::zero();
                evaluate_at_generator(&t_blocks, power, &mut t_xi);

                let mut v_xi = k_xi;
                let mut term_v = req.public_eval;
                term_v.mul(&r2_xi);
                v_xi.add(&term_v);
                v_xi.add(&e_xi);
                v_xi.add(&t_xi);

                let mut term_mask = mask_xi;
                crate::math::modulus_points::mul_by_modulus_point::<SCHEME>(
                    &mut term_mask,
                    req.point_index as usize,
                );
                v_xi.add(&term_mask);
                v_xi
            }
        };

        Ok(PointResponse {
            handshake_timestamp: req.handshake_timestamp,
            point_index: req.point_index,
            point_type: req.point_type,
            eval,
        })
    }
}
