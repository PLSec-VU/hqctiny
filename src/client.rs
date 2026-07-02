use crate::error::{Error, Result};
use crate::hqc::{HqcPublicKeyParameters, HqcScheme};
use crate::math::gf2_8984::Gf2_8984;
use crate::math::hqc_bridge;
use crate::math::segmentation::{combine, evaluate_at_generator, split};
use crate::protocol::*;
use crate::traits::*;
use std::collections::HashMap;

// --- States ---
pub struct Initial;

pub struct AwaitingHandshake {
    pub request: HandshakeRequest,
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
}

pub struct CollectingPoints {
    pub request: HandshakeRequest,
    pub cookie: Vec<u8>,
    pub salt: [u8; 16],
    pub key_index: u8,
    pub points_u: HashMap<u8, Gf2_8984>,
    pub points_v: HashMap<u8, Gf2_8984>,
    pub sk: Vec<u8>,
}

pub struct Completed {
    pub session_key: Vec<u8>,
}

pub struct Client<SCHEME, SStore, E, State>
where
    SCHEME: HqcScheme,
    SStore: SessionStore,
    E: EntropyProvider,
{
    pub session_store: SStore,
    pub entropy_provider: E,
    pub state: State,
    _phantom: std::marker::PhantomData<SCHEME>,
}

impl<SCHEME, SStore, E> Client<SCHEME, SStore, E, Initial>
where
    SCHEME: HqcScheme,
    SStore: SessionStore,
    E: EntropyProvider,
{
    pub fn new(session_store: SStore, entropy_provider: E) -> Self {
        Self {
            session_store,
            entropy_provider,
            state: Initial,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Generate an ephemeral HQC keypair and create the handshake request.
    pub fn initialize(
        self,
    ) -> (
        Client<SCHEME, SStore, E, AwaitingHandshake>,
        HandshakeRequest,
    ) {
        let mut entropy = [0u8; 48];
        self.entropy_provider.random_bytes(&mut entropy);

        let mut pk = vec![0u8; SCHEME::PUBLIC_KEY_BYTES];
        let mut sk = vec![0u8; SCHEME::SECRET_KEY_BYTES];
        unsafe {
            SCHEME::keypair(&entropy, &mut pk, &mut sk);
        }

        let pk_params = SCHEME::partial_public_key_encaps(&pk);
        let hash_ek_kem = *pk_params.hash_ek_kem();

        let request = HandshakeRequest { hash_ek_kem };

        let next_state = Client {
            session_store: self.session_store,
            entropy_provider: self.entropy_provider,
            state: AwaitingHandshake {
                request: request.clone(),
                pk,
                sk,
            },
            _phantom: std::marker::PhantomData,
        };

        (next_state, request)
    }
}

impl<SCHEME, SStore, E> Client<SCHEME, SStore, E, AwaitingHandshake>
where
    SCHEME: HqcScheme,
    SStore: SessionStore,
    E: EntropyProvider,
{
    /// Process the server's handshake response and prepare point requests.
    #[allow(clippy::type_complexity)]
    pub fn handle_handshake_response(
        self,
        res: HandshakeResponse,
    ) -> Result<(
        Client<SCHEME, SStore, E, CollectingPoints>,
        Vec<PointRequest>,
    )> {
        let pk_params = SCHEME::partial_public_key_encaps(&self.state.pk);

        // Split h and s into K[z] blocks for efficient evaluation
        let h_blocks = split(pk_params.h());
        let s_blocks = split(pk_params.s());

        // Generate POINTS_NUM point requests (one U and one V per point)
        let points_num = SCHEME::POINTS_NUM;
        let mut point_requests = Vec::with_capacity(points_num * 2);
        for i in 0..points_num as u8 {
            // h(x_i) where x_i = a^(i+1)
            let mut h_xi = Gf2_8984::zero();
            evaluate_at_generator(&h_blocks, i + 1, &mut h_xi);
            point_requests.push(PointRequest {
                cookie: res.cookie.clone(),
                key_index: res.key_index,
                point_index: i + 1,
                point_type: PointType::U,
                public_eval: h_xi,
            });

            // s(x_i) where x_i = a^(i+1)
            let mut s_xi = Gf2_8984::zero();
            evaluate_at_generator(&s_blocks, i + 1, &mut s_xi);
            point_requests.push(PointRequest {
                cookie: res.cookie.clone(),
                key_index: res.key_index,
                point_index: i + 1,
                point_type: PointType::V,
                public_eval: s_xi,
            });
        }

        let next_state = Client {
            session_store: self.session_store,
            entropy_provider: self.entropy_provider,
            state: CollectingPoints {
                request: self.state.request.clone(),
                cookie: res.cookie,
                salt: res.salt,
                key_index: res.key_index,
                points_u: HashMap::new(),
                points_v: HashMap::new(),
                sk: self.state.sk,
            },
            _phantom: std::marker::PhantomData,
        };

        Ok((next_state, point_requests))
    }
}

#[allow(clippy::type_complexity)]
pub enum PointResult<SCHEME, SStore, E>
where
    SCHEME: HqcScheme,
    SStore: SessionStore,
    E: EntropyProvider,
{
    Collecting(Box<Client<SCHEME, SStore, E, CollectingPoints>>),
    Completed(
        Client<SCHEME, SStore, E, Completed>,
        Vec<u8>, // K_session
    ),
}

impl<SCHEME, SStore, E> Client<SCHEME, SStore, E, CollectingPoints>
where
    SCHEME: HqcScheme,
    SStore: SessionStore,
    E: EntropyProvider,
{
    /// Collect point response and check if all points have been collected.
    pub fn handle_point_response(
        mut self,
        res: PointResponse,
    ) -> Result<PointResult<SCHEME, SStore, E>> {
        let points_num = SCHEME::POINTS_NUM;
        if res.point_index < 1 || res.point_index as usize > points_num {
            return Err(Error::InvalidPointIndex);
        }

        match res.point_type {
            PointType::U => {
                self.state.points_u.insert(res.point_index, res.eval);
            }
            PointType::V => {
                self.state.points_v.insert(res.point_index, res.eval);
            }
        }

        if self.state.points_u.len() >= points_num && self.state.points_v.len() >= points_num {
            // Build ordered arrays of evaluations
            let mut u_evals = vec![Gf2_8984::zero(); points_num];
            let mut v_evals = vec![Gf2_8984::zero(); points_num];
            for i in 0..points_num {
                let idx = (i + 1) as u8;
                u_evals[i] = *self
                    .state
                    .points_u
                    .get(&idx)
                    .ok_or(Error::InterpolationFailed)?;
                v_evals[i] = *self
                    .state
                    .points_v
                    .get(&idx)
                    .ok_or(Error::InterpolationFailed)?;
            }

            // Interpolate u and v in K[z] space
            let u_blocks = SCHEME::interpolate(&u_evals);
            let v_blocks = SCHEME::interpolate(&v_evals);

            // Combine back to F2[x] polynomials (masked u and v)
            let u_masked_poly = combine(&u_blocks);
            let v_masked_poly = combine(&v_blocks);

            // Reduce modulo x^n - 1 to vanish the mask
            let n = SCHEME::PARAM_N;
            let n_words = n.div_ceil(64);
            let mut u_poly_buf = vec![0u64; n_words];
            let u_poly = hqc_bridge::reduce_mod_xn_minus_1(&u_masked_poly, n, &mut u_poly_buf);

            let mut v_poly_buf = vec![0u64; n_words];
            let v_poly = hqc_bridge::reduce_mod_xn_minus_1(&v_masked_poly, n, &mut v_poly_buf);

            // Pack u and v into the expected word arrays
            let mut u_words = vec![0u64; SCHEME::VEC_N_SIZE_64];
            let mut v_words = vec![0u64; SCHEME::VEC_N_SIZE_64];
            u_words[..u_poly.len().min(SCHEME::VEC_N_SIZE_64)]
                .copy_from_slice(&u_poly[..u_poly.len().min(SCHEME::VEC_N_SIZE_64)]);
            v_words[..v_poly.len().min(SCHEME::VEC_N_SIZE_64)]
                .copy_from_slice(&v_poly[..v_poly.len().min(SCHEME::VEC_N_SIZE_64)]);

            // Serialize HQC ciphertext
            let mut ct = vec![0u8; SCHEME::CIPHERTEXT_BYTES];
            SCHEME::serialize_ciphertext(&mut ct, &u_words, &v_words, &self.state.salt);

            // Decapsulate using the HQC KEM secret key
            let mut ss = vec![0u8; SCHEME::SHARED_SECRET_BYTES];
            let ret = SCHEME::dec(&mut ss, &ct, &self.state.sk);
            if ret != 0 {
                return Err(Error::DecodingFailed);
            }

            let next_state = Client {
                session_store: self.session_store,
                entropy_provider: self.entropy_provider,
                state: Completed {
                    session_key: ss.clone(),
                },
                _phantom: std::marker::PhantomData,
            };

            Ok(PointResult::Completed(next_state, ss))
        } else {
            Ok(PointResult::Collecting(Box::new(self)))
        }
    }
}
