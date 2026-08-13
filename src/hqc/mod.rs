pub mod ffi;

pub trait HqcScheme {
    const PUBLIC_KEY_BYTES: usize;
    const SECRET_KEY_BYTES: usize;
    const SHARED_SECRET_BYTES: usize;
    const CIPHERTEXT_BYTES: usize;
    const VEC_N_SIZE_64: usize;
    const VEC_N1N2_SIZE_64: usize;
    const VEC_N_SIZE_BYTES: usize;
    const VEC_N1N2_SIZE_BYTES: usize;
    const PARAM_SECURITY_BYTES: usize;
    const PARAM_OMEGA_R: u16;
    const PARAM_OMEGA_E: u16;
    const SALT_BYTES: usize = 16;
    const SEED_BYTES: usize = 32;

    type PublicKeyParameters: HqcPublicKeyParameters;
    type SharedSecretParameters: HqcSharedSecretParameters;
    type MessageParameters: HqcMessageParameters;
    type Tree: crate::merkle::MerkleOps;

    /// Generates a public and secret keypair.
    ///
    /// Returns `0` on success.
    ///
    /// # Arguments
    /// * `entropy` - High-entropy seed input (usually 48 bytes) to seed the PRNG.
    /// * `pk` - Output buffer where the public key will be written. Must have length `Self::PUBLIC_KEY_BYTES`.
    /// * `sk` - Output buffer where the secret key will be written. Must have length `Self::SECRET_KEY_BYTES`.
    ///
    /// # Safety
    /// This function is thread-safe.
    unsafe fn keypair(entropy: &[u8], pk: &mut [u8], sk: &mut [u8]) -> i32;

    /// Encapsulates a shared secret.
    ///
    /// Returns `0` on success.
    ///
    /// # Arguments
    /// * `entropy` - High-entropy seed input (usually 48 bytes) to seed the PRNG.
    /// * `ct` - Output buffer where the ciphertext will be written. Must have length `Self::CIPHERTEXT_BYTES`.
    /// * `ss` - Output buffer where the shared secret will be written. Must have length `Self::SHARED_SECRET_BYTES`.
    /// * `pk` - Input public key buffer. Must have length `Self::PUBLIC_KEY_BYTES`.
    ///
    /// # Safety
    /// This function is thread-safe.
    #[cfg(test)]
    unsafe fn enc(entropy: &[u8], ct: &mut [u8], ss: &mut [u8], pk: &[u8]) -> i32;

    /// Decapsulates a ciphertext.
    ///
    /// Returns `0` on success.
    ///
    /// # Arguments
    /// * `ss` - Output buffer where the shared secret will be written. Must have length `Self::SHARED_SECRET_BYTES`.
    /// * `ct` - Input ciphertext buffer. Must have length `Self::CIPHERTEXT_BYTES`.
    /// * `sk` - Input secret key buffer. Must have length `Self::SECRET_KEY_BYTES`.
    fn dec(ss: &mut [u8], ct: &[u8], sk: &[u8]) -> i32;

    /// Computes public key parameters `h`, `s`, and its hash.
    ///
    /// # Arguments
    /// * `ek` - Input public/encryption key buffer. Must have length `Self::PUBLIC_KEY_BYTES`.
    fn partial_public_key_encaps(ek: &[u8]) -> Self::PublicKeyParameters;

    /// Derives the shared secret key `K` and encryption seed `theta`.
    ///
    /// # Arguments
    /// * `m` - Input message byte array. Must have length `Self::PARAM_SECURITY_BYTES`.
    /// * `salt` - Input salt byte array. Must have length `Self::SALT_BYTES` (16 bytes).
    /// * `hash_ek_kem` - Input hash of the public key. Must have length `Self::SEED_BYTES` (32 bytes).
    fn derive_shared_secret(
        m: &[u8],
        salt: &[u8],
        hash_ek_kem: &[u8],
    ) -> Self::SharedSecretParameters;

    /// Computes sampled error/randomness vectors using the encryption seed `theta`.
    ///
    /// # Arguments
    /// * `theta` - Input seed byte array. Must have length `Self::SEED_BYTES` (32 bytes).
    fn partial_message_encaps(m: &[u8], theta: &[u8]) -> Self::MessageParameters;

    /// Like `partial_message_encaps` but skips sampling r1 (only r2 and e are needed
    /// for V-type point responses; r1 is always last in the XOF stream so skipping it
    /// leaves r2 and e unchanged).
    fn partial_message_encaps_v(m: &[u8], theta: &[u8]) -> Self::MessageParameters {
        Self::partial_message_encaps(m, theta)
    }

    type SupportParameters: HqcSupportParameters;

    /// Like `partial_message_encaps`, but stops at the **supports** of r1/r2/e
    /// rather than scattering them into dense PARAM_N-bit vectors.
    ///
    /// The dense scatter is O(VEC_N_SIZE_64 * weight) and dominates sampling
    /// (91% of it at HQC-5). Callers that only evaluate these polynomials —
    /// the server's point-response path — never need the dense form.
    fn partial_message_encaps_support(m: &[u8], theta: &[u8]) -> Self::SupportParameters;

    /// Support-only counterpart of `partial_message_encaps_v`: draws r2 and e
    /// but not r1, which is last in the XOF stream.
    fn partial_message_encaps_v_support(m: &[u8], theta: &[u8]) -> Self::SupportParameters {
        Self::partial_message_encaps_support(m, theta)
    }

    /// Performs the PKE encryption step to reconstruct ciphertext components `u` and `v`.
    ///
    /// # Arguments
    /// * `u` - Output buffer for PKE component `u`. Must have length `Self::VEC_N_SIZE_64` words.
    /// * `v` - Output buffer for PKE component `v`. Must have length `Self::VEC_N_SIZE_64` words.
    /// * `m` - Input message byte array. Must have length `Self::PARAM_SECURITY_BYTES`.
    /// * `r1` - Randomness vector `r1` from message parameters. Must have length `Self::VEC_N_SIZE_64` words.
    /// * `h` - Parameter vector `h` from public key parameters. Must have length `Self::VEC_N_SIZE_64` words.
    /// * `r2` - Randomness vector `r2` from message parameters. Must have length `Self::VEC_N_SIZE_64` words.
    /// * `s` - Parameter vector `s` from public key parameters. Must have length `Self::VEC_N_SIZE_64` words.
    /// * `e` - Error vector `e` from message parameters. Must have length `Self::VEC_N_SIZE_64` words.
    #[cfg(test)]
    fn encrypt_pke(
        u: &mut [u64],
        v: &mut [u64],
        pk_params: &Self::PublicKeyParameters,
        msg_params: &Self::MessageParameters,
    );

    /// Serializes KEM ciphertext components `u`, `v`, and `salt` into a byte array.
    ///
    /// # Arguments
    /// * `ct` - Output buffer where serialized KEM ciphertext will be stored. Must have length `Self::CIPHERTEXT_BYTES`.
    /// * `u` - PKE ciphertext component `u`. Must have length `Self::VEC_N_SIZE_64` words.
    /// * `v` - PKE ciphertext component `v`. Must have length `Self::VEC_N_SIZE_64` words.
    /// * `salt` - Salt byte array. Must have length `Self::SALT_BYTES` (16 bytes).
    fn serialize_ciphertext(ct: &mut [u8], u: &[u64], v: &[u64], salt: &[u8]);

    const PARAM_N: usize;
    const PARAM_N1N2: usize;
    const POINTS_NUM: usize;

    fn interpolate(
        evals: &[crate::math::gf2_9009::Gf2_9009],
    ) -> Vec<crate::math::gf2_9009::Gf2_9009>;
    fn code_encode(em: &mut [u64], m: &[u8]);

    /// Degree of the segment-evaluated ring modulus x^n + 1 at point a^point_idx:
    /// bit n lands in block n/W at offset n%W, so the evaluation is
    /// x^(n%W + point_idx*(n/W)) + 1.
    fn get_point_degree(point_idx: usize) -> usize {
        let w = crate::math::segmentation::W;
        (Self::PARAM_N % w) + (Self::PARAM_N / w) * point_idx
    }
}

pub trait HqcPublicKeyParameters {
    fn hash_ek_kem(&self) -> &[u8; 32];
    fn h(&self) -> &[u64];
    fn s(&self) -> &[u64];
}

pub trait HqcSharedSecretParameters {
    fn K(&self) -> &[u8];
    fn theta(&self) -> &[u8; 32];
}

pub trait HqcMessageParameters {
    fn m(&self) -> &[u8];
    fn r1(&self) -> &[u64];
    fn r2(&self) -> &[u64];
    fn e(&self) -> &[u64];
}

/// HQC's r1/r2/e as **supports** — the lists of set-bit positions — rather
/// than dense PARAM_N-bit vectors.
///
/// Sampling produces the support first and then scatters it into a dense
/// vector at O(VEC_N_SIZE_64 * weight) cost. Consumers that only evaluate
/// these polynomials never need the dense form, so they take this instead.
/// Each slice holds exactly the vector's Hamming weight, and the positions
/// are distinct (HQC Algorithm 5).
pub trait HqcSupportParameters {
    fn m(&self) -> &[u8];
    fn r1(&self) -> &[u32];
    fn r2(&self) -> &[u32];
    fn e(&self) -> &[u32];
}

macro_rules! define_hqc_variant {
    (
        $mod_name:ident,
        $struct_name:ident,
        $prefix:literal,
        $pk_bytes:expr,
        $sk_bytes:expr,
        $ss_bytes:expr,
        $ct_bytes:expr,
        $vec_n_size_64:expr,
        $vec_n1n2_size_64:expr,
        $vec_n_size_BYTES:expr,
        $vec_n1n2_size_BYTES:expr,
        $param_security_bytes:expr,
        $param_omega_r:expr,
        $param_omega_e:expr,
        $param_n:expr,
        $param_n_mult:expr,
        $points_num:expr,
        $merkle_nodes:expr,
        $newton_weights_file:literal
    ) => {
        pub mod $mod_name {
            #[cfg(test)]
            use crate::hqc::{HqcPublicKeyParameters, HqcMessageParameters};
            use crate::hqc::ffi::hqc_ffi_decls;
            use zeroize::Zeroize;

            lazy_static::lazy_static! {
                static ref NEWTON_WEIGHTS: Box<[crate::math::gf2_9009::Gf2_9009]> =
                    crate::math::interpolate::load_newton_weights::<$points_num>(include_bytes!($newton_weights_file));
            }

            pub const PUBLIC_KEY_BYTES: usize = $pk_bytes;
            pub const SECRET_KEY_BYTES: usize = $sk_bytes;
            pub const SHARED_SECRET_BYTES: usize = $ss_bytes;
            pub const CIPHERTEXT_BYTES: usize = $ct_bytes;
            pub const VEC_N_SIZE_64: usize = $vec_n_size_64;
            pub const VEC_N1N2_SIZE_64: usize = $vec_n1n2_size_64;
            pub const VEC_N_SIZE_BYTES: usize = $vec_n_size_BYTES;
            pub const VEC_N1N2_SIZE_BYTES: usize = $vec_n1n2_size_BYTES;
            pub const PARAM_SECURITY_BYTES: usize = $param_security_bytes;
            pub const PARAM_OMEGA_R: u16 = $param_omega_r;
            pub const PARAM_OMEGA_E: u16 = $param_omega_e;
            pub const SALT_BYTES: usize = 16;
            pub const SEED_BYTES: usize = 32;

            /// Multiplication length used by the AVX2 sources, from their
            /// `parameters.h`.
            #[cfg(feature = "avx2")]
            const PARAM_N_MULT: usize = $param_n_mult;

            /// Length of a PARAM_N-bit vector once padded out to whole 256-bit
            /// blocks, mirroring `VEC_N_256_SIZE_64` in the AVX2 sources'
            /// `parameters.h`. That is the size those routines write.
            #[cfg(feature = "avx2")]
            const VEC_N_256_SIZE_64: usize = PARAM_N_MULT.div_ceil(256) * 4;

            pub struct PublicKeyParameters {
                pub hash_ek_kem: [u8; SEED_BYTES],
                pub h: [u64; VEC_N_SIZE_64],
                pub s: [u64; VEC_N_SIZE_64],
            }

            impl crate::hqc::HqcPublicKeyParameters for PublicKeyParameters {
                fn hash_ek_kem(&self) -> &[u8; 32] {
                    &self.hash_ek_kem
                }
                fn h(&self) -> &[u64] {
                    &self.h
                }
                fn s(&self) -> &[u64] {
                    &self.s
                }
            }

            #[derive(zeroize::Zeroize)]
            #[zeroize(drop)]
            pub struct SharedSecretParameters {
                pub K: [u8; SHARED_SECRET_BYTES],
                pub theta: [u8; SEED_BYTES],
            }

            impl crate::hqc::HqcSharedSecretParameters for SharedSecretParameters {
                fn K(&self) -> &[u8] {
                    &self.K
                }
                fn theta(&self) -> &[u8; 32] {
                    &self.theta
                }
            }

            /// r1/r2/e as supports (set-bit positions) instead of dense
            /// vectors. `r1_len` is 0 when only r2 and e were drawn.
            #[derive(zeroize::Zeroize)]
            #[zeroize(drop)]
            pub struct SupportParameters {
                pub m: [u8; PARAM_SECURITY_BYTES],
                pub r1: [u32; PARAM_OMEGA_R as usize],
                pub r2: [u32; PARAM_OMEGA_R as usize],
                pub e: [u32; PARAM_OMEGA_E as usize],
                pub r1_len: usize,
            }

            impl crate::hqc::HqcSupportParameters for SupportParameters {
                fn m(&self) -> &[u8] {
                    &self.m
                }
                fn r1(&self) -> &[u32] {
                    &self.r1[..self.r1_len]
                }
                fn r2(&self) -> &[u32] {
                    &self.r2
                }
                fn e(&self) -> &[u32] {
                    &self.e
                }
            }

            #[derive(zeroize::Zeroize)]
            #[zeroize(drop)]
            pub struct MessageParameters {
                pub m: [u8; PARAM_SECURITY_BYTES],
                pub r1: [u64; VEC_N_SIZE_64],
                pub r2: [u64; VEC_N_SIZE_64],
                pub e: [u64; VEC_N_SIZE_64],
            }

            impl crate::hqc::HqcMessageParameters for MessageParameters {
                fn m(&self) -> &[u8] {
                    &self.m
                }
                fn r1(&self) -> &[u64] {
                    &self.r1
                }
                fn r2(&self) -> &[u64] {
                    &self.r2
                }
                fn e(&self) -> &[u64] {
                    &self.e
                }
            }

            pub struct $struct_name;

            hqc_ffi_decls!($prefix);

            /// Draws a fixed-weight vector into `out`.
            ///
            /// The portable `vect_sample_fixed_weight2` fills `out` directly.
            /// Its AVX2 counterpart takes `__m256i *` and XORs whole 256-bit
            /// blocks, so it needs a 32-byte-aligned buffer padded out to
            /// `VEC_N_256_SIZE_64` words; sample there and copy back.
            ///
            /// # Safety
            /// `xof_ctx` must point to an initialized XOF context, and `weight`
            /// must not exceed `PARAM_OMEGA_R`.
            unsafe fn sample_fixed_weight2(
                xof_ctx: *mut crate::hqc::ffi::shake256_xof_ctx,
                out: &mut [u64; VEC_N_SIZE_64],
                weight: u16,
            ) {
                #[cfg(not(feature = "avx2"))]
                unsafe {
                    c_vect_sample_fixed_weight2(xof_ctx, out.as_mut_ptr(), weight);
                }
                #[cfg(feature = "avx2")]
                unsafe {
                    let mut padded =
                        crate::hqc::ffi::Vec256::<VEC_N_256_SIZE_64>::zeroed();
                    c_vect_sample_fixed_weight2(xof_ctx, padded.as_mut_ptr(), weight);
                    padded.copy_prefix_to(out);
                }
            }

            /// Multiplies two PARAM_N-bit polynomials modulo `X^n - 1`.
            ///
            /// Like `sample_fixed_weight2`, the AVX2 `vect_mul` reads and writes
            /// `__m256i *` operands, so all three route through padded, aligned
            /// scratch buffers there.
            ///
            /// # Safety
            /// All three slices must be `VEC_N_SIZE_64` words long. Under
            /// `avx2` the caller must hold [`FFI_LOCK`]: that `vect_mul` keeps
            /// its intermediate products in file-scope globals.
            ///
            /// [`FFI_LOCK`]: crate::hqc::ffi::FFI_LOCK
            #[cfg(test)]
            unsafe fn vect_mul(o: &mut [u64], v1: &[u64], v2: &[u64]) {
                #[cfg(not(feature = "avx2"))]
                unsafe {
                    c_vect_mul(o.as_mut_ptr(), v1.as_ptr(), v2.as_ptr());
                }
                #[cfg(feature = "avx2")]
                unsafe {
                    use crate::hqc::ffi::Vec256;
                    let v1 = Vec256::<VEC_N_256_SIZE_64>::from_prefix(v1);
                    let v2 = Vec256::<VEC_N_256_SIZE_64>::from_prefix(v2);
                    let mut padded = Vec256::<VEC_N_256_SIZE_64>::zeroed();
                    c_vect_mul(padded.as_mut_ptr(), v1.as_ptr(), v2.as_ptr());
                    padded.copy_prefix_to(o);
                }
            }

            impl crate::hqc::HqcScheme for $struct_name {
                const PUBLIC_KEY_BYTES: usize = PUBLIC_KEY_BYTES;
                const SECRET_KEY_BYTES: usize = SECRET_KEY_BYTES;
                const SHARED_SECRET_BYTES: usize = SHARED_SECRET_BYTES;
                const CIPHERTEXT_BYTES: usize = CIPHERTEXT_BYTES;
                const VEC_N_SIZE_64: usize = VEC_N_SIZE_64;
                const VEC_N1N2_SIZE_64: usize = VEC_N1N2_SIZE_64;
                const VEC_N_SIZE_BYTES: usize = VEC_N_SIZE_BYTES;
                const VEC_N1N2_SIZE_BYTES: usize = VEC_N1N2_SIZE_BYTES;
                const PARAM_SECURITY_BYTES: usize = PARAM_SECURITY_BYTES;
                const PARAM_OMEGA_R: u16 = PARAM_OMEGA_R;
                const PARAM_OMEGA_E: u16 = PARAM_OMEGA_E;

                const PARAM_N: usize = $param_n;
                const PARAM_N1N2: usize = VEC_N1N2_SIZE_BYTES * 8;
                const POINTS_NUM: usize = $points_num;

                type PublicKeyParameters = PublicKeyParameters;
                type SharedSecretParameters = SharedSecretParameters;
                type MessageParameters = MessageParameters;
                type Tree = crate::merkle::MerkleTree<{$merkle_nodes}>;

                fn interpolate(evals: &[crate::math::gf2_9009::Gf2_9009]) -> Vec<crate::math::gf2_9009::Gf2_9009> {
                    assert_eq!(evals.len(), Self::POINTS_NUM);
                    let evals_arr: &[crate::math::gf2_9009::Gf2_9009; $points_num] = evals.try_into().unwrap();
                    crate::math::interpolate::interpolate_newton::<$points_num>(&*NEWTON_WEIGHTS, evals_arr).into()
                }

                fn code_encode(em: &mut [u64], m: &[u8]) {
                    assert_eq!(em.len(), VEC_N_SIZE_64);
                    assert_eq!(m.len(), PARAM_SECURITY_BYTES);
                    unsafe {
                        c_code_encode(em.as_mut_ptr(), m.as_ptr() as *const u64);
                    }
                }

                unsafe fn keypair(entropy: &[u8], pk: &mut [u8], sk: &mut [u8]) -> i32 {
                    assert_eq!(pk.len(), PUBLIC_KEY_BYTES);
                    assert_eq!(sk.len(), SECRET_KEY_BYTES);
                    let _guard = crate::hqc::ffi::FFI_LOCK.lock().unwrap();
                    let mut personal = [0u8; 0];
                    unsafe {
                        c_prng_init(
                            entropy.as_ptr() as *mut u8,
                            personal.as_mut_ptr(),
                            entropy.len() as u32,
                            0,
                        );
                        c_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
                    }
                }

                #[cfg(test)]
                unsafe fn enc(entropy: &[u8], ct: &mut [u8], ss: &mut [u8], pk: &[u8]) -> i32 {
                    assert_eq!(ct.len(), CIPHERTEXT_BYTES);
                    assert_eq!(ss.len(), SHARED_SECRET_BYTES);
                    assert_eq!(pk.len(), PUBLIC_KEY_BYTES);
                    let _guard = crate::hqc::ffi::FFI_LOCK.lock().unwrap();
                    let mut personal = [0u8; 0];
                    unsafe {
                        c_prng_init(
                            entropy.as_ptr() as *mut u8,
                            personal.as_mut_ptr(),
                            entropy.len() as u32,
                            0,
                        );
                        c_crypto_kem_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr())
                    }
                }

                fn dec(ss: &mut [u8], ct: &[u8], sk: &[u8]) -> i32 {
                    assert_eq!(ss.len(), SHARED_SECRET_BYTES);
                    assert_eq!(ct.len(), CIPHERTEXT_BYTES);
                    assert_eq!(sk.len(), SECRET_KEY_BYTES);
                    // The portable decryption path is reentrant, but the AVX2
                    // one keeps its scratch in function-level statics and
                    // file-scope globals, so it has to be serialized.
                    #[cfg(feature = "avx2")]
                    let _guard = crate::hqc::ffi::FFI_LOCK.lock().unwrap();
                    unsafe {
                        c_crypto_kem_dec(ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
                    }
                }

                fn partial_public_key_encaps(ek: &[u8]) -> Self::PublicKeyParameters {
                    assert_eq!(ek.len(), PUBLIC_KEY_BYTES);
                    let mut hash_ek_kem = [0u8; SEED_BYTES];
                    unsafe {
                        c_hash_h(hash_ek_kem.as_mut_ptr(), ek.as_ptr());
                    }

                    let mut h = [0u64; VEC_N_SIZE_64];
                    let mut s = [0u64; VEC_N_SIZE_64];
                    unsafe {
                        c_hqc_ek_pke_from_string(h.as_mut_ptr(), s.as_mut_ptr(), ek.as_ptr());
                    }

                    PublicKeyParameters { hash_ek_kem, h, s }
                }

                fn derive_shared_secret(
                    m: &[u8],
                    salt: &[u8],
                    hash_ek_kem: &[u8],
                ) -> Self::SharedSecretParameters {
                    assert_eq!(m.len(), PARAM_SECURITY_BYTES);
                    assert_eq!(salt.len(), SALT_BYTES);
                    assert_eq!(hash_ek_kem.len(), SEED_BYTES);

                    let mut K_theta = [0u8; SHARED_SECRET_BYTES + SEED_BYTES];
                    unsafe {
                        c_hash_g(
                            K_theta.as_mut_ptr(),
                            hash_ek_kem.as_ptr(),
                            m.as_ptr(),
                            salt.as_ptr(),
                        );
                    }

                    let mut K = [0u8; SHARED_SECRET_BYTES];
                    let mut theta = [0u8; SEED_BYTES];
                    K.copy_from_slice(&K_theta[..SHARED_SECRET_BYTES]);
                    theta.copy_from_slice(&K_theta[SHARED_SECRET_BYTES..]);

                    SharedSecretParameters { K, theta }
                }

                fn partial_message_encaps(m: &[u8], theta: &[u8]) -> Self::MessageParameters {
                    assert_eq!(m.len(), PARAM_SECURITY_BYTES);
                    assert_eq!(theta.len(), SEED_BYTES);
                    let mut theta_xof_ctx = crate::hqc::ffi::shake256_xof_ctx { ctx: [0; 26] };
                    unsafe {
                        c_xof_init(&mut theta_xof_ctx, theta.as_ptr(), SEED_BYTES as u32);
                    }

                    let mut r2 = [0u64; VEC_N_SIZE_64];
                    let mut e = [0u64; VEC_N_SIZE_64];
                    let mut r1 = [0u64; VEC_N_SIZE_64];

                    unsafe {
                        sample_fixed_weight2(&mut theta_xof_ctx, &mut r2, PARAM_OMEGA_R);
                        sample_fixed_weight2(&mut theta_xof_ctx, &mut e, PARAM_OMEGA_E);
                        sample_fixed_weight2(&mut theta_xof_ctx, &mut r1, PARAM_OMEGA_R);
                    }

                    let mut m_arr = [0u8; PARAM_SECURITY_BYTES];
                    m_arr.copy_from_slice(m);

                    MessageParameters { m: m_arr, r1, r2, e }
                }

                fn partial_message_encaps_v(m: &[u8], theta: &[u8]) -> Self::MessageParameters {
                    assert_eq!(m.len(), PARAM_SECURITY_BYTES);
                    assert_eq!(theta.len(), SEED_BYTES);
                    let mut theta_xof_ctx = crate::hqc::ffi::shake256_xof_ctx { ctx: [0; 26] };
                    unsafe {
                        c_xof_init(&mut theta_xof_ctx, theta.as_ptr(), SEED_BYTES as u32);
                    }

                    let mut r2 = [0u64; VEC_N_SIZE_64];
                    let mut e = [0u64; VEC_N_SIZE_64];

                    unsafe {
                        sample_fixed_weight2(&mut theta_xof_ctx, &mut r2, PARAM_OMEGA_R);
                        sample_fixed_weight2(&mut theta_xof_ctx, &mut e, PARAM_OMEGA_E);
                        // r1 is last in the XOF stream and unused for V-type responses.
                    }

                    let mut m_arr = [0u8; PARAM_SECURITY_BYTES];
                    m_arr.copy_from_slice(m);

                    MessageParameters { m: m_arr, r1: [0u64; VEC_N_SIZE_64], r2, e }
                }

                type SupportParameters = SupportParameters;

                fn partial_message_encaps_support(m: &[u8], theta: &[u8]) -> Self::SupportParameters {
                    assert_eq!(m.len(), PARAM_SECURITY_BYTES);
                    assert_eq!(theta.len(), SEED_BYTES);
                    let mut theta_xof_ctx = crate::hqc::ffi::shake256_xof_ctx { ctx: [0; 26] };
                    unsafe {
                        c_xof_init(&mut theta_xof_ctx, theta.as_ptr(), SEED_BYTES as u32);
                    }

                    let mut r2 = [0u32; PARAM_OMEGA_R as usize];
                    let mut e = [0u32; PARAM_OMEGA_E as usize];
                    let mut r1 = [0u32; PARAM_OMEGA_R as usize];

                    // Same XOF draw order as partial_message_encaps, so the
                    // supports describe exactly the same r2/e/r1.
                    unsafe {
                        c_vect_generate_random_support2(&mut theta_xof_ctx, r2.as_mut_ptr(), PARAM_OMEGA_R);
                        c_vect_generate_random_support2(&mut theta_xof_ctx, e.as_mut_ptr(), PARAM_OMEGA_E);
                        c_vect_generate_random_support2(&mut theta_xof_ctx, r1.as_mut_ptr(), PARAM_OMEGA_R);
                    }

                    let mut m_arr = [0u8; PARAM_SECURITY_BYTES];
                    m_arr.copy_from_slice(m);

                    SupportParameters { m: m_arr, r1, r2, e, r1_len: PARAM_OMEGA_R as usize }
                }

                fn partial_message_encaps_v_support(m: &[u8], theta: &[u8]) -> Self::SupportParameters {
                    assert_eq!(m.len(), PARAM_SECURITY_BYTES);
                    assert_eq!(theta.len(), SEED_BYTES);
                    let mut theta_xof_ctx = crate::hqc::ffi::shake256_xof_ctx { ctx: [0; 26] };
                    unsafe {
                        c_xof_init(&mut theta_xof_ctx, theta.as_ptr(), SEED_BYTES as u32);
                    }

                    let mut r2 = [0u32; PARAM_OMEGA_R as usize];
                    let mut e = [0u32; PARAM_OMEGA_E as usize];

                    unsafe {
                        c_vect_generate_random_support2(&mut theta_xof_ctx, r2.as_mut_ptr(), PARAM_OMEGA_R);
                        c_vect_generate_random_support2(&mut theta_xof_ctx, e.as_mut_ptr(), PARAM_OMEGA_E);
                        // r1 is last in the XOF stream and unused for V-type responses.
                    }

                    let mut m_arr = [0u8; PARAM_SECURITY_BYTES];
                    m_arr.copy_from_slice(m);

                    SupportParameters { m: m_arr, r1: [0u32; PARAM_OMEGA_R as usize], r2, e, r1_len: 0 }
                }


                #[cfg(test)]
                fn encrypt_pke(
                    u: &mut [u64],
                    v: &mut [u64],
                    pk_params: &Self::PublicKeyParameters,
                    msg_params: &Self::MessageParameters,
                ) {
                    let m = msg_params.m();
                    let r1 = msg_params.r1();
                    let h = pk_params.h();
                    let r2 = msg_params.r2();
                    let s = pk_params.s();
                    let e = msg_params.e();

                    assert_eq!(u.len(), VEC_N_SIZE_64);
                    assert_eq!(v.len(), VEC_N_SIZE_64);
                    assert_eq!(m.len(), PARAM_SECURITY_BYTES);
                    assert_eq!(r1.len(), VEC_N_SIZE_64);
                    assert_eq!(h.len(), VEC_N_SIZE_64);
                    assert_eq!(r2.len(), VEC_N_SIZE_64);
                    assert_eq!(s.len(), VEC_N_SIZE_64);
                    assert_eq!(e.len(), VEC_N_SIZE_64);

                    // `vect_mul` shares global scratch under `avx2`; see its wrapper.
                    #[cfg(feature = "avx2")]
                    let _guard = crate::hqc::ffi::FFI_LOCK.lock().unwrap();

                    unsafe {
                        vect_mul(u, r2, h);
                        c_vect_add(u.as_mut_ptr(), r1.as_ptr(), u.as_ptr(), VEC_N_SIZE_64 as u32);

                        c_code_encode(v.as_mut_ptr(), m.as_ptr() as *const u64);

                        let mut tmp = [0u64; VEC_N_SIZE_64];
                        vect_mul(&mut tmp, r2, s);
                        c_vect_add(tmp.as_mut_ptr(), e.as_ptr(), tmp.as_ptr(), VEC_N_SIZE_64 as u32);
                        c_vect_truncate(tmp.as_mut_ptr());

                        c_vect_add(v.as_mut_ptr(), v.as_ptr(), tmp.as_ptr(), VEC_N1N2_SIZE_64 as u32);
                    }
                }

                fn serialize_ciphertext(
                    ct: &mut [u8],
                    u: &[u64],
                    v: &[u64],
                    salt: &[u8],
                ) {
                    assert_eq!(ct.len(), CIPHERTEXT_BYTES);
                    assert_eq!(u.len(), VEC_N_SIZE_64);
                    assert_eq!(v.len(), VEC_N_SIZE_64);
                    assert_eq!(salt.len(), SALT_BYTES);

                    let u_bytes = unsafe {
                        core::slice::from_raw_parts(u.as_ptr() as *const u8, VEC_N_SIZE_BYTES)
                    };
                    ct[..VEC_N_SIZE_BYTES].copy_from_slice(u_bytes);

                    let v_bytes = unsafe {
                        core::slice::from_raw_parts(v.as_ptr() as *const u8, VEC_N1N2_SIZE_BYTES)
                    };
                    ct[VEC_N_SIZE_BYTES .. VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES].copy_from_slice(v_bytes);
                    ct[VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES..].copy_from_slice(salt);
                }
            }

            // Backward-compatible module-level functions:
            /// Generates a public and secret keypair seeded with cryptographic entropy.
            ///
            /// Returns `0` on success. Thread-safe.
            ///
            /// # Safety
            /// `entropy` must contain at least 48 bytes of high-quality randomness.
            pub unsafe fn keypair(entropy: &[u8], pk: &mut [u8; PUBLIC_KEY_BYTES], sk: &mut [u8; SECRET_KEY_BYTES]) -> i32 {
                unsafe {
                    <$struct_name as crate::hqc::HqcScheme>::keypair(entropy, pk, sk)
                }
            }

            /// Decapsulates a shared secret from a ciphertext using a secret key.
            ///
            /// Returns `0` on success.
            pub fn dec(ss: &mut [u8; SHARED_SECRET_BYTES], ct: &[u8; CIPHERTEXT_BYTES], sk: &[u8; SECRET_KEY_BYTES]) -> i32 {
                <$struct_name as crate::hqc::HqcScheme>::dec(ss, ct, sk)
            }

            /// Computes public key parameters `h`, `s`, and its hash.
            pub fn partial_public_key_encaps(ek: &[u8; PUBLIC_KEY_BYTES]) -> PublicKeyParameters {
                <$struct_name as crate::hqc::HqcScheme>::partial_public_key_encaps(ek)
            }

            /// Derives the shared secret key `K` and encryption seed `theta` from the message `m`, `salt`, and public key hash.
            pub fn derive_shared_secret(
                m: &[u8; PARAM_SECURITY_BYTES],
                salt: &[u8; SALT_BYTES],
                hash_ek_kem: &[u8; SEED_BYTES],
            ) -> SharedSecretParameters {
                <$struct_name as crate::hqc::HqcScheme>::derive_shared_secret(m, salt, hash_ek_kem)
            }

            /// Computes sampled error/randomness vectors using the encryption seed `theta`.
            pub fn partial_message_encaps(
                m: &[u8; PARAM_SECURITY_BYTES],
                theta: &[u8; SEED_BYTES],
            ) -> MessageParameters {
                <$struct_name as crate::hqc::HqcScheme>::partial_message_encaps(m, theta)
            }
        }
    };
}

define_hqc_variant!(
    hqc1,
    Hqc1,
    "hqc_1_",
    2241,
    2321,
    32,
    4433,
    277,
    276,
    2209,
    2208,
    16,
    75,
    75,
    17669,
    18048,
    7,
    32,
    "../math/newton_weights_17669.bin"
);
define_hqc_variant!(
    hqc3,
    Hqc3,
    "hqc_3_",
    4514,
    4602,
    32,
    8978,
    561,
    560,
    4482,
    4480,
    24,
    114,
    114,
    35851,
    36480,
    15,
    64,
    "../math/newton_weights_35851.bin"
);
define_hqc_variant!(
    hqc5,
    Hqc5,
    "hqc_5_",
    7237,
    7333,
    32,
    14421,
    901,
    900,
    7205,
    7200,
    32,
    149,
    149,
    57637,
    59904,
    25,
    128,
    "../math/newton_weights_57637.bin"
);

pub use hqc1::Hqc1;
pub use hqc3::Hqc3;
pub use hqc5::Hqc5;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_flow_generic<T: HqcScheme>() {
        let entropy = [42u8; 48];
        unsafe {
            let mut pk = vec![0u8; T::PUBLIC_KEY_BYTES];
            let mut sk = vec![0u8; T::SECRET_KEY_BYTES];
            assert_eq!(T::keypair(&entropy, &mut pk, &mut sk), 0);

            let mut ct = vec![0u8; T::CIPHERTEXT_BYTES];
            let mut ss_enc = vec![0u8; T::SHARED_SECRET_BYTES];
            assert_eq!(T::enc(&entropy, &mut ct, &mut ss_enc, &pk), 0);

            let mut ss_dec = vec![0u8; T::SHARED_SECRET_BYTES];
            assert_eq!(T::dec(&mut ss_dec, &ct, &sk), 0);

            assert_eq!(ss_enc, ss_dec);
            assert_ne!(ss_enc, vec![0u8; T::SHARED_SECRET_BYTES]);
        }
    }

    fn test_decoupled_flow_generic<T: HqcScheme>()
    where
        T::PublicKeyParameters: HqcPublicKeyParameters,
        T::SharedSecretParameters: HqcSharedSecretParameters,
        T::MessageParameters: HqcMessageParameters,
    {
        let entropy = [42u8; 48];
        unsafe {
            let mut pk = vec![0u8; T::PUBLIC_KEY_BYTES];
            let mut sk = vec![0u8; T::SECRET_KEY_BYTES];
            assert_eq!(T::keypair(&entropy, &mut pk, &mut sk), 0);

            let m = vec![0xAAu8; T::PARAM_SECURITY_BYTES];
            let salt = vec![0x55u8; T::SALT_BYTES];

            // 1. Process public key parameters
            let pk_params = T::partial_public_key_encaps(&pk);

            // 2. Derive shared secret and theta
            let ss_params = T::derive_shared_secret(&m, &salt, pk_params.hash_ek_kem());

            // 3. Process message parameters (sampling vectors using theta directly)
            let msg_params = T::partial_message_encaps(&m, ss_params.theta());

            // Reconstruct PKE ciphertext components u and v
            let mut u = vec![0u64; T::VEC_N_SIZE_64];
            let mut v = vec![0u64; T::VEC_N_SIZE_64];
            T::encrypt_pke(&mut u, &mut v, &pk_params, &msg_params);

            // Serialize KEM ciphertext
            let mut ct = vec![0u8; T::CIPHERTEXT_BYTES];
            T::serialize_ciphertext(&mut ct, &u, &v, &salt);

            // Decapsulate
            let mut ss_dec = vec![0u8; T::SHARED_SECRET_BYTES];
            assert_eq!(T::dec(&mut ss_dec, &ct, &sk), 0);

            // Verify they match
            assert_eq!(ss_params.K(), ss_dec.as_slice());
        }
    }

    #[test]
    fn test_hqc1_flow() {
        test_flow_generic::<Hqc1>();
    }

    #[test]
    fn test_hqc3_flow() {
        test_flow_generic::<Hqc3>();
    }

    #[test]
    fn test_hqc5_flow() {
        test_flow_generic::<Hqc5>();
    }

    #[test]
    fn test_hqc1_decoupled_flow() {
        test_decoupled_flow_generic::<Hqc1>();
    }

    #[test]
    fn test_hqc3_decoupled_flow() {
        test_decoupled_flow_generic::<Hqc3>();
    }

    #[test]
    fn test_hqc5_decoupled_flow() {
        test_decoupled_flow_generic::<Hqc5>();
    }

    /// The support-returning sampler must describe exactly the same vectors as
    /// the dense one: expanding its supports bit by bit must reproduce r2 and
    /// e word for word. This is what lets the server skip the dense scatter.
    fn test_support_matches_dense_generic<T: HqcScheme>()
    where
        T::MessageParameters: HqcMessageParameters,
    {
        let m = vec![0xA5u8; T::PARAM_SECURITY_BYTES];
        let theta = [0x3Cu8; 32];

        let dense = T::partial_message_encaps_v(&m, &theta);
        let sup = T::partial_message_encaps_v_support(&m, &theta);

        for (name, support, expected) in [("r2", sup.r2(), dense.r2()), ("e", sup.e(), dense.e())] {
            let mut rebuilt = vec![0u64; T::VEC_N_SIZE_64];
            for &pos in support {
                let pos = pos as usize;
                assert!(pos < T::PARAM_N, "{name}: position {pos} >= PARAM_N");
                rebuilt[pos / 64] |= 1u64 << (pos % 64);
            }
            assert_eq!(rebuilt.as_slice(), expected, "{name} mismatch");
        }
    }

    /// Distinctness is load-bearing for `evaluate_support_at_generator`:
    /// the dense path ORs coincident positions to one bit, the support path
    /// XORs them and cancels. Algorithm 5 promises distinctness; pin it.
    fn test_support_distinct_generic<T: HqcScheme>()
    where
        T::MessageParameters: HqcMessageParameters,
    {
        let m = vec![0x5Au8; T::PARAM_SECURITY_BYTES];
        for seed in 0..8u8 {
            let theta = [seed; 32];
            let sup = T::partial_message_encaps_support(&m, &theta);
            for (name, support) in [("r1", sup.r1()), ("r2", sup.r2()), ("e", sup.e())] {
                let mut seen = support.to_vec();
                seen.sort_unstable();
                let before = seen.len();
                seen.dedup();
                assert_eq!(
                    seen.len(),
                    before,
                    "{name} has duplicate positions (seed {seed})"
                );
            }
        }
    }

    #[test]
    fn test_hqc1_support_matches_dense() {
        test_support_matches_dense_generic::<Hqc1>();
    }

    #[test]
    fn test_hqc3_support_matches_dense() {
        test_support_matches_dense_generic::<Hqc3>();
    }

    #[test]
    fn test_hqc5_support_matches_dense() {
        test_support_matches_dense_generic::<Hqc5>();
    }

    #[test]
    fn test_hqc1_support_distinct() {
        test_support_distinct_generic::<Hqc1>();
    }

    #[test]
    fn test_hqc3_support_distinct() {
        test_support_distinct_generic::<Hqc3>();
    }

    #[test]
    fn test_hqc5_support_distinct() {
        test_support_distinct_generic::<Hqc5>();
    }
}
