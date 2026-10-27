pub mod ffi;

/// Rust surface over one HQC parameter set's C reference implementation.
///
/// Every slice argument below must be exactly the length its name implies
/// (`pk` is `PUBLIC_KEY_BYTES`, `u`/`v` are `VEC_N_SIZE_64` words, and so
/// on). The implementations assert this before crossing into C, so a wrong
/// length panics rather than corrupting memory.
pub trait HqcScheme: crate::auth::AuthLevel {
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

    /// Generates a public and secret keypair. Returns `0` on success.
    ///
    /// # Safety
    /// `entropy` seeds the C PRNG and must carry at least 48 bytes of
    /// high-quality randomness — a predictable seed yields a predictable key.
    unsafe fn keypair(entropy: &[u8], pk: &mut [u8], sk: &mut [u8]) -> i32;

    /// Reference HQC encapsulation. Returns `0` on success.
    ///
    /// # Safety
    /// Same entropy requirement as [`HqcScheme::keypair`].
    unsafe fn enc(entropy: &[u8], ct: &mut [u8], ss: &mut [u8], pk: &[u8]) -> i32;

    /// Decapsulates a ciphertext. Returns `0` on success.
    fn dec(ss: &mut [u8], ct: &[u8], sk: &[u8]) -> i32;

    /// Seeds the C PRNG once with `seed`, then runs key generation and
    /// encapsulation on that one stream, as the NIST KAT generator does.
    #[cfg(test)]
    fn kat_run(seed: &[u8], pk: &mut [u8], sk: &mut [u8], ct: &mut [u8], ss: &mut [u8]);

    /// `o = a * b` modulo `X^n - 1` with the C backend's `vect_mul`; all
    /// three slices are `VEC_N_SIZE_64` words long.
    fn ring_multiply(o: &mut [u64], a: &[u64], b: &[u64]);

    /// Writes the bytes `start..start + out.len()` of the serialized
    /// `u = r1 + h * r2` of reference encapsulation into `out`. `h` is
    /// expanded from `h_seed`, the seed field of the public key. `r1` and
    /// `r2` come from `theta` exactly as in `hqc_pke_encrypt`.
    fn compute_u_window(h_seed: &[u8], theta: &[u8], start: usize, out: &mut [u8]);

    /// The whole serialized `u`, `VEC_N_SIZE_BYTES` long.
    fn compute_u(h_seed: &[u8], theta: &[u8], u_bytes: &mut [u8]) {
        Self::compute_u_window(h_seed, theta, 0, u_bytes);
    }

    /// The first `out.len()` bytes of the PRNG stream the reference
    /// encapsulation reads `m` and `salt` from, after seeding with `entropy`.
    fn reference_prng_stream(entropy: &[u8], out: &mut [u8]);

    /// Computes public key parameters `h`, `s`, and its hash.
    fn partial_public_key_encaps(ek: &[u8]) -> Self::PublicKeyParameters;

    /// Derives the shared secret key `K` and encryption seed `theta`.
    fn derive_shared_secret(
        m: &[u8],
        salt: &[u8],
        hash_ek_kem: &[u8],
    ) -> Self::SharedSecretParameters;

    /// Computes sampled error/randomness vectors using the encryption seed `theta`.
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

    /// Performs the PKE encryption step, reconstructing ciphertext components
    /// `u` and `v` from the public-key and message parameters.
    #[cfg(test)]
    fn encrypt_pke(
        u: &mut [u64],
        v: &mut [u64],
        pk_params: &Self::PublicKeyParameters,
        msg_params: &Self::MessageParameters,
    );

    /// Serializes KEM ciphertext components `u`, `v`, and `salt` into `ct`.
    fn serialize_ciphertext(ct: &mut [u8], u: &[u64], v: &[u64], salt: &[u8]);

    const PARAM_N: usize;
    const PARAM_N1N2: usize;
    const CRT_MODULI: &'static [crate::crt::Modulus];
    const CRT_GARNER: &'static [u8];

    fn code_encode(em: &mut [u64], m: &[u8]);
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
        $crt_moduli:expr,
        $crt_garner_file:literal
    ) => {
        pub mod $mod_name {
            use crate::hqc::ffi::hqc_ffi_decls;
            #[cfg(test)]
            use crate::hqc::{HqcMessageParameters, HqcPublicKeyParameters};
            use zeroize::Zeroize;

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
            const PARAM_N_MULT: usize = $param_n_mult;

            /// Length of a PARAM_N-bit vector once padded out to whole 256-bit
            /// blocks, mirroring `VEC_N_256_SIZE_64` in the AVX2 sources'
            /// `parameters.h`. That is the size those routines write.
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
                unsafe {
                    let mut padded = crate::hqc::ffi::Vec256::<VEC_N_256_SIZE_64>::zeroed();
                    c_vect_sample_fixed_weight2(xof_ctx, padded.as_mut_ptr(), weight);
                    padded.copy_prefix_to(out);
                }
            }

            /// Multiplies two PARAM_N-bit polynomials modulo `X^n - 1`
            /// through padded, aligned buffers. Test-only: the server calls
            /// `c_vect_mul` on its own padded buffers.
            ///
            /// # Safety
            /// All three slices must be `VEC_N_SIZE_64` words long.
            unsafe fn vect_mul(o: &mut [u64], v1: &[u64], v2: &[u64]) {
                use crate::hqc::ffi::Vec256;
                let v1 = Vec256::<VEC_N_256_SIZE_64>::from_prefix(v1);
                let v2 = Vec256::<VEC_N_256_SIZE_64>::from_prefix(v2);
                let mut padded = Vec256::<VEC_N_256_SIZE_64>::zeroed();
                unsafe {
                    c_vect_mul(padded.as_mut_ptr(), v1.as_ptr(), v2.as_ptr());
                }
                padded.copy_prefix_to(o);
            }

            /// Draws `out.len()` distinct positions from the XOF, with the same
            /// result as `vect_generate_random_support2`.
            fn sample_support(xof_ctx: &mut crate::hqc::ffi::shake256_xof_ctx, out: &mut [u32]) {
                let weight = out.len();
                let mut random = [0u32; crate::support::MAX_SUPPORT_WEIGHT];
                unsafe {
                    c_xof_get_bytes(xof_ctx, random.as_mut_ptr() as *mut u8, 4 * weight as u32);
                }
                crate::support::finish_support(&random[..weight], $param_n as u32, out);
                random.zeroize();
            }

            #[cfg(test)]
            #[test]
            fn sample_support_matches_reference_c() {
                use crate::hqc::ffi::shake256_xof_ctx;
                for weight in [PARAM_OMEGA_R, PARAM_OMEGA_E] {
                    for seed_byte in 0..20u8 {
                        let seed = [seed_byte; SEED_BYTES];
                        let mut c_xof = shake256_xof_ctx { ctx: [0; 26] };
                        let mut rust_xof = shake256_xof_ctx { ctx: [0; 26] };
                        let mut expected = vec![0u32; weight as usize];
                        let mut got = vec![0u32; weight as usize];
                        unsafe {
                            c_xof_init(&mut c_xof, seed.as_ptr(), SEED_BYTES as u32);
                            c_xof_init(&mut rust_xof, seed.as_ptr(), SEED_BYTES as u32);
                            c_vect_generate_random_support2(
                                &mut c_xof,
                                expected.as_mut_ptr(),
                                weight,
                            );
                        }
                        sample_support(&mut rust_xof, &mut got);
                        assert_eq!(got, expected);
                    }
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
                const CRT_MODULI: &'static [crate::crt::Modulus] = &$crt_moduli;
                const CRT_GARNER: &'static [u8] = include_bytes!($crt_garner_file);

                type PublicKeyParameters = PublicKeyParameters;
                type SharedSecretParameters = SharedSecretParameters;
                type MessageParameters = MessageParameters;

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

                unsafe fn enc(entropy: &[u8], ct: &mut [u8], ss: &mut [u8], pk: &[u8]) -> i32 {
                    assert_eq!(ct.len(), CIPHERTEXT_BYTES);
                    assert_eq!(ss.len(), SHARED_SECRET_BYTES);
                    assert_eq!(pk.len(), PUBLIC_KEY_BYTES);
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
                    unsafe { c_crypto_kem_dec(ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) }
                }

                #[cfg(test)]
                fn kat_run(
                    seed: &[u8],
                    pk: &mut [u8],
                    sk: &mut [u8],
                    ct: &mut [u8],
                    ss: &mut [u8],
                ) {
                    let mut personal = [0u8; 0];
                    unsafe {
                        c_prng_init(
                            seed.as_ptr() as *mut u8,
                            personal.as_mut_ptr(),
                            seed.len() as u32,
                            0,
                        );
                        assert_eq!(c_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
                        assert_eq!(
                            c_crypto_kem_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr()),
                            0
                        );
                    }
                }

                fn ring_multiply(o: &mut [u64], a: &[u64], b: &[u64]) {
                    assert_eq!(o.len(), VEC_N_SIZE_64);
                    assert_eq!(a.len(), VEC_N_SIZE_64);
                    assert_eq!(b.len(), VEC_N_SIZE_64);
                    unsafe { vect_mul(o, a, b) }
                }

                fn compute_u_window(h_seed: &[u8], theta: &[u8], start: usize, out: &mut [u8]) {
                    use crate::hqc::ffi::{Vec256, shake256_xof_ctx};
                    assert_eq!(h_seed.len(), SEED_BYTES);
                    assert_eq!(theta.len(), SEED_BYTES);
                    assert!(start + out.len() <= VEC_N_SIZE_BYTES);

                    let words = start / 8..(start + out.len()).div_ceil(8);
                    let mut h = Vec256::<VEC_N_256_SIZE_64>::zeroed();
                    let mut r2 = Vec256::<VEC_N_256_SIZE_64>::zeroed();
                    let mut r1_window = Vec256::<VEC_N_256_SIZE_64>::zeroed();
                    let mut u = Vec256::<VEC_N_256_SIZE_64>::zeroed();
                    let mut r2_support = [0u32; PARAM_OMEGA_R as usize];
                    let mut r1_support = [0u32; PARAM_OMEGA_R as usize];
                    let mut skipped_e = [0u8; 4 * PARAM_OMEGA_E as usize];
                    let mut xof = shake256_xof_ctx { ctx: [0; 26] };

                    unsafe {
                        c_xof_init(&mut xof, h_seed.as_ptr(), SEED_BYTES as u32);
                        c_vect_set_random(&mut xof, h.as_mut_ptr());

                        c_xof_init(&mut xof, theta.as_ptr(), SEED_BYTES as u32);
                    }
                    sample_support(&mut xof, &mut r2_support);
                    unsafe {
                        c_xof_get_bytes(&mut xof, skipped_e.as_mut_ptr(), skipped_e.len() as u32);
                    }
                    sample_support(&mut xof, &mut r1_support);

                    crate::support::scatter_window(
                        &r2_support,
                        0,
                        &mut r2.words_mut()[..VEC_N_SIZE_64],
                    );
                    crate::support::scatter_window(
                        &r1_support,
                        words.start,
                        &mut r1_window.words_mut()[..words.len()],
                    );

                    unsafe {
                        c_vect_mul(u.as_mut_ptr(), r2.as_ptr(), h.as_ptr());
                    }
                    for (word, r1_word) in u.words_mut()[words.clone()]
                        .iter_mut()
                        .zip(r1_window.words())
                    {
                        *word ^= r1_word;
                    }

                    let u_bytes = unsafe {
                        core::slice::from_raw_parts(u.as_ptr() as *const u8, VEC_N_SIZE_BYTES)
                    };
                    out.copy_from_slice(&u_bytes[start..start + out.len()]);

                    r2.words_mut().zeroize();
                    r2_support.zeroize();
                    r1_support.zeroize();
                    r1_window.words_mut().zeroize();
                }

                fn reference_prng_stream(entropy: &[u8], out: &mut [u8]) {
                    let mut personal = [0u8; 0];
                    unsafe {
                        c_prng_init(
                            entropy.as_ptr() as *mut u8,
                            personal.as_mut_ptr(),
                            entropy.len() as u32,
                            0,
                        );
                        c_prng_get_bytes(out.as_mut_ptr(), out.len() as u32);
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

                    MessageParameters {
                        m: m_arr,
                        r1,
                        r2,
                        e,
                    }
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

                    MessageParameters {
                        m: m_arr,
                        r1: [0u64; VEC_N_SIZE_64],
                        r2,
                        e,
                    }
                }

                type SupportParameters = SupportParameters;

                fn partial_message_encaps_support(
                    m: &[u8],
                    theta: &[u8],
                ) -> Self::SupportParameters {
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
                    sample_support(&mut theta_xof_ctx, &mut r2);
                    sample_support(&mut theta_xof_ctx, &mut e);
                    sample_support(&mut theta_xof_ctx, &mut r1);

                    let mut m_arr = [0u8; PARAM_SECURITY_BYTES];
                    m_arr.copy_from_slice(m);

                    SupportParameters {
                        m: m_arr,
                        r1,
                        r2,
                        e,
                        r1_len: PARAM_OMEGA_R as usize,
                    }
                }

                fn partial_message_encaps_v_support(
                    m: &[u8],
                    theta: &[u8],
                ) -> Self::SupportParameters {
                    assert_eq!(m.len(), PARAM_SECURITY_BYTES);
                    assert_eq!(theta.len(), SEED_BYTES);
                    let mut theta_xof_ctx = crate::hqc::ffi::shake256_xof_ctx { ctx: [0; 26] };
                    unsafe {
                        c_xof_init(&mut theta_xof_ctx, theta.as_ptr(), SEED_BYTES as u32);
                    }

                    let mut r2 = [0u32; PARAM_OMEGA_R as usize];
                    let mut e = [0u32; PARAM_OMEGA_E as usize];

                    sample_support(&mut theta_xof_ctx, &mut r2);
                    sample_support(&mut theta_xof_ctx, &mut e);

                    let mut m_arr = [0u8; PARAM_SECURITY_BYTES];
                    m_arr.copy_from_slice(m);

                    SupportParameters {
                        m: m_arr,
                        r1: [0u32; PARAM_OMEGA_R as usize],
                        r2,
                        e,
                        r1_len: 0,
                    }
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

                    unsafe {
                        vect_mul(u, r2, h);
                        c_vect_add(
                            u.as_mut_ptr(),
                            r1.as_ptr(),
                            u.as_ptr(),
                            VEC_N_SIZE_64 as u32,
                        );

                        c_code_encode(v.as_mut_ptr(), m.as_ptr() as *const u64);

                        let mut tmp = [0u64; VEC_N_SIZE_64];
                        vect_mul(&mut tmp, r2, s);
                        c_vect_add(
                            tmp.as_mut_ptr(),
                            e.as_ptr(),
                            tmp.as_ptr(),
                            VEC_N_SIZE_64 as u32,
                        );
                        c_vect_truncate(tmp.as_mut_ptr());

                        c_vect_add(
                            v.as_mut_ptr(),
                            v.as_ptr(),
                            tmp.as_ptr(),
                            VEC_N1N2_SIZE_64 as u32,
                        );
                    }
                }

                fn serialize_ciphertext(ct: &mut [u8], u: &[u64], v: &[u64], salt: &[u8]) {
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
                    ct[VEC_N_SIZE_BYTES..VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES]
                        .copy_from_slice(v_bytes);
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
            pub unsafe fn keypair(
                entropy: &[u8],
                pk: &mut [u8; PUBLIC_KEY_BYTES],
                sk: &mut [u8; SECRET_KEY_BYTES],
            ) -> i32 {
                unsafe { <$struct_name as crate::hqc::HqcScheme>::keypair(entropy, pk, sk) }
            }

            /// Decapsulates a shared secret from a ciphertext using a secret key.
            ///
            /// Returns `0` on success.
            pub fn dec(
                ss: &mut [u8; SHARED_SECRET_BYTES],
                ct: &[u8; CIPHERTEXT_BYTES],
                sk: &[u8; SECRET_KEY_BYTES],
            ) -> i32 {
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
    crate::crt::params::HQC1_MODULI,
    "../crt/garner_hqc1.bin"
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
    crate::crt::params::HQC3_MODULI,
    "../crt/garner_hqc3.bin"
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
    crate::crt::params::HQC5_MODULI,
    "../crt/garner_hqc5.bin"
);

pub use hqc1::Hqc1;
pub use hqc3::Hqc3;
pub use hqc5::Hqc5;

#[cfg(test)]
mod tests {
    use super::*;

    const KAT_RECORDS_CHECKED: usize = 3;
    const ALL_KAT_RECORDS: usize = usize::MAX;

    struct KatRecord {
        seed: Vec<u8>,
        pk: Vec<u8>,
        sk: Vec<u8>,
        ct: Vec<u8>,
        ss: Vec<u8>,
    }

    fn kat_field(record: &str, name: &str) -> Vec<u8> {
        let prefix = format!("{name} = ");
        let line = record
            .lines()
            .find_map(|line| line.strip_prefix(prefix.as_str()))
            .unwrap();
        hex::decode(line.trim()).unwrap()
    }

    const KAT_FILE_HQC1: &str = include_str!("../../hqc/kats/ref/hqc-1/PQCkemKAT_2321.rsp");
    const KAT_FILE_HQC3: &str = include_str!("../../hqc/kats/ref/hqc-3/PQCkemKAT_4602.rsp");
    const KAT_FILE_HQC5: &str = include_str!("../../hqc/kats/ref/hqc-5/PQCkemKAT_7333.rsp");

    fn kat_file(level: u8) -> &'static str {
        match level {
            1 => KAT_FILE_HQC1,
            3 => KAT_FILE_HQC3,
            5 => KAT_FILE_HQC5,
            _ => unreachable!("HQC has levels 1, 3 and 5"),
        }
    }

    fn kat_records(level: u8, count: usize) -> Vec<KatRecord> {
        kat_file(level)
            .split("\n\n")
            .filter(|record| record.contains("count = "))
            .take(count)
            .map(|record| KatRecord {
                seed: kat_field(record, "seed"),
                pk: kat_field(record, "pk"),
                sk: kat_field(record, "sk"),
                ct: kat_field(record, "ct"),
                ss: kat_field(record, "ss"),
            })
            .collect()
    }

    fn test_decapsulation_matches_kat<T: HqcScheme>(level: u8) {
        for backend in crate::math::poly_mul::Backend::available() {
            for record in kat_records(level, KAT_RECORDS_CHECKED) {
                let mut ss = vec![0u8; T::SHARED_SECRET_BYTES];
                let status = backend.run_forced(|| T::dec(&mut ss, &record.ct, &record.sk));
                assert_eq!(status, 0, "{}", backend.name());
                assert_eq!(ss, record.ss, "{}", backend.name());
            }
        }
    }

    #[test]
    fn test_decapsulation_matches_kat_hqc1() {
        test_decapsulation_matches_kat::<Hqc1>(1);
    }

    #[test]
    fn test_decapsulation_matches_kat_hqc3() {
        test_decapsulation_matches_kat::<Hqc3>(3);
    }

    #[test]
    fn test_decapsulation_matches_kat_hqc5() {
        test_decapsulation_matches_kat::<Hqc5>(5);
    }

    fn test_full_kat<T: HqcScheme>(level: u8) {
        for record in kat_records(level, ALL_KAT_RECORDS) {
            let mut pk = vec![0u8; T::PUBLIC_KEY_BYTES];
            let mut sk = vec![0u8; T::SECRET_KEY_BYTES];
            let mut ct = vec![0u8; T::CIPHERTEXT_BYTES];
            let mut ss = vec![0u8; T::SHARED_SECRET_BYTES];
            T::kat_run(&record.seed, &mut pk, &mut sk, &mut ct, &mut ss);
            assert_eq!(pk, record.pk);
            assert_eq!(sk, record.sk);
            assert_eq!(ct, record.ct);
            assert_eq!(ss, record.ss);
            let mut decapsulated = vec![0u8; T::SHARED_SECRET_BYTES];
            assert_eq!(T::dec(&mut decapsulated, &record.ct, &record.sk), 0);
            assert_eq!(decapsulated, record.ss);
        }
    }

    #[test]
    fn test_full_kat_hqc1() {
        test_full_kat::<Hqc1>(1);
    }

    #[test]
    fn test_full_kat_hqc3() {
        test_full_kat::<Hqc3>(3);
    }

    #[test]
    fn test_full_kat_hqc5() {
        test_full_kat::<Hqc5>(5);
    }

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

    fn test_u_windows_match_reference_generic<T: HqcScheme>()
    where
        T::MessageParameters: HqcMessageParameters,
    {
        let mut pk = vec![0u8; T::PUBLIC_KEY_BYTES];
        let mut sk = vec![0u8; T::SECRET_KEY_BYTES];
        assert_eq!(unsafe { T::keypair(&[7u8; 48], &mut pk, &mut sk) }, 0);
        let pk_params = T::partial_public_key_encaps(&pk);
        let m = vec![0x3Cu8; T::PARAM_SECURITY_BYTES];
        let theta = [0x99u8; 32];
        let msg_params = T::partial_message_encaps(&m, &theta);
        let mut u = vec![0u64; T::VEC_N_SIZE_64];
        let mut v = vec![0u64; T::VEC_N_SIZE_64];
        T::encrypt_pke(&mut u, &mut v, &pk_params, &msg_params);
        let expected: Vec<u8> = u.iter().flat_map(|w| w.to_le_bytes()).collect();
        let expected = &expected[..T::VEC_N_SIZE_BYTES];

        let h_seed = &pk[..32];
        let mut whole = vec![0u8; T::VEC_N_SIZE_BYTES];
        T::compute_u(h_seed, &theta, &mut whole);
        assert_eq!(whole, expected);

        let window_len = 1100;
        let mut start = 0;
        while start < T::VEC_N_SIZE_BYTES {
            let len = window_len.min(T::VEC_N_SIZE_BYTES - start);
            let mut window = vec![0u8; len];
            T::compute_u_window(h_seed, &theta, start, &mut window);
            assert_eq!(window, &expected[start..start + len]);
            start += window_len;
        }
    }

    #[test]
    fn test_u_windows_match_reference() {
        test_u_windows_match_reference_generic::<Hqc1>();
        test_u_windows_match_reference_generic::<Hqc3>();
        test_u_windows_match_reference_generic::<Hqc5>();
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
