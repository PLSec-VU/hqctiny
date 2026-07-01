#[repr(C)]
#[derive(Clone, Copy)]
pub struct shake256_xof_ctx {
    pub ctx: [u64; 26],
}

macro_rules! define_hqc_variant {
    (
        $mod_name:ident,
        $prefix:literal,
        $pk_bytes:expr,
        $sk_bytes:expr,
        $ss_bytes:expr,
        $ct_bytes:expr,
        $vec_n_size_64:expr,
        $vec_n1n2_size_64:expr,
        $vec_n_size_bytes:expr,
        $vec_n1n2_size_bytes:expr,
        $param_security_bytes:expr,
        $param_omega_r:expr,
        $param_omega_e:expr
    ) => {
        pub mod $mod_name {
            pub const PUBLIC_KEY_BYTES: usize = $pk_bytes;
            pub const SECRET_KEY_BYTES: usize = $sk_bytes;
            pub const SHARED_SECRET_BYTES: usize = $ss_bytes;
            pub const CIPHERTEXT_BYTES: usize = $ct_bytes;
            pub const VEC_N_SIZE_64: usize = $vec_n_size_64;
            pub const VEC_N1N2_SIZE_64: usize = $vec_n1n2_size_64;
            pub const VEC_N_SIZE_BYTES: usize = $vec_n_size_bytes;
            pub const VEC_N1N2_SIZE_BYTES: usize = $vec_n1n2_size_bytes;
            pub const PARAM_SECURITY_BYTES: usize = $param_security_bytes;
            pub const PARAM_OMEGA_R: u16 = $param_omega_r;
            pub const PARAM_OMEGA_E: u16 = $param_omega_e;
            pub const SALT_BYTES: usize = 16;
            pub const SEED_BYTES: usize = 32;

            pub struct PartialEncaps {
                pub K: [u8; SHARED_SECRET_BYTES],
                pub theta: [u8; SEED_BYTES],
                pub r1: [u64; VEC_N_SIZE_64],
                pub h: [u64; VEC_N_SIZE_64],
                pub r2: [u64; VEC_N_SIZE_64],
                pub s: [u64; VEC_N_SIZE_64],
                pub e: [u64; VEC_N_SIZE_64],
            }

            unsafe extern "C" {
                #[link_name = concat!($prefix, "prng_init")]
                pub(crate) fn c_prng_init(
                    entropy_input: *mut u8,
                    personalization_string: *mut u8,
                    enlen: u32,
                    perlen: u32,
                );

                #[link_name = concat!($prefix, "crypto_kem_keypair")]
                pub(crate) fn c_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> i32;

                #[cfg(test)]
                #[link_name = concat!($prefix, "crypto_kem_enc")]
                pub(crate) fn c_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> i32;

                #[link_name = concat!($prefix, "crypto_kem_dec")]
                pub(crate) fn c_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;

                #[link_name = concat!($prefix, "hash_h")]
                pub(crate) fn c_hash_h(output: *mut u8, ek_kem: *const u8);

                #[link_name = concat!($prefix, "hash_g")]
                pub(crate) fn c_hash_g(
                    output: *mut u8,
                    hash_ek_kem: *const u8,
                    m: *const u8,
                    salt: *const u8,
                );

                #[link_name = concat!($prefix, "hqc_ek_pke_from_string")]
                pub(crate) fn c_hqc_ek_pke_from_string(
                    h: *mut u64,
                    s: *mut u64,
                    ek_pke: *const u8,
                );

                #[link_name = concat!($prefix, "xof_init")]
                pub(crate) fn c_xof_init(
                    xof_ctx: *mut crate::hqc::shake256_xof_ctx,
                    seed: *const u8,
                    seed_size: u32,
                );

                #[link_name = concat!($prefix, "vect_sample_fixed_weight2")]
                pub(crate) fn c_vect_sample_fixed_weight2(
                    xof_ctx: *mut crate::hqc::shake256_xof_ctx,
                    v: *mut u64,
                    weight: u16,
                );

                #[cfg(test)]
                #[link_name = concat!($prefix, "vect_mul")]
                pub(crate) fn c_vect_mul(o: *mut u64, v1: *const u64, v2: *const u64);

                #[cfg(test)]
                #[link_name = concat!($prefix, "vect_add")]
                pub(crate) fn c_vect_add(o: *mut u64, v1: *const u64, v2: *const u64, size: u32);

                #[cfg(test)]
                #[link_name = concat!($prefix, "code_encode")]
                pub(crate) fn c_code_encode(em: *mut u64, m: *const u64);

                #[cfg(test)]
                #[link_name = concat!($prefix, "vect_truncate")]
                pub(crate) fn c_vect_truncate(v: *mut u64);
            }

            /// Seeds the internal global PRNG state required for keypair generation.
            ///
            /// # Safety
            /// This function mutates global state and is not thread-safe.
            pub unsafe fn prng_init(entropy: &[u8]) {
                let mut personal = [0u8; 0];
                unsafe {
                    c_prng_init(
                        entropy.as_ptr() as *mut u8,
                        personal.as_mut_ptr(),
                        entropy.len() as u32,
                        0,
                    );
                }
            }

            /// Generates a public and secret keypair.
            ///
            /// Returns `0` on success.
            ///
            /// # Safety
            /// `prng_init` must have been called prior to calling this function.
            pub unsafe fn keypair(pk: &mut [u8; PUBLIC_KEY_BYTES], sk: &mut [u8; SECRET_KEY_BYTES]) -> i32 {
                unsafe {
                    c_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
                }
            }

            /// Decapsulates a shared secret from a ciphertext using a secret key.
            ///
            /// Returns `0` on success.
            pub fn dec(ss: &mut [u8; SHARED_SECRET_BYTES], ct: &[u8; CIPHERTEXT_BYTES], sk: &[u8; SECRET_KEY_BYTES]) -> i32 {
                unsafe {
                    c_crypto_kem_dec(ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
                }
            }

            /// Performs partial deterministic KEM encapsulation, returning the key `K`,
            /// randomness `theta`, and intermediate vectors `r1`, `h`, `r2`, `s`, `e`.
            pub fn encaps_parameters(
                ek: &[u8; PUBLIC_KEY_BYTES],
                m: &[u8; PARAM_SECURITY_BYTES],
                salt: &[u8; SALT_BYTES],
            ) -> PartialEncaps {
                let mut hash_ek_kem = [0u8; SEED_BYTES];
                unsafe {
                    c_hash_h(hash_ek_kem.as_mut_ptr(), ek.as_ptr());
                }

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

                let mut h = [0u64; VEC_N_SIZE_64];
                let mut s = [0u64; VEC_N_SIZE_64];
                unsafe {
                    c_hqc_ek_pke_from_string(h.as_mut_ptr(), s.as_mut_ptr(), ek.as_ptr());
                }

                let mut theta_xof_ctx = crate::hqc::shake256_xof_ctx { ctx: [0; 26] };
                unsafe {
                    c_xof_init(&mut theta_xof_ctx, theta.as_ptr(), SEED_BYTES as u32);
                }

                let mut r2 = [0u64; VEC_N_SIZE_64];
                let mut e = [0u64; VEC_N_SIZE_64];
                let mut r1 = [0u64; VEC_N_SIZE_64];

                unsafe {
                    c_vect_sample_fixed_weight2(&mut theta_xof_ctx, r2.as_mut_ptr(), PARAM_OMEGA_R);
                    c_vect_sample_fixed_weight2(&mut theta_xof_ctx, e.as_mut_ptr(), PARAM_OMEGA_E);
                    c_vect_sample_fixed_weight2(&mut theta_xof_ctx, r1.as_mut_ptr(), PARAM_OMEGA_R);
                }

                PartialEncaps { K, theta, r1, h, r2, s, e }
            }
        }
    };
}

// Instantiate variants with respective parameters:
define_hqc_variant!(hqc1, "hqc_1_", 2241, 2321, 32, 4433, 277, 276, 2209, 2208, 16, 75, 75);
define_hqc_variant!(hqc3, "hqc_3_", 4514, 4602, 32, 8978, 561, 560, 4482, 4480, 24, 114, 114);
define_hqc_variant!(hqc5, "hqc_5_", 7237, 7333, 32, 14421, 901, 900, 7205, 7200, 32, 149, 149);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hqc1_flow() {
        unsafe {
            let entropy = [42u8; 48];
            hqc1::prng_init(&entropy);

            let mut pk = [0u8; hqc1::PUBLIC_KEY_BYTES];
            let mut sk = [0u8; hqc1::SECRET_KEY_BYTES];
            assert_eq!(hqc1::keypair(&mut pk, &mut sk), 0);

            let mut ct = [0u8; hqc1::CIPHERTEXT_BYTES];
            let mut ss_enc = [0u8; hqc1::SHARED_SECRET_BYTES];
            assert_eq!(hqc1::c_crypto_kem_enc(ct.as_mut_ptr(), ss_enc.as_mut_ptr(), pk.as_ptr()), 0);

            let mut ss_dec = [0u8; hqc1::SHARED_SECRET_BYTES];
            assert_eq!(hqc1::dec(&mut ss_dec, &ct, &sk), 0);

            assert_eq!(ss_enc, ss_dec);
            assert_ne!(ss_enc, [0u8; hqc1::SHARED_SECRET_BYTES]);
        }
    }

    #[test]
    fn test_hqc3_flow() {
        unsafe {
            let entropy = [43u8; 48];
            hqc3::prng_init(&entropy);

            let mut pk = [0u8; hqc3::PUBLIC_KEY_BYTES];
            let mut sk = [0u8; hqc3::SECRET_KEY_BYTES];
            assert_eq!(hqc3::keypair(&mut pk, &mut sk), 0);

            let mut ct = [0u8; hqc3::CIPHERTEXT_BYTES];
            let mut ss_enc = [0u8; hqc3::SHARED_SECRET_BYTES];
            assert_eq!(hqc3::c_crypto_kem_enc(ct.as_mut_ptr(), ss_enc.as_mut_ptr(), pk.as_ptr()), 0);

            let mut ss_dec = [0u8; hqc3::SHARED_SECRET_BYTES];
            assert_eq!(hqc3::dec(&mut ss_dec, &ct, &sk), 0);

            assert_eq!(ss_enc, ss_dec);
            assert_ne!(ss_enc, [0u8; hqc3::SHARED_SECRET_BYTES]);
        }
    }

    #[test]
    fn test_hqc5_flow() {
        unsafe {
            let entropy = [44u8; 48];
            hqc5::prng_init(&entropy);

            let mut pk = [0u8; hqc5::PUBLIC_KEY_BYTES];
            let mut sk = [0u8; hqc5::SECRET_KEY_BYTES];
            assert_eq!(hqc5::keypair(&mut pk, &mut sk), 0);

            let mut ct = [0u8; hqc5::CIPHERTEXT_BYTES];
            let mut ss_enc = [0u8; hqc5::SHARED_SECRET_BYTES];
            assert_eq!(hqc5::c_crypto_kem_enc(ct.as_mut_ptr(), ss_enc.as_mut_ptr(), pk.as_ptr()), 0);

            let mut ss_dec = [0u8; hqc5::SHARED_SECRET_BYTES];
            assert_eq!(hqc5::dec(&mut ss_dec, &ct, &sk), 0);

            assert_eq!(ss_enc, ss_dec);
            assert_ne!(ss_enc, [0u8; hqc5::SHARED_SECRET_BYTES]);
        }
    }

    #[test]
    fn test_hqc1_partial_encaps() {
        unsafe {
            let entropy = [42u8; 48];
            hqc1::prng_init(&entropy);

            let mut pk = [0u8; hqc1::PUBLIC_KEY_BYTES];
            let mut sk = [0u8; hqc1::SECRET_KEY_BYTES];
            assert_eq!(hqc1::keypair(&mut pk, &mut sk), 0);

            let m = [0xAAu8; hqc1::PARAM_SECURITY_BYTES];
            let salt = [0x55u8; hqc1::SALT_BYTES];

            // Perform partial deterministic encaps
            let res = hqc1::encaps_parameters(&pk, &m, &salt);

            // Reconstruct PKE ciphertext components u and v
            let mut u = [0u64; hqc1::VEC_N_SIZE_64];
            hqc1::c_vect_mul(u.as_mut_ptr(), res.r2.as_ptr(), res.h.as_ptr());
            hqc1::c_vect_add(u.as_mut_ptr(), res.r1.as_ptr(), u.as_ptr(), hqc1::VEC_N_SIZE_64 as u32);

            let mut v = [0u64; hqc1::VEC_N_SIZE_64];
            hqc1::c_code_encode(v.as_mut_ptr(), m.as_ptr() as *const u64);

            let mut tmp = [0u64; hqc1::VEC_N_SIZE_64];
            hqc1::c_vect_mul(tmp.as_mut_ptr(), res.r2.as_ptr(), res.s.as_ptr());
            hqc1::c_vect_add(tmp.as_mut_ptr(), res.e.as_ptr(), tmp.as_ptr(), hqc1::VEC_N_SIZE_64 as u32);
            hqc1::c_vect_truncate(tmp.as_mut_ptr());

            hqc1::c_vect_add(v.as_mut_ptr(), v.as_ptr(), tmp.as_ptr(), hqc1::VEC_N1N2_SIZE_64 as u32);

            // Serialize KEM ciphertext
            let mut ct = [0u8; hqc1::CIPHERTEXT_BYTES];
            let u_bytes = core::slice::from_raw_parts(u.as_ptr() as *const u8, hqc1::VEC_N_SIZE_BYTES);
            ct[..hqc1::VEC_N_SIZE_BYTES].copy_from_slice(u_bytes);

            let v_bytes = core::slice::from_raw_parts(v.as_ptr() as *const u8, hqc1::VEC_N1N2_SIZE_BYTES);
            ct[hqc1::VEC_N_SIZE_BYTES .. hqc1::VEC_N_SIZE_BYTES + hqc1::VEC_N1N2_SIZE_BYTES].copy_from_slice(v_bytes);
            ct[hqc1::VEC_N_SIZE_BYTES + hqc1::VEC_N1N2_SIZE_BYTES ..].copy_from_slice(&salt);

            // Decapsulate
            let mut ss_dec = [0u8; hqc1::SHARED_SECRET_BYTES];
            assert_eq!(hqc1::dec(&mut ss_dec, &ct, &sk), 0);

            // Verify they match
            assert_eq!(res.K, ss_dec);
        }
    }

    #[test]
    fn test_hqc3_partial_encaps() {
        unsafe {
            let entropy = [43u8; 48];
            hqc3::prng_init(&entropy);

            let mut pk = [0u8; hqc3::PUBLIC_KEY_BYTES];
            let mut sk = [0u8; hqc3::SECRET_KEY_BYTES];
            assert_eq!(hqc3::keypair(&mut pk, &mut sk), 0);

            let m = [0xAAu8; hqc3::PARAM_SECURITY_BYTES];
            let salt = [0x55u8; hqc3::SALT_BYTES];

            // Perform partial deterministic encaps
            let res = hqc3::encaps_parameters(&pk, &m, &salt);

            // Reconstruct PKE ciphertext components u and v
            let mut u = [0u64; hqc3::VEC_N_SIZE_64];
            hqc3::c_vect_mul(u.as_mut_ptr(), res.r2.as_ptr(), res.h.as_ptr());
            hqc3::c_vect_add(u.as_mut_ptr(), res.r1.as_ptr(), u.as_ptr(), hqc3::VEC_N_SIZE_64 as u32);

            let mut v = [0u64; hqc3::VEC_N_SIZE_64];
            hqc3::c_code_encode(v.as_mut_ptr(), m.as_ptr() as *const u64);

            let mut tmp = [0u64; hqc3::VEC_N_SIZE_64];
            hqc3::c_vect_mul(tmp.as_mut_ptr(), res.r2.as_ptr(), res.s.as_ptr());
            hqc3::c_vect_add(tmp.as_mut_ptr(), res.e.as_ptr(), tmp.as_ptr(), hqc3::VEC_N_SIZE_64 as u32);
            hqc3::c_vect_truncate(tmp.as_mut_ptr());

            hqc3::c_vect_add(v.as_mut_ptr(), v.as_ptr(), tmp.as_ptr(), hqc3::VEC_N1N2_SIZE_64 as u32);

            // Serialize KEM ciphertext
            let mut ct = [0u8; hqc3::CIPHERTEXT_BYTES];
            let u_bytes = core::slice::from_raw_parts(u.as_ptr() as *const u8, hqc3::VEC_N_SIZE_BYTES);
            ct[..hqc3::VEC_N_SIZE_BYTES].copy_from_slice(u_bytes);

            let v_bytes = core::slice::from_raw_parts(v.as_ptr() as *const u8, hqc3::VEC_N1N2_SIZE_BYTES);
            ct[hqc3::VEC_N_SIZE_BYTES .. hqc3::VEC_N_SIZE_BYTES + hqc3::VEC_N1N2_SIZE_BYTES].copy_from_slice(v_bytes);
            ct[hqc3::VEC_N_SIZE_BYTES + hqc3::VEC_N1N2_SIZE_BYTES ..].copy_from_slice(&salt);

            // Decapsulate
            let mut ss_dec = [0u8; hqc3::SHARED_SECRET_BYTES];
            assert_eq!(hqc3::dec(&mut ss_dec, &ct, &sk), 0);

            // Verify they match
            assert_eq!(res.K, ss_dec);
        }
    }

    #[test]
    fn test_hqc5_partial_encaps() {
        unsafe {
            let entropy = [44u8; 48];
            hqc5::prng_init(&entropy);

            let mut pk = [0u8; hqc5::PUBLIC_KEY_BYTES];
            let mut sk = [0u8; hqc5::SECRET_KEY_BYTES];
            assert_eq!(hqc5::keypair(&mut pk, &mut sk), 0);

            let m = [0xAAu8; hqc5::PARAM_SECURITY_BYTES];
            let salt = [0x55u8; hqc5::SALT_BYTES];

            // Perform partial deterministic encaps
            let res = hqc5::encaps_parameters(&pk, &m, &salt);

            // Reconstruct PKE ciphertext components u and v
            let mut u = [0u64; hqc5::VEC_N_SIZE_64];
            hqc5::c_vect_mul(u.as_mut_ptr(), res.r2.as_ptr(), res.h.as_ptr());
            hqc5::c_vect_add(u.as_mut_ptr(), res.r1.as_ptr(), u.as_ptr(), hqc5::VEC_N_SIZE_64 as u32);

            let mut v = [0u64; hqc5::VEC_N_SIZE_64];
            hqc5::c_code_encode(v.as_mut_ptr(), m.as_ptr() as *const u64);

            let mut tmp = [0u64; hqc5::VEC_N_SIZE_64];
            hqc5::c_vect_mul(tmp.as_mut_ptr(), res.r2.as_ptr(), res.s.as_ptr());
            hqc5::c_vect_add(tmp.as_mut_ptr(), res.e.as_ptr(), tmp.as_ptr(), hqc5::VEC_N_SIZE_64 as u32);
            hqc5::c_vect_truncate(tmp.as_mut_ptr());

            hqc5::c_vect_add(v.as_mut_ptr(), v.as_ptr(), tmp.as_ptr(), hqc5::VEC_N1N2_SIZE_64 as u32);

            // Serialize KEM ciphertext
            let mut ct = [0u8; hqc5::CIPHERTEXT_BYTES];
            let u_bytes = core::slice::from_raw_parts(u.as_ptr() as *const u8, hqc5::VEC_N_SIZE_BYTES);
            ct[..hqc5::VEC_N_SIZE_BYTES].copy_from_slice(u_bytes);

            let v_bytes = core::slice::from_raw_parts(v.as_ptr() as *const u8, hqc5::VEC_N1N2_SIZE_BYTES);
            ct[hqc5::VEC_N_SIZE_BYTES .. hqc5::VEC_N_SIZE_BYTES + hqc5::VEC_N1N2_SIZE_BYTES].copy_from_slice(v_bytes);
            ct[hqc5::VEC_N_SIZE_BYTES + hqc5::VEC_N1N2_SIZE_BYTES ..].copy_from_slice(&salt);

            // Decapsulate
            let mut ss_dec = [0u8; hqc5::SHARED_SECRET_BYTES];
            assert_eq!(hqc5::dec(&mut ss_dec, &ct, &sk), 0);

            // Verify they match
            assert_eq!(res.K, ss_dec);
        }
    }
}
