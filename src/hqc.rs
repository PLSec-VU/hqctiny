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

    /// Seeds the internal global PRNG state.
    ///
    /// # Arguments
    /// * `entropy` - High-entropy seed input (usually 48 bytes).
    ///
    /// # Safety
    /// This function mutates global state and is not thread-safe.
    unsafe fn prng_init(entropy: &[u8]);

    /// Generates a public and secret keypair.
    ///
    /// Returns `0` on success.
    ///
    /// # Arguments
    /// * `pk` - Output buffer where the public key will be written. Must have length `Self::PUBLIC_KEY_BYTES`.
    /// * `sk` - Output buffer where the secret key will be written. Must have length `Self::SECRET_KEY_BYTES`.
    ///
    /// # Safety
    /// `prng_init` must have been called prior to calling this function.
    unsafe fn keypair(pk: &mut [u8], sk: &mut [u8]) -> i32;

    /// Encapsulates a shared secret.
    ///
    /// Returns `0` on success.
    ///
    /// # Arguments
    /// * `ct` - Output buffer where the ciphertext will be written. Must have length `Self::CIPHERTEXT_BYTES`.
    /// * `ss` - Output buffer where the shared secret will be written. Must have length `Self::SHARED_SECRET_BYTES`.
    /// * `pk` - Input public key buffer. Must have length `Self::PUBLIC_KEY_BYTES`.
    ///
    /// # Safety
    /// `prng_init` must have been called prior to calling this function.
    #[cfg(test)]
    unsafe fn enc(ct: &mut [u8], ss: &mut [u8], pk: &[u8]) -> i32;

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
    fn serialize_ciphertext(
        ct: &mut [u8],
        u: &[u64],
        v: &[u64],
        salt: &[u8],
    );
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct shake256_xof_ctx {
    pub ctx: [u64; 26],
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
        $vec_n_size_bytes:expr,
        $vec_n1n2_size_bytes:expr,
        $param_security_bytes:expr,
        $param_omega_r:expr,
        $param_omega_e:expr
    ) => {
        pub mod $mod_name {
            #[cfg(test)]
            use crate::hqc::{HqcPublicKeyParameters, HqcMessageParameters};

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

                type PublicKeyParameters = PublicKeyParameters;
                type SharedSecretParameters = SharedSecretParameters;
                type MessageParameters = MessageParameters;

                unsafe fn prng_init(entropy: &[u8]) {
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

                unsafe fn keypair(pk: &mut [u8], sk: &mut [u8]) -> i32 {
                    assert_eq!(pk.len(), PUBLIC_KEY_BYTES);
                    assert_eq!(sk.len(), SECRET_KEY_BYTES);
                    unsafe {
                        c_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
                    }
                }

                #[cfg(test)]
                unsafe fn enc(ct: &mut [u8], ss: &mut [u8], pk: &[u8]) -> i32 {
                    assert_eq!(ct.len(), CIPHERTEXT_BYTES);
                    assert_eq!(ss.len(), SHARED_SECRET_BYTES);
                    assert_eq!(pk.len(), PUBLIC_KEY_BYTES);
                    unsafe {
                        c_crypto_kem_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr())
                    }
                }

                fn dec(ss: &mut [u8], ct: &[u8], sk: &[u8]) -> i32 {
                    assert_eq!(ss.len(), SHARED_SECRET_BYTES);
                    assert_eq!(ct.len(), CIPHERTEXT_BYTES);
                    assert_eq!(sk.len(), SECRET_KEY_BYTES);
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

                    let mut m_arr = [0u8; PARAM_SECURITY_BYTES];
                    m_arr.copy_from_slice(m);

                    MessageParameters { m: m_arr, r1, r2, e }
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
                        c_vect_mul(u.as_mut_ptr(), r2.as_ptr(), h.as_ptr());
                        c_vect_add(u.as_mut_ptr(), r1.as_ptr(), u.as_ptr(), VEC_N_SIZE_64 as u32);

                        c_code_encode(v.as_mut_ptr(), m.as_ptr() as *const u64);

                        let mut tmp = [0u64; VEC_N_SIZE_64];
                        c_vect_mul(tmp.as_mut_ptr(), r2.as_ptr(), s.as_ptr());
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
            /// Seeds the internal global PRNG state required for keypair generation.
            ///
            /// # Safety
            /// This function mutates global state and is not thread-safe.
            pub unsafe fn prng_init(entropy: &[u8]) {
                unsafe {
                    <$struct_name as crate::hqc::HqcScheme>::prng_init(entropy);
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
                    <$struct_name as crate::hqc::HqcScheme>::keypair(pk, sk)
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

// Instantiate variants with respective parameters:
define_hqc_variant!(hqc1, Hqc1, "hqc_1_", 2241, 2321, 32, 4433, 277, 276, 2209, 2208, 16, 75, 75);
define_hqc_variant!(hqc3, Hqc3, "hqc_3_", 4514, 4602, 32, 8978, 561, 560, 4482, 4480, 24, 114, 114);
define_hqc_variant!(hqc5, Hqc5, "hqc_5_", 7237, 7333, 32, 14421, 901, 900, 7205, 7200, 32, 149, 149);

pub use hqc1::Hqc1;
pub use hqc3::Hqc3;
pub use hqc5::Hqc5;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_flow_generic<T: HqcScheme>() {
        unsafe {
            let entropy = [42u8; 48];
            T::prng_init(&entropy);

            let mut pk = vec![0u8; T::PUBLIC_KEY_BYTES];
            let mut sk = vec![0u8; T::SECRET_KEY_BYTES];
            assert_eq!(T::keypair(&mut pk, &mut sk), 0);

            let mut ct = vec![0u8; T::CIPHERTEXT_BYTES];
            let mut ss_enc = vec![0u8; T::SHARED_SECRET_BYTES];
            assert_eq!(T::enc(&mut ct, &mut ss_enc, &pk), 0);

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
        unsafe {
            let entropy = [42u8; 48];
            T::prng_init(&entropy);

            let mut pk = vec![0u8; T::PUBLIC_KEY_BYTES];
            let mut sk = vec![0u8; T::SECRET_KEY_BYTES];
            assert_eq!(T::keypair(&mut pk, &mut sk), 0);

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
            T::encrypt_pke(
                &mut u,
                &mut v,
                &pk_params,
                &msg_params,
            );

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
}
