macro_rules! define_hqc_variant {
    ($mod_name:ident, $prefix:literal, $pk_bytes:expr, $sk_bytes:expr, $ss_bytes:expr, $ct_bytes:expr) => {
        pub mod $mod_name {
            pub const PUBLIC_KEY_BYTES: usize = $pk_bytes;
            pub const SECRET_KEY_BYTES: usize = $sk_bytes;
            pub const SHARED_SECRET_BYTES: usize = $ss_bytes;
            pub const CIPHERTEXT_BYTES: usize = $ct_bytes;

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
        }
    };
}

define_hqc_variant!(hqc1, "hqc_1_", 2241, 2321, 32, 4433);
define_hqc_variant!(hqc3, "hqc_3_", 4514, 4602, 32, 8978);
define_hqc_variant!(hqc5, "hqc_5_", 7237, 7333, 32, 14421);

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
}
