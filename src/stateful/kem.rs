use crate::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};

const PRNG_ENTROPY_BYTES: usize = 48;

pub trait StatefulKem: HqcScheme {
    const LEVEL_ID: u8;

    fn encaps(entropy: &[u8; PRNG_ENTROPY_BYTES], pk: &[u8]) -> Option<(Vec<u8>, Vec<u8>)>;

    fn generate_keypair(entropy: &[u8; PRNG_ENTROPY_BYTES]) -> (Vec<u8>, Vec<u8>) {
        let mut pk = vec![0u8; Self::PUBLIC_KEY_BYTES];
        let mut sk = vec![0u8; Self::SECRET_KEY_BYTES];
        let status = unsafe { <Self as HqcScheme>::keypair(entropy, &mut pk, &mut sk) };
        assert_eq!(status, 0, "HQC keypair generation failed");
        (pk, sk)
    }

    fn decaps(ct: &[u8], sk: &[u8]) -> Option<Vec<u8>> {
        let mut ss = vec![0u8; Self::SHARED_SECRET_BYTES];
        (<Self as HqcScheme>::dec(&mut ss, ct, sk) == 0).then_some(ss)
    }
}

pub const ENTROPY_BYTES: usize = PRNG_ENTROPY_BYTES;

macro_rules! impl_stateful_kem {
    ($scheme:ty, $level:expr, $prefix:literal, $module:ident) => {
        mod $module {
            unsafe extern "C" {
                #[link_name = concat!($prefix, "prng_init")]
                pub(super) fn prng_init(
                    entropy_input: *mut u8,
                    personalization_string: *mut u8,
                    enlen: u32,
                    perlen: u32,
                );
                #[link_name = concat!($prefix, "crypto_kem_enc")]
                pub(super) fn crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> i32;
            }
        }

        impl StatefulKem for $scheme {
            const LEVEL_ID: u8 = $level;

            fn encaps(entropy: &[u8; PRNG_ENTROPY_BYTES], pk: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
                assert_eq!(pk.len(), Self::PUBLIC_KEY_BYTES);
                let mut ct = vec![0u8; Self::CIPHERTEXT_BYTES];
                let mut ss = vec![0u8; Self::SHARED_SECRET_BYTES];
                let mut seed = *entropy;
                let mut personalization = [0u8; 0];
                let status = {
                    unsafe {
                        $module::prng_init(
                            seed.as_mut_ptr(),
                            personalization.as_mut_ptr(),
                            PRNG_ENTROPY_BYTES as u32,
                            0,
                        );
                        $module::crypto_kem_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr())
                    }
                };
                (status == 0).then_some((ct, ss))
            }
        }
    };
}

impl_stateful_kem!(Hqc1, 1, "hqc_1_", ffi_hqc1);
impl_stateful_kem!(Hqc3, 3, "hqc_3_", ffi_hqc3);
impl_stateful_kem!(Hqc5, 5, "hqc_5_", ffi_hqc5);
