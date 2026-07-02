use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    pub static ref FFI_LOCK: Mutex<()> = Mutex::new(());
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct shake256_xof_ctx {
    pub ctx: [u64; 26],
}

macro_rules! hqc_ffi_decls {
    ($prefix:literal) => {
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
            pub(crate) fn c_hqc_ek_pke_from_string(h: *mut u64, s: *mut u64, ek_pke: *const u8);

            #[link_name = concat!($prefix, "xof_init")]
            pub(crate) fn c_xof_init(
                xof_ctx: *mut $crate::hqc::ffi::shake256_xof_ctx,
                seed: *const u8,
                seed_size: u32,
            );

            #[link_name = concat!($prefix, "vect_sample_fixed_weight2")]
            pub(crate) fn c_vect_sample_fixed_weight2(
                xof_ctx: *mut $crate::hqc::ffi::shake256_xof_ctx,
                v: *mut u64,
                weight: u16,
            );

            #[cfg(test)]
            #[link_name = concat!($prefix, "vect_mul")]
            pub(crate) fn c_vect_mul(o: *mut u64, v1: *const u64, v2: *const u64);

            #[cfg(test)]
            #[link_name = concat!($prefix, "vect_add")]
            pub(crate) fn c_vect_add(o: *mut u64, v1: *const u64, v2: *const u64, size: u32);

            #[link_name = concat!($prefix, "code_encode")]
            pub(crate) fn c_code_encode(em: *mut u64, m: *const u64);

            #[cfg(test)]
            #[link_name = concat!($prefix, "vect_truncate")]
            pub(crate) fn c_vect_truncate(v: *mut u64);
        }
    };
}

pub(crate) use hqc_ffi_decls;
