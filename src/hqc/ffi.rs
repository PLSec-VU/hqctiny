#[repr(C)]
#[derive(Clone, Copy)]
pub struct shake256_xof_ctx {
    pub ctx: [u64; 26],
}

/// Scratch buffer for the AVX2 sources, which take `__m256i *` where the
/// portable ones take `uint64_t *`.
///
/// Those routines work in whole 256-bit blocks: they write up to
/// `VEC_N_256_SIZE_64` words — past the end of a `VEC_N_SIZE_64` buffer — and
/// dereference the pointer at `__m256i` alignment. A Rust `[u64; VEC_N_SIZE_64]`
/// is neither long enough nor aligned enough, so the AVX2 paths sample into one
/// of these and copy the `VEC_N_SIZE_64`-word prefix they model back out.
#[repr(C, align(32))]
pub(crate) struct Vec256<const WORDS: usize> {
    words: [u64; WORDS],
}

impl<const WORDS: usize> Vec256<WORDS> {
    /// The C side XORs into its destination, so it must start zeroed.
    pub(crate) fn zeroed() -> Self {
        Self { words: [0; WORDS] }
    }

    /// Copies `src` into the low words, leaving the 256-bit padding zeroed.
    pub(crate) fn from_prefix(src: &[u64]) -> Self {
        let mut buf = Self::zeroed();
        buf.words[..src.len()].copy_from_slice(src);
        buf
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut u64 {
        self.words.as_mut_ptr()
    }

    pub(crate) fn as_ptr(&self) -> *const u64 {
        self.words.as_ptr()
    }

    pub(crate) fn words(&self) -> &[u64; WORDS] {
        &self.words
    }

    pub(crate) fn words_mut(&mut self) -> &mut [u64; WORDS] {
        &mut self.words
    }

    /// Copies back as many leading words as `dst` holds, dropping the padding.
    pub(crate) fn copy_prefix_to(&self, dst: &mut [u64]) {
        dst.copy_from_slice(&self.words[..dst.len()]);
    }
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

            #[link_name = concat!($prefix, "xof_get_bytes")]
            pub(crate) fn c_xof_get_bytes(
                xof_ctx: *mut $crate::hqc::ffi::shake256_xof_ctx,
                output: *mut u8,
                output_size: u32,
            );

            #[link_name = concat!($prefix, "vect_sample_fixed_weight2")]
            pub(crate) fn c_vect_sample_fixed_weight2(
                xof_ctx: *mut $crate::hqc::ffi::shake256_xof_ctx,
                v: *mut u64,
                weight: u16,
            );

            #[link_name = concat!($prefix, "code_encode")]
            pub(crate) fn c_code_encode(em: *mut u64, m: *const u64);

            #[link_name = concat!($prefix, "crypto_kem_enc")]
            pub(crate) fn c_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> i32;

            #[link_name = concat!($prefix, "vect_set_random")]
            pub(crate) fn c_vect_set_random(
                xof_ctx: *mut $crate::hqc::ffi::shake256_xof_ctx,
                v: *mut u64,
            );

            #[link_name = concat!($prefix, "vect_mul")]
            pub(crate) fn c_vect_mul(o: *mut u64, v1: *const u64, v2: *const u64);

            #[link_name = concat!($prefix, "prng_get_bytes")]
            pub(crate) fn c_prng_get_bytes(output: *mut u8, outlen: u32);
        }

        #[cfg(test)]
        unsafe extern "C" {
            /// The first half of `vect_sample_fixed_weight2`: draws `weight`
            /// distinct positions in [0, PARAM_N) from the XOF. The second
            /// half (`vect_write_support_to_vector`) scatters them into a
            /// dense PARAM_N-bit vector at O(VEC_N_SIZE_64 * weight) cost;
            /// callers that only need the positions skip it by calling this
            /// directly. `support` must hold at least `weight` u32s.
            #[link_name = concat!($prefix, "vect_generate_random_support2")]
            pub(crate) fn c_vect_generate_random_support2(
                xof_ctx: *mut $crate::hqc::ffi::shake256_xof_ctx,
                support: *mut u32,
                weight: u16,
            );

            #[link_name = concat!($prefix, "vect_add")]
            pub(crate) fn c_vect_add(o: *mut u64, v1: *const u64, v2: *const u64, size: u32);

            #[link_name = concat!($prefix, "vect_truncate")]
            pub(crate) fn c_vect_truncate(v: *mut u64);
        }
    };
}

pub(crate) use hqc_ffi_decls;
