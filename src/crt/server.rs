use super::gf2x::{mul_mod, reduce_in_place, xor_into, xor_word_at};
use super::params::{MAX_RESIDUE_WORDS, Modulus};
use super::scatter::{scatter_buffer_words, scatter_support};
use crate::blinding;
use crate::hqc::{HqcScheme, HqcSupportParameters};
use crate::limits::MAX_VEC_N_SIZE_64;
use crate::math::xor::xor_shifted_into;

pub const QUOTIENT_MASK_CONTEXT: &[u8] = b"crt quotient mask";
pub const TRUNCATE_MASK_CONTEXT: &[u8] = b"crt truncate mask";
const MAX_SCATTER_WORDS: usize = MAX_VEC_N_SIZE_64.div_ceil(4) * 4;
const MAX_UNREDUCED_WORDS: usize = 2 * MAX_VEC_N_SIZE_64;

#[inline(always)]
fn quotient_mask_words<SCHEME: HqcScheme>(theta: &[u8], out: &mut [u64]) {
    let n = SCHEME::PARAM_N;
    let mask = blinding::generate_quotient_mask(theta, QUOTIENT_MASK_CONTEXT, n, out);
    mask[(n - 1) / 64] &= !(1u64 << ((n - 1) % 64));
}

#[inline(always)]
fn add_masked_remainder<SCHEME: HqcScheme>(
    theta: &[u8],
    m: &[u8],
    e_support: &[u32],
    unreduced: &mut [u64],
) {
    let n = SCHEME::PARAM_N;
    let n_words = SCHEME::VEC_N_SIZE_64;
    scatter_support(e_support, &mut unreduced[..scatter_buffer_words(n_words)]);

    let mut scratch = [0u64; MAX_VEC_N_SIZE_64];
    let scratch = &mut scratch[..n_words];
    SCHEME::code_encode(scratch, m);
    xor_into(unreduced, scratch);

    let truncate =
        blinding::truncate_mask_word(theta, TRUNCATE_MASK_CONTEXT, n, SCHEME::PARAM_N1N2);
    xor_word_at(unreduced, SCHEME::PARAM_N1N2, truncate);

    quotient_mask_words::<SCHEME>(theta, scratch);
    xor_shifted_into(unreduced, scratch, 0);
    xor_shifted_into(unreduced, scratch, n);
}

#[inline(always)]
pub fn residue_body<SCHEME: HqcScheme>(
    theta: &[u8],
    m: &[u8],
    modulus: Modulus,
    s_residue: &[u64],
    out: &mut [u64],
) {
    let n_words = SCHEME::VEC_N_SIZE_64;
    let words = modulus.words();
    let support = SCHEME::partial_message_encaps_v_support(m, theta);

    let mut r2 = [0u64; MAX_SCATTER_WORDS];
    scatter_support(support.r2(), &mut r2[..scatter_buffer_words(n_words)]);
    reduce_in_place(&mut r2[..n_words], modulus);
    let mut product = [0u64; MAX_RESIDUE_WORDS];
    mul_mod(s_residue, &r2[..words], modulus, &mut product);

    let mut unreduced = [0u64; MAX_UNREDUCED_WORDS];
    let unreduced = &mut unreduced[..2 * n_words];
    add_masked_remainder::<SCHEME>(theta, m, support.e(), unreduced);
    reduce_in_place(unreduced, modulus);

    out[..words].fill(0);
    xor_into(&mut out[..words], &product[..words]);
    xor_into(&mut out[..words], &unreduced[..words]);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,pclmulqdq,bmi2")]
fn residue_wide_simd<SCHEME: HqcScheme>(
    theta: &[u8],
    m: &[u8],
    modulus: Modulus,
    s_residue: &[u64],
    out: &mut [u64],
) {
    residue_body::<SCHEME>(theta, m, modulus, s_residue, out)
}

pub fn masked_residue<SCHEME: HqcScheme>(
    theta: &[u8],
    m: &[u8],
    modulus: Modulus,
    s_residue: &[u64],
    out: &mut [u64],
) {
    #[cfg(target_arch = "x86_64")]
    if crate::cpu::has_avx2_and_pclmulqdq() {
        return unsafe { residue_wide_simd::<SCHEME>(theta, m, modulus, s_residue, out) };
    }
    residue_body::<SCHEME>(theta, m, modulus, s_residue, out)
}
