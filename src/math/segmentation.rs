//! Polynomial segmentation for the Binius-style tower construction.
//!
//! Converts between F2[x] polynomials and vectors of GF(2^9009) field elements
//! by splitting coefficient blocks of size W = ceil(DEGREE/2).

use super::gf2_9009::{DEGREE, GF29009_NUM_U64, Gf2_9009};

/// Block size. Must satisfy DEGREE <= 2*W (HQCTiny.v: d_le_W2), otherwise the
/// kernel-blinding bijection of the security proof does not cover all kernel
/// residues; hence ceiling division, giving 4505 rather than 4504.
pub const W: usize = DEGREE.div_ceil(2); // 4505

/// Number of significant limbs in a split block (block width is W bits = 71 u64s).
pub const EFF_WORDS: usize = W.div_ceil(64); // 71

#[inline(always)]
fn get_64_bits(poly: &[u64], bit_idx: usize) -> u64 {
    let word_idx = bit_idx / 64;
    let shift = bit_idx % 64;
    if word_idx >= poly.len() {
        return 0;
    }
    let mut val = poly[word_idx] >> shift;
    if shift > 0 && word_idx + 1 < poly.len() {
        val |= poly[word_idx + 1] << (64 - shift);
    }
    val
}

/// Split an F2[x] polynomial into GF(2^9009) elements.
pub fn split(poly: &[u64]) -> Vec<Gf2_9009> {
    let total_bits = poly.len() * 64;
    let num_blocks = total_bits.div_ceil(W).max(1);
    let mut out = vec![Gf2_9009::zero(); num_blocks];

    #[allow(clippy::needless_range_loop)]
    for k in 0..num_blocks {
        let mut data = [0u64; GF29009_NUM_U64];
        let block_start_bit = k * W;

        let full_words = W / 64;
        let remaining_bits = W % 64;
        for w_out in 0..full_words {
            let bit_idx = block_start_bit + w_out * 64;
            data[w_out] = get_64_bits(poly, bit_idx);
        }
        if remaining_bits > 0 {
            let bit_idx = block_start_bit + full_words * 64;
            let last_word = get_64_bits(poly, bit_idx);
            let mask = (1u64 << remaining_bits) - 1;
            data[full_words] = last_word & mask;
        }

        out[k] = Gf2_9009::new(data);
    }
    out
}

#[inline(always)]
fn xor_64_bits(out: &mut [u64], bit_idx: usize, val: u64) {
    let word_idx = bit_idx / 64;
    let shift = bit_idx % 64;
    if word_idx < out.len() {
        out[word_idx] ^= val << shift;
    }
    if shift > 0 && word_idx + 1 < out.len() {
        out[word_idx + 1] ^= val >> (64 - shift);
    }
}

/// Combine a slice of GF(2^9009) elements back into an F2[x] polynomial.
pub fn combine(blocks: &[Gf2_9009]) -> Vec<u64> {
    if blocks.is_empty() {
        return vec![0];
    }

    let total_bits = (blocks.len() - 1) * W + DEGREE;
    let num_words = total_bits.div_ceil(64);
    let mut out = vec![0u64; num_words];

    for (k, elem) in blocks.iter().enumerate() {
        let block_start_bit = k * W;
        for w_in in 0..GF29009_NUM_U64 {
            let val = elem.data[w_in];
            xor_64_bits(&mut out, block_start_bit + w_in * 64, val);
        }
    }
    out
}

/// Evaluate a segmented polynomial at a generator point generator^idx.
pub fn evaluate_at_generator(blocks: &[Gf2_9009], idx: u8, out: &mut Gf2_9009) {
    *out = Gf2_9009::zero();
    let mut term = Gf2_9009::zero();

    for (j, coeff) in blocks.iter().enumerate() {
        coeff.mul_by_x_pow((idx as usize) * j, &mut term);
        out.add(&term);
    }
}

/// Split a packed GF(2) polynomial and evaluate it at generator^idx in one pass.
///
/// Equivalent to `evaluate_at_generator(&split(poly), idx, out)` but avoids
/// allocating the intermediate `Vec<Gf2_9009>` and processes each block with
/// the narrow-width shift variant (EFF_WORDS limbs instead of GF29009_NUM_U64).
pub fn evaluate_poly_at_generator(poly: &[u64], idx: u8, out: &mut Gf2_9009) {
    *out = Gf2_9009::zero();
    if poly.is_empty() {
        return;
    }

    let total_bits = poly.len() * 64;
    let num_blocks = total_bits.div_ceil(W).max(1);
    let full_words = W / 64; // 70
    let remaining_bits = W % 64; // 25
    let mask = (1u64 << remaining_bits) - 1;

    for j in 0..num_blocks {
        let block_start_bit = j * W;
        let mut coeff_data = [0u64; GF29009_NUM_U64];

        for (w_out, coeff_word) in coeff_data[..full_words].iter_mut().enumerate() {
            *coeff_word = get_64_bits(poly, block_start_bit + w_out * 64);
        }
        // remaining_bits is always > 0 (W % 64 = 25)
        let last_word = get_64_bits(poly, block_start_bit + full_words * 64);
        coeff_data[full_words] = last_word & mask;

        let coeff = Gf2_9009 { data: coeff_data };
        coeff.mul_by_x_pow_xor_into((idx as usize) * j, EFF_WORDS, out);
    }
}
