//! Polynomial segmentation for the Binius-style tower construction.
//!
//! Converts between F2[x] polynomials and vectors of GF(2^8984) field elements
//! by splitting coefficient blocks of size W = DEGREE/2.

use super::gf2_8984::{Gf2_8984, DEGREE, GF28984_NUM_U64};

/// Block size: half the field degree.
pub const W: usize = DEGREE / 2; // 4492

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

/// Split an F2[x] polynomial into GF(2^8984) elements.
pub fn split(poly: &[u64]) -> Vec<Gf2_8984> {
    let total_bits = poly.len() * 64;
    let num_blocks = total_bits.div_ceil(W).max(1);
    let mut out = vec![Gf2_8984::zero(); num_blocks];

    for k in 0..num_blocks {
        let mut data = [0u64; GF28984_NUM_U64];
        let block_start_bit = k * W;

        // 4492 bits = 70 words of 64 bits (4480 bits) + 1 word of 12 bits
        for w_out in 0..70 {
            let bit_idx = block_start_bit + w_out * 64;
            data[w_out] = get_64_bits(poly, bit_idx);
        }
        let bit_idx = block_start_bit + 70 * 64;
        let last_word = get_64_bits(poly, bit_idx);
        data[70] = last_word & ((1u64 << 12) - 1);

        out[k] = Gf2_8984::new(data);
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

/// Combine a slice of GF(2^8984) elements back into an F2[x] polynomial.
pub fn combine(blocks: &[Gf2_8984]) -> Vec<u64> {
    if blocks.is_empty() {
        return vec![0];
    }

    let total_bits = (blocks.len() - 1) * W + DEGREE;
    let num_words = total_bits.div_ceil(64);
    let mut out = vec![0u64; num_words];

    for (k, elem) in blocks.iter().enumerate() {
        let block_start_bit = k * W;
        for w_in in 0..GF28984_NUM_U64 {
            let val = elem.data[w_in];
            xor_64_bits(&mut out, block_start_bit + w_in * 64, val);
        }
    }
    out
}

/// Evaluate a segmented polynomial at a generator point generator^idx.
pub fn evaluate_at_generator(blocks: &[Gf2_8984], idx: u8, out: &mut Gf2_8984) {
    *out = Gf2_8984::zero();
    let generator = {
        let mut d = [0u64; GF28984_NUM_U64];
        d[0] = 2; // bit 1 is generator a = x^1
        Gf2_8984::new(d)
    };

    // point = generator^idx
    let mut point = Gf2_8984::one();
    for _ in 0..idx {
        point.mul(&generator);
    }

    let mut term_pow = Gf2_8984::one();
    for coeff in blocks {
        let mut term = *coeff;
        term.mul(&term_pow);
        out.add(&term);
        term_pow.mul(&point);
    }
}
