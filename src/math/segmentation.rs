//! Polynomial segmentation for the Binius-style tower construction.
//!
//! Converts between F2[x] polynomials and vectors of GF(2^8984) field elements
//! by splitting coefficient blocks of size W = DEGREE/2.

use super::gf2_8984::{Gf2_8984, DEGREE, GF28984_NUM_U64};

/// Block size: half the field degree.
pub const W: usize = DEGREE / 2; // 4492

/// Split an F2[x] polynomial into GF(2^8984) elements.
pub fn split(poly: &[u64]) -> Vec<Gf2_8984> {
    let total_bits = poly.len() * 64;
    let num_blocks = total_bits.div_ceil(W).max(1);
    let mut out = vec![Gf2_8984::zero(); num_blocks];

    for (k, slot) in out.iter_mut().enumerate() {
        let mut data = [0u64; GF28984_NUM_U64];
        let block_start_bit = k * W;
        for j in 0..W {
            let bit_pos = block_start_bit + j;
            let word_idx = bit_pos / 64;
            let bit_idx = bit_pos % 64;
            let bit = if word_idx < poly.len() {
                (poly[word_idx] >> bit_idx) & 1
            } else {
                0
            };
            let out_word = j / 64;
            let out_bit = j % 64;
            data[out_word] ^= bit << out_bit;
        }
        *slot = Gf2_8984::new(data);
    }
    out
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
        for j in 0..DEGREE {
            let in_word = j / 64;
            let in_bit = j % 64;
            let bit = (elem.data[in_word] >> in_bit) & 1;
            let bit_pos = block_start_bit + j;
            let out_word = bit_pos / 64;
            let out_bit = bit_pos % 64;
            out[out_word] ^= bit << out_bit;
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
