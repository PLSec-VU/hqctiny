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
/// Each block has degree < W, and block `j`'s contribution is shifted by
/// `idx * j`. For every current parameter set the resulting max exponent
/// (`W - 1 + idx * (num_blocks - 1)`, at most 4804 of 9008 bits) stays under
/// DEGREE, so the accumulation never needs modular reduction at all — this
/// skips both the per-block `reduce` pass and its scratch copy that
/// `mul_by_x_pow_xor_into` would otherwise pay for. If a future caller's
/// idx/poly-length combination *does* exceed DEGREE, the accumulator is
/// sized to the true bound and a single reduction is applied at the end, so
/// correctness never depends on the fast-path assumption holding.
pub fn evaluate_poly_at_generator(poly: &[u64], idx: u8, out: &mut Gf2_9009) {
    use super::gf2_9009::reduce;

    *out = Gf2_9009::zero();
    if poly.is_empty() {
        return;
    }

    let total_bits = poly.len() * 64;
    let num_blocks = total_bits.div_ceil(W).max(1);
    let full_words = W / 64; // 70
    let remaining_bits = W % 64; // 25
    let mask = (1u64 << remaining_bits) - 1;

    let max_shift = (idx as usize) * (num_blocks - 1);
    let max_bit = max_shift + W - 1;
    let needs_reduce = max_bit >= DEGREE;
    let acc_words = (max_bit / 64 + 1).max(GF29009_NUM_U64 + 1);

    let mut acc = [0u64; 512];
    debug_assert!(acc_words <= acc.len(), "evaluation exceeds scratch buffer");

    for j in 0..num_blocks {
        let block_start_bit = j * W;
        let mut coeff_data = [0u64; GF29009_NUM_U64];

        for (w_out, coeff_word) in coeff_data[..full_words].iter_mut().enumerate() {
            *coeff_word = get_64_bits(poly, block_start_bit + w_out * 64);
        }
        // remaining_bits is always > 0 (W % 64 = 25)
        let last_word = get_64_bits(poly, block_start_bit + full_words * 64);
        coeff_data[full_words] = last_word & mask;

        let shift = (idx as usize) * j;
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        if bit_shift == 0 {
            for (i, &w) in coeff_data[..EFF_WORDS].iter().enumerate() {
                acc[i + word_shift] ^= w;
            }
        } else {
            let inv_shift = 64 - bit_shift;
            for (i, &w) in coeff_data[..EFF_WORDS].iter().enumerate() {
                acc[i + word_shift] ^= w << bit_shift;
                acc[i + word_shift + 1] ^= w >> inv_shift;
            }
        }
    }

    if needs_reduce {
        reduce(&mut acc[..acc_words], out);
    } else {
        // max_bit < DEGREE, so every set bit is already below the
        // normalization boundary — no need to clear anything.
        out.data.copy_from_slice(&acc[..GF29009_NUM_U64]);
    }
}

/// Evaluate a fixed-weight (sparse) F2[x] polynomial at generator^idx.
///
/// Scans set bits directly instead of processing every block, which is much
/// cheaper than `evaluate_poly_at_generator` when the vector's Hamming
/// weight is small relative to its length — the case for HQC's r1/r2/e
/// randomness vectors. Shares the same no-reduction-needed bound as
/// `evaluate_poly_at_generator` (see its doc comment); callers must ensure
/// `idx * (num_blocks - 1) + W - 1 < DEGREE`, which holds for all current
/// parameter sets.
pub fn evaluate_sparse_poly_at_generator(poly: &[u64], idx: u8, out: &mut Gf2_9009) {
    *out = Gf2_9009::zero();
    let idx = idx as usize;

    for (word_idx, &word) in poly.iter().enumerate() {
        let mut w = word;
        while w != 0 {
            let bit = w.trailing_zeros() as usize;
            w &= w - 1;
            let pos = word_idx * 64 + bit;
            let block = pos / W;
            let offset = pos % W;
            let exponent = offset + idx * block;
            let ew = exponent / 64;
            let eb = exponent % 64;
            debug_assert!(
                ew < GF29009_NUM_U64,
                "sparse evaluation exceeds field element width"
            );
            out.data[ew] ^= 1u64 << eb;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift64* so failures are reproducible.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545F4914F6CDD1D)
        }
    }

    /// Reference block-splitter mirroring the removed `split()`, kept local
    /// to this test as ground truth for `evaluate_poly_at_generator`.
    fn split_for_test(poly: &[u64]) -> Vec<Gf2_9009> {
        let total_bits = poly.len() * 64;
        let num_blocks = total_bits.div_ceil(W).max(1);
        let full_words = W / 64;
        let remaining_bits = W % 64;
        let mask = (1u64 << remaining_bits) - 1;
        let mut out = vec![Gf2_9009::zero(); num_blocks];
        for (k, block) in out.iter_mut().enumerate() {
            let mut data = [0u64; GF29009_NUM_U64];
            let block_start_bit = k * W;
            for (w_out, d) in data[..full_words].iter_mut().enumerate() {
                *d = get_64_bits(poly, block_start_bit + w_out * 64);
            }
            let last_word = get_64_bits(poly, block_start_bit + full_words * 64);
            data[full_words] = last_word & mask;
            *block = Gf2_9009::new(data);
        }
        out
    }

    /// The fast unreduced evaluator must agree with the always-correct
    /// (split + evaluate_at_generator) path for every current parameter
    /// set's VEC_N_SIZE_64 and point-index range.
    #[test]
    fn test_evaluate_poly_at_generator_matches_reference() {
        let mut rng = XorShift(0xC0FF_EE12_3456_789A);
        for &nwords in &[277usize, 561, 901] {
            let poly: Vec<u64> = (0..nwords).map(|_| rng.next()).collect();
            let blocks = split_for_test(&poly);
            for idx in 1..=25u8 {
                let mut expected = Gf2_9009::zero();
                evaluate_at_generator(&blocks, idx, &mut expected);
                let mut got = Gf2_9009::zero();
                evaluate_poly_at_generator(&poly, idx, &mut got);
                assert_eq!(got, expected, "mismatch nwords={nwords} idx={idx}");
            }
        }
    }

    /// The sparse evaluator must agree with the dense one on the same
    /// (few-bits-set) polynomial, mirroring HQC's fixed-weight r1/r2/e.
    #[test]
    fn test_evaluate_sparse_matches_dense() {
        let mut rng = XorShift(0xFACE_FEED_DEAD_BEEF);
        for &nwords in &[277usize, 561, 901] {
            let mut poly = vec![0u64; nwords];
            for _ in 0..20 {
                let bit = (rng.next() as usize) % (nwords * 64);
                poly[bit / 64] |= 1u64 << (bit % 64);
            }
            for idx in 1..=25u8 {
                let mut expected = Gf2_9009::zero();
                evaluate_poly_at_generator(&poly, idx, &mut expected);
                let mut got = Gf2_9009::zero();
                evaluate_sparse_poly_at_generator(&poly, idx, &mut got);
                assert_eq!(got, expected, "mismatch nwords={nwords} idx={idx}");
            }
        }
    }
}
