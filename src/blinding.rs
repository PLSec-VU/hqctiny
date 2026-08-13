//! Blinding mask generation and stripping operations.
//!
//! This module provides functions to:
use crate::math::gf2_9009::{DEGREE, Gf2_9009};
use crate::math::segmentation::W;

/// Reduce a polynomial modulo x^n - 1 (constant-time for fixed `n`).
///
/// Writes into `out`, which must be at least `n.div_ceil(64)` words.
/// Returns a subslice of `out` with the reduced polynomial.
pub fn reduce_mod_xn_minus_1<'o>(poly: &[u64], n: usize, out: &'o mut [u64]) -> &'o mut [u64] {
    use core::simd::u64x4;

    let n_words = n.div_ceil(64);
    debug_assert!(
        out.len() >= n_words,
        "reduce_mod_xn_minus_1 output buffer too small"
    );

    // Base: low n_words of poly (poly may be shorter for mask polys of length n_words).
    out[..n_words].fill(0);
    let base = poly.len().min(n_words);
    out[..base].copy_from_slice(&poly[..base]);

    // Reads from poly beyond its length return 0 — the polynomial is zero there.
    let read = |idx: usize| -> u64 { if idx < poly.len() { poly[idx] } else { 0 } };

    let word_offset = n / 64;
    let bit_offset = n % 64;
    let shift_lo = u64x4::splat(bit_offset as u64);
    let shift_hi = u64x4::splat((64 - bit_offset) as u64);

    // Fold the words above bit n back down using SIMD chunks.
    let (out_chunks, out_tail) = out[..n_words].as_chunks_mut::<4>();
    let num_chunks = out_chunks.len();
    for (chunk_idx, out_quad) in out_chunks.iter_mut().enumerate() {
        let i = chunk_idx * 4;
        let r0 = read(word_offset + i);
        let r1 = read(word_offset + i + 1);
        let r2 = read(word_offset + i + 2);
        let r3 = read(word_offset + i + 3);
        let v_lo = u64x4::from_array([r0, r1, r2, r3]);
        let mut w = v_lo >> shift_lo;
        if bit_offset != 0 {
            let r4 = read(word_offset + i + 4);
            let v_hi = u64x4::from_array([r1, r2, r3, r4]);
            w ^= v_hi << shift_hi;
        }
        let cur = u64x4::from_array(*out_quad);
        *out_quad = (cur ^ w).to_array();
    }

    let start_tail = num_chunks * 4;
    for (idx, out_word) in out_tail.iter_mut().enumerate() {
        let i = start_tail + idx;
        let mut w = read(word_offset + i) >> bit_offset;
        if bit_offset != 0 {
            w ^= read(word_offset + i + 1) << (64 - bit_offset);
        }
        *out_word ^= w;
    }

    // Truncate final word to exactly n bits.
    let last_bits = n % 64;
    if last_bits != 0 {
        out[n_words - 1] &= (1u64 << last_bits) - 1;
    }

    &mut out[..n_words]
}

/// Fill `out` with BLAKE3 XOF output keyed by theta and context.
fn fill_mask_words(theta: &[u8], context: &[u8], out: &mut [u64]) {
    let cl = context.len();
    let tl = theta.len();
    let mut ctx_seed = [0u8; 128]; // stack alloc
    let ctx_seed = &mut ctx_seed[..tl + cl];
    ctx_seed[..tl].copy_from_slice(theta);
    ctx_seed[tl..tl + cl].copy_from_slice(context);

    let mut hasher = blake3::Hasher::new();
    hasher.update(ctx_seed);
    hasher.update(b"mask");
    let mut xof = hasher.finalize_xof();
    xof.fill(bytemuck::cast_slice_mut::<u64, u8>(out));
}

/// Clear all bits at positions >= start.
fn clear_bits_from(words: &mut [u64], start: usize) {
    let word = start / 64;
    if word >= words.len() {
        return;
    }
    words[word] &= (1u64 << (start % 64)) - 1;
    for w in &mut words[word + 1..] {
        *w = 0;
    }
}

/// Clear all bits at positions < end.
fn clear_bits_below(words: &mut [u64], end: usize) {
    let word = end / 64;
    let bit = end % 64;
    let full = word.min(words.len());
    words[..full].fill(0);
    if bit > 0 && word < words.len() {
        words[word] &= !((1u64 << bit) - 1);
    }
}

/// Writes into `out`, which must be at least `n.div_ceil(64)` words.
/// Returns a subslice of `out` with the mask.
pub fn generate_quotient_mask<'o>(
    theta: &[u8],
    context: &[u8],
    n: usize,
    out: &'o mut [u64],
) -> &'o mut [u64] {
    let n_words = n.div_ceil(64);
    debug_assert!(
        out.len() >= n_words,
        "generate_mask output buffer too small"
    );

    let out = &mut out[..n_words];
    fill_mask_words(theta, context, out);
    clear_bits_from(out, n);
    out
}

/// Writes into `out`, which must be at least `n.div_ceil(64)` words.
/// Returns a subslice of `out` with the mask.
pub fn generate_truncate_mask<'o>(
    theta: &[u8],
    context: &[u8],
    n: usize,
    n1n2: usize,
    out: &'o mut [u64],
) -> &'o mut [u64] {
    let n_words = n.div_ceil(64);
    debug_assert!(
        out.len() >= n_words,
        "generate_truncate_mask output buffer too small"
    );

    let out = &mut out[..n_words];
    fill_mask_words(theta, context, out);
    clear_bits_below(out, n1n2);
    clear_bits_from(out, n);
    out
}

/// Evaluate the truncate mask (random bits over [n1n2, n)) at a^idx, without
/// materializing the full `n`-bit mask polynomial.
///
/// The random region always fits inside a single W-block for every current
/// parameter set (verified: n1n2 % W + (n - n1n2) <= W for HQC-1/3/5), so we
/// only need the `n - n1n2` bits that survive `clear_bits_below`/`clear_bits_from`
/// instead of the full `n.div_ceil(64)`-word XOF fill, and the evaluation is
/// one `mul_by_x_pow` of a near-empty element instead of a full block-by-block
/// pass. `fill_mask_words` maps XOF byte `b` to bits `[8b, 8b+8)` of the mask
/// polynomial (little-endian byte order), so the surviving bits start at XOF
/// byte `n1n2 / 8`; BLAKE3's XOF supports O(1) seeking there instead of
/// discarding the bytes before it.
pub fn evaluate_truncate_mask_at_generator(
    theta: &[u8],
    context: &[u8],
    n: usize,
    n1n2: usize,
    idx: u8,
    out: &mut Gf2_9009,
) {
    let bits = n - n1n2;
    debug_assert!(
        bits <= 64,
        "truncate range must fit in one machine word for this fast path"
    );
    let block = n1n2 / W;
    let offset = n1n2 % W;
    debug_assert!(
        offset + bits <= W,
        "truncate range crosses a block boundary; fast path is invalid for these parameters"
    );

    let byte_start = n1n2 / 8;
    let bit_off_in_byte = n1n2 % 8;
    let byte_len = (bit_off_in_byte + bits).div_ceil(8);
    debug_assert!(byte_len <= 16);

    let mut hasher = blake3::Hasher::new();
    hasher.update(theta);
    hasher.update(context);
    hasher.update(b"mask");
    let mut xof = hasher.finalize_xof();
    xof.set_position(byte_start as u64);
    let mut bytes = [0u8; 16];
    xof.fill(&mut bytes[..byte_len]);

    let mut wide: u128 = 0;
    for (i, &b) in bytes[..byte_len].iter().enumerate() {
        wide |= (b as u128) << (8 * i);
    }
    wide >>= bit_off_in_byte;
    if bits < 128 {
        wide &= (1u128 << bits) - 1;
    }
    let word = wide as u64;

    let mut coeff = Gf2_9009::zero();
    let word_idx = offset / 64;
    let bit_shift = offset % 64;
    debug_assert!(word_idx + 1 < crate::math::gf2_9009::GF29009_NUM_U64);
    coeff.data[word_idx] ^= word << bit_shift;
    if bit_shift != 0 {
        coeff.data[word_idx + 1] ^= word >> (64 - bit_shift);
    }

    coeff.mul_by_x_pow((idx as usize) * block, out);
}

pub const KER_DELTA_BITS: usize = DEGREE - W;

pub fn num_kernel_deltas(n: usize) -> usize {
    2 * n.div_ceil(W) - 2
}

pub fn generate_kernel_deltas(theta: &[u8], context: &[u8], count: usize) -> Vec<Gf2_9009> {
    let delta_words = KER_DELTA_BITS.div_ceil(64);
    let rem_bits = KER_DELTA_BITS % 64;
    let mask = if rem_bits > 0 {
        (1u64 << rem_bits) - 1
    } else {
        u64::MAX
    };

    let mut hasher = blake3::Hasher::new();
    hasher.update(theta);
    hasher.update(context);
    let mut xof = hasher.finalize_xof();

    let mut deltas = vec![Gf2_9009::zero(); count];
    for delta in &mut deltas {
        xof.fill(bytemuck::cast_slice_mut::<u64, u8>(
            &mut delta.data[..delta_words],
        ));
        delta.data[delta_words - 1] &= mask;
    }
    deltas
}

/// Evaluate the kernel chain of `deltas` at the point a^power.
pub fn evaluate_ker_chain(deltas: &[Gf2_9009], power: usize) -> Gf2_9009 {
    let mut acc = Gf2_9009::zero();
    let eff_words = KER_DELTA_BITS.div_ceil(64); // 71 — deltas have no significant bits beyond this
    for (j, delta) in deltas.iter().enumerate() {
        delta.mul_by_x_pow_xor_into(W + power * j, eff_words, &mut acc);
        delta.mul_by_x_pow_xor_into(power * (j + 1), eff_words, &mut acc);
    }
    acc
}

/// Generate `count` kernel deltas from theta and evaluate their chain at
/// a^power in one pass, without materializing the `Vec<Gf2_9009>` that
/// `generate_kernel_deltas` + `evaluate_ker_chain` would otherwise allocate
/// (each element is a full 1128-byte `Gf2_9009` even though only 71 words
/// are ever significant). Streams one delta at a time from the XOF into a
/// reused buffer instead.
pub fn evaluate_kernel_deltas_at_generator(
    theta: &[u8],
    context: &[u8],
    count: usize,
    power: usize,
) -> Gf2_9009 {
    let delta_words = KER_DELTA_BITS.div_ceil(64);
    let rem_bits = KER_DELTA_BITS % 64;
    let mask = if rem_bits > 0 {
        (1u64 << rem_bits) - 1
    } else {
        u64::MAX
    };

    let mut hasher = blake3::Hasher::new();
    hasher.update(theta);
    hasher.update(context);
    let mut xof = hasher.finalize_xof();

    let mut acc = Gf2_9009::zero();
    let mut delta = Gf2_9009::zero();
    for j in 0..count {
        xof.fill(bytemuck::cast_slice_mut::<u64, u8>(
            &mut delta.data[..delta_words],
        ));
        delta.data[delta_words - 1] &= mask;
        delta.mul_by_x_pow_xor_into(W + power * j, delta_words, &mut acc);
        delta.mul_by_x_pow_xor_into(power * (j + 1), delta_words, &mut acc);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::segmentation::{combine, evaluate_at_generator, evaluate_poly_at_generator};

    #[test]
    fn test_truncate_mask() {
        let theta = b"mask theta test _______________";
        let n: usize = 17669;
        let n1n2: usize = 100;
        let n_words = n.div_ceil(64);
        let mut buf = [0u64; 512];
        let mask = generate_truncate_mask(theta, b"truncate mask", n, n1n2, &mut buf);

        // Check first n1n2 bits are zero
        for i in 0..n1n2 {
            let word = i / 64;
            let bit = i % 64;
            assert_eq!((mask[word] >> bit) & 1, 0, "bit {} should be zero", i);
        }

        // Check degree is < n
        assert_eq!(
            mask[n_words - 1] >> (n % 64),
            0,
            "bits from n upwards should be zero (degree < n)"
        );
        assert_eq!(mask.len(), n_words);
    }

    #[test]
    fn test_mask_degree() {
        let theta = b"mask theta test _______________";
        let n: usize = 17669;
        let n_words = n.div_ceil(64);
        let mut buf = [0u64; 512];
        let mask = generate_quotient_mask(theta, b"mask", n, &mut buf);

        assert_eq!(
            mask[n_words - 1] >> (n % 64),
            0,
            "bits from n upwards should be zero (degree < n)"
        );
        assert_eq!(mask.len(), n_words);
    }

    #[test]
    fn test_mask_contexts_independent() {
        let theta = b"mask theta test _______________";
        let n: usize = 17669;
        let mut buf_u = [0u64; 512];
        let mut buf_v = [0u64; 512];
        let mask_u = generate_quotient_mask(theta, b"quotient mask u", n, &mut buf_u).to_vec();
        let mask_v = generate_quotient_mask(theta, b"quotient mask v", n, &mut buf_v).to_vec();
        assert_ne!(mask_u, mask_v, "u and v masks must differ");
    }

    #[test]
    fn test_kernel_delta_degree() {
        let theta = b"kernel theta test ______________";
        let deltas = generate_kernel_deltas(theta, b"kernel deltas u", 6);
        assert_eq!(deltas.len(), 6);
        let delta_words = KER_DELTA_BITS.div_ceil(64);
        let rem_bits = KER_DELTA_BITS % 64;
        for delta in &deltas {
            assert_eq!(
                delta.data[delta_words - 1] >> rem_bits,
                0,
                "delta degree must be < KER_DELTA_BITS"
            );
            for w in &delta.data[delta_words..] {
                assert_eq!(*w, 0);
            }
        }
    }

    #[test]
    fn test_kernel_chain_vanishes_under_combine() {
        let theta = b"kernel theta test ______________";
        let count = 6;
        let deltas = generate_kernel_deltas(theta, b"kernel deltas u", count);

        // Chain coefficients in K[z]: C_j = delta_j * x^W + delta_{j-1}
        let mut chain = vec![Gf2_9009::zero(); count + 1];
        let mut shifted = Gf2_9009::zero();
        for (j, delta) in deltas.iter().enumerate() {
            delta.mul_by_x_pow(W, &mut shifted);
            chain[j].add(&shifted);
            chain[j + 1].add(delta);
        }

        // The chain lies in the kernel of combine, so the client's
        // interpolate + combine recovery is unaffected by it.
        let combined = combine(&chain);
        assert!(
            combined.iter().all(|&w| w == 0),
            "kernel chain must vanish under combine"
        );

        // The shift-based evaluator agrees with generic evaluation.
        for power in 1..=7u8 {
            let mut expected = Gf2_9009::zero();
            evaluate_at_generator(&chain, power, &mut expected);
            let got = evaluate_ker_chain(&deltas, power as usize);
            assert_eq!(got, expected, "evaluator mismatch at power {}", power);
        }
    }

    /// The fused streaming evaluator must agree with the original
    /// generate-then-evaluate path for the kernel chain.
    #[test]
    fn test_evaluate_kernel_deltas_at_generator_matches_reference() {
        let theta = b"kernel theta test ______________";
        let count = 6;
        let deltas = generate_kernel_deltas(theta, b"kernel deltas u", count);
        for power in 1..=25usize {
            let expected = evaluate_ker_chain(&deltas, power);
            let got = evaluate_kernel_deltas_at_generator(theta, b"kernel deltas u", count, power);
            assert_eq!(got, expected, "mismatch at power {}", power);
        }
    }

    /// The fast single-word truncate mask evaluator must agree with
    /// generating the full mask polynomial and evaluating it densely, for
    /// each real HQC-1/3/5 (n, n1n2) pair.
    #[test]
    fn test_evaluate_truncate_mask_at_generator_matches_reference() {
        let theta = b"truncate theta test _____________";
        let context = b"truncate mask";
        for &(n, n1n2) in &[(17669usize, 17664usize), (35851, 35840), (57637, 57600)] {
            let n_words = n.div_ceil(64);
            let mut buf = vec![0u64; n_words];
            let mask_poly = generate_truncate_mask(theta, context, n, n1n2, &mut buf).to_vec();

            for idx in 1..=25u8 {
                let mut expected = Gf2_9009::zero();
                evaluate_poly_at_generator(&mask_poly, idx, &mut expected);
                let mut got = Gf2_9009::zero();
                evaluate_truncate_mask_at_generator(theta, context, n, n1n2, idx, &mut got);
                assert_eq!(got, expected, "mismatch n={n} n1n2={n1n2} idx={idx}");
            }
        }
    }

    #[test]
    fn test_reduce_mod() {
        let n = 17669;
        let n_word = n / 64;
        let n_bit = n % 64;
        let mut poly = [0u64; 512];
        poly[n_word] |= 1u64 << n_bit;

        let mut out_buf = [0u64; 512];
        let reduced = reduce_mod_xn_minus_1(&poly[..n_word + 1], n, &mut out_buf);
        assert_eq!(reduced[0], 1, "x^n should reduce to 1");
        for item in reduced.iter().skip(1) {
            assert_eq!(*item, 0, "unexpected bits in reduced");
        }
    }
}
