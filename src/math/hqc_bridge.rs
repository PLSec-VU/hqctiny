//! Bridge between HQC primitives and the protocol's K[z] polynomial representation.
//!
//! - Mask generation (non-CT; only polynomial degree matters).
//! - Reduction modulo x^n - 1 for mask stripping.

/// Reduce a polynomial modulo x^n - 1 (constant-time for fixed `n`).
///
/// Writes into `out`, which must be at least `n.div_ceil(64)` words.
/// Returns a subslice of `out` with the reduced polynomial.
pub fn reduce_mod_xn_minus_1<'o>(poly: &[u64], n: usize, out: &'o mut [u64]) -> &'o mut [u64] {
    let n_words = n.div_ceil(64);
    assert!(
        out.len() >= n_words,
        "reduce_mod_xn_minus_1 output buffer too small"
    );

    // The masked polynomial (u + m·(xⁿ-1)) has degree < 2n after
    // interpolation + combine - 2·n_words words is an upper bound.
    let max_words = 2 * n_words;
    let mut padded = vec![0u64; max_words];
    let copy_len = poly.len().min(max_words);
    padded[..copy_len].copy_from_slice(&poly[..copy_len]);

    out[..n_words].fill(0);

    for (wi, padded_word) in padded.iter().enumerate() {
        let word = *padded_word; // unconditional read
        let base = wi * 64;
        // Process each bit position (deterministic inner loop)
        for bi in 0..64 {
            let bit = (word >> bi) & 1;
            let pos = base + bi;
            let reduced = pos % n;
            let rw = reduced / 64;
            let rb = reduced % 64;
            out[rw] ^= bit << rb;
        }
    }

    // Truncate final word to exactly n bits
    let last_bits = n % 64;
    if last_bits != 0 {
        let mask = (1u64 << last_bits) - 1;
        out[n_words - 1] &= mask;
    }

    &mut out[..n_words]
}

/// Generate a quotient-blinding mask polynomial m of degree n-2.
///
/// Writes into `out`, which must be at least `n.div_ceil(64)` words.
/// Returns a subslice of `out` with the mask.
pub fn generate_mask<'o>(
    theta: &[u8],
    context: &[u8],
    n: usize,
    out: &'o mut [u64],
) -> &'o mut [u64] {
    let n_words = n.div_ceil(64);
    assert!(
        out.len() >= n_words,
        "generate_mask output buffer too small"
    );

    let cl = context.len();
    let tl = theta.len();
    let mut ctx_seed = [0u8; 128]; // stack alloc
    let ctx_seed = &mut ctx_seed[..tl + cl];
    ctx_seed[..tl].copy_from_slice(theta);
    ctx_seed[tl..tl + cl].copy_from_slice(context);

    let out_bytes = bytemuck::cast_slice_mut::<u64, u8>(&mut out[..n_words]);
    
    let mut hasher = blake3::Hasher::new();
    hasher.update(ctx_seed);
    hasher.update(b"mask");
    let mut xof = hasher.finalize_xof();
    xof.fill(out_bytes);

    // Any bits from n-1 upwards should be zero
    let valid_bits = n - 1;
    let full_words = valid_bits / 64;
    let extra_bits = valid_bits % 64;

    if full_words < n_words {
        let mask = (1u64 << extra_bits) - 1;
        out[full_words] &= mask;
        for w in out.iter_mut().take(n_words).skip(full_words + 1) {
            *w = 0;
        }
    }

    &mut out[..n_words]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_degree() {
        let theta = b"mask theta test _______________";
        let n: usize = 17669;
        let n_words = n.div_ceil(64);
        let mut buf = [0u64; 512];
        let mask = generate_mask(theta, b"mask", n, &mut buf);

        let last_bit = (n - 1) % 64;
        let last_word = (n - 1) / 64;
        if last_word < mask.len() {
            assert_eq!(
                (mask[last_word] >> last_bit) & 1,
                0,
                "bit n-1 should be zero (degree < n-1)"
            );
        }
        assert_eq!(mask.len(), n_words);
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
