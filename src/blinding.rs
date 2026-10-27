//! Reduction modulo x^n - 1 and the pseudorandom masks of the v half.

use chacha20::ChaCha12;
use chacha20::cipher::{KeyIvInit, StreamCipher};

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

const QUOTIENT_MASK_KEY_LABEL: &[u8] = b"quotient mask stream key";

fn keystream(theta: &[u8], context: &[u8], label: &[u8]) -> ChaCha12 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(theta);
    hasher.update(context);
    hasher.update(label);
    let key = *hasher.finalize().as_bytes();
    ChaCha12::new(&key.into(), &[0u8; 12].into())
}

fn fill_keystream(stream: &mut ChaCha12, out: &mut [u64]) {
    out.fill(0);
    stream.apply_keystream(bytemuck::cast_slice_mut::<u64, u8>(out));
}

fn fill_quotient_mask_words(theta: &[u8], context: &[u8], out: &mut [u64]) {
    let mut stream = keystream(theta, context, QUOTIENT_MASK_KEY_LABEL);
    fill_keystream(&mut stream, out);
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
    fill_quotient_mask_words(theta, context, out);
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

/// The random bits of the truncate mask, from bit `n1n2` up to bit `n`, as one
/// word. They equal bits `n1n2..n` of `generate_truncate_mask`, and the
/// BLAKE3 output is read from byte `n1n2 / 8` on instead of from the start.
#[inline(always)]
pub fn truncate_mask_word(theta: &[u8], context: &[u8], n: usize, n1n2: usize) -> u64 {
    let bits = n - n1n2;
    debug_assert!(
        bits <= 64,
        "truncate range must fit in one machine word for this fast path"
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
    wide as u64
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_truncate_mask_word_matches_full_mask() {
        let theta = b"truncate theta test _____________";
        let context = b"truncate mask";
        for &(n, n1n2) in &[(17669usize, 17664usize), (35851, 35840), (57637, 57600)] {
            let mut buf = vec![0u64; n.div_ceil(64)];
            let mask = generate_truncate_mask(theta, context, n, n1n2, &mut buf).to_vec();
            let word = truncate_mask_word(theta, context, n, n1n2);
            for bit in 0..n - n1n2 {
                let from_mask = (mask[(n1n2 + bit) / 64] >> ((n1n2 + bit) % 64)) & 1;
                assert_eq!(from_mask, (word >> bit) & 1, "n={n} bit={bit}");
            }
        }
    }
}
