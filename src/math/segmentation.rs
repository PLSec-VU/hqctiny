//! Polynomial segmentation for the Binius-style tower construction.
//!
//! Converts between F2[x] polynomials and vectors of GF(2^9009) field elements
//! by splitting coefficient blocks of size W = ceil(DEGREE/2).

use super::gf2_9009::{DEGREE, GF29009_NUM_U64, Gf2_9009};

/// Block size. Must satisfy DEGREE <= 2*W (HQCLethe.v: d_le_W2), otherwise the
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

// `evaluate_sparse_poly_at_generator` used to live here: it scanned a dense
// fixed-weight vector's set bits with `trailing_zeros`. It was removed because
// it was not constant-time in the support — both the inner loop's trip count
// and the `out.data[ew]` store address derived from secret θ-derived bit
// positions — and because the dense vector it consumed was itself built by an
// O(VEC_N_SIZE_64 * weight) scatter from a support the caller already had.
// `evaluate_support_at_generator` below replaces both steps at once.

/// Largest `PARAM_OMEGA_R` / `PARAM_OMEGA_E` over all supported parameter
/// sets (HQC-5). Bounds the stack scratch in
/// `evaluate_support_at_generator`.
pub const MAX_SUPPORT_WEIGHT: usize = 149;

/// Evaluate a fixed-weight polynomial at generator^idx directly from its
/// support — the list of set-bit positions, as
/// `vect_generate_random_support2` produces it — without ever materialising
/// the dense `PARAM_N`-bit vector.
///
/// Equivalent to `evaluate_poly_at_generator` on the dense expansion of
/// `support`, provided the support entries are **distinct**: the dense path
/// ORs coincident positions into a single bit, whereas this one XORs them
/// and would cancel. HQC's Algorithm 5 sampler guarantees distinctness.
///
/// `acc_words` is the number of accumulator limbs the result can reach,
/// `ceil((W + idx_max*(num_blocks-1)) / 64)` — see
/// `encoding::public_eval_limbs`. Limbs at or above it are never written,
/// so sweeping only that prefix is both correct and ~1.9x less work than
/// sweeping all 141.
///
/// # Constant-time
/// The support values are secret (θ-derived HQC randomness), and this is
/// constant-time in them. Both loop bounds are public — `acc_words` is a
/// parameter-set constant and `support.len()` is the public weight — and
/// **every memory address is a loop counter**: `ew[j]`, `eb[j]` and
/// `out.data[i]` are never indexed by a support value. `pos % W` and
/// `pos / W` divide by a constant, so LLVM emits multiply-shift rather than
/// a `div` with operand-dependent latency (verified: the whole crate emits
/// no `div`).
///
/// The one remaining secret-dependent operation is the `1 << (exponent % 64)`
/// variable shift, which lowers to a single `shl %cl` — fixed-latency on
/// x86-64, as `lsl` is on aarch64. Valgrind flags it, since a variable shift
/// is not constant-time on every ISA; it is on both targets here.
///
/// Re-check with a ctgrind-style run: pass a `support` backed by
/// uninitialised memory and run under `valgrind -q --error-exitcode=9`.
/// Memcheck reports undefined values only when they reach a branch or an
/// address, so the sole expected finding is that one-byte shift count. Any
/// "Conditional jump or move depends on uninitialised value" is a real
/// regression — that check is what caught LLVM lowering `ct_eq_mask` back
/// into a branch during development.
pub fn evaluate_support_at_generator(
    support: &[u32],
    idx: u8,
    acc_words: usize,
    out: &mut Gf2_9009,
) {
    debug_assert!(acc_words <= GF29009_NUM_U64);
    debug_assert!(support.len() <= MAX_SUPPORT_WEIGHT);

    *out = Gf2_9009::zero();
    let idx = idx as usize;
    let weight = support.len();

    // Map each support position to (accumulator limb, bit within limb).
    // Indexed by the loop counter j, never by the position itself.
    let mut ew = [0u32; MAX_SUPPORT_WEIGHT];
    let mut eb = [0u64; MAX_SUPPORT_WEIGHT];
    for (j, &pos) in support.iter().enumerate() {
        let pos = pos as usize;
        let exponent = pos % W + idx * (pos / W);
        debug_assert!(
            exponent / 64 < acc_words,
            "exponent {exponent} exceeds acc_words {acc_words}"
        );
        ew[j] = (exponent / 64) as u32;
        eb[j] = 1u64 << (exponent % 64);
    }

    accumulate_masked(&ew[..weight], &eb[..weight], acc_words, out);
}

/// Constant-time masked accumulate: `out.data[i] ^= XOR of eb[j] where
/// ew[j] == i`, sweeping every `i` for every `j` so neither the branch
/// pattern nor the address stream depends on `ew`.
#[inline]
fn accumulate_masked(ew: &[u32], eb: &[u64], acc_words: usize, out: &mut Gf2_9009) {
    // SSE4.1 is not baseline x86-64 (that is SSE2), so this is detected rather
    // than assumed. The check is once per evaluation, not per iteration, and
    // reads only public data.
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("sse4.1") {
            unsafe {
                accumulate_masked_sse41(ew, eb, acc_words, out);
            }
            return;
        }
    }
    accumulate_masked_scalar(ew, eb, acc_words, out);
}

fn accumulate_masked_scalar(ew: &[u32], eb: &[u64], acc_words: usize, out: &mut Gf2_9009) {
    for i in 0..acc_words {
        let mut val = 0u64;
        for (&w, &b) in ew.iter().zip(eb) {
            val ^= b & ct_eq_mask(i as u32, w);
        }
        out.data[i] ^= val;
    }
}

/// Two-lane form of `accumulate_masked_scalar`, structured after the vendored
/// AVX2 `vect_write_support_to_vector` but comparing accumulator *pairs*.
///
/// Each entry is pre-broadcast to its pair index `ew[j] >> 1`, with its bit
/// mask confined to the correct 64-bit lane via `ew[j] & 1`. The inner loop is
/// then three SSE ops per entry. Four accumulator pairs are processed per pass
/// over the support so the two loads per entry feed four comparisons — the
/// loop is load-bound, not ALU-bound.
///
/// # Safety
/// Requires SSE4.1 (`_mm_cmpeq_epi64`); callers must check.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.1")]
unsafe fn accumulate_masked_sse41(ew: &[u32], eb: &[u64], acc_words: usize, out: &mut Gf2_9009) {
    use std::arch::x86_64::*;
    unsafe {
        let weight = ew.len();
        let mut blk = [_mm_setzero_si128(); MAX_SUPPORT_WEIGHT];
        let mut bit = [_mm_setzero_si128(); MAX_SUPPORT_WEIGHT];
        let lane_id = _mm_set_epi64x(1, 0);
        for j in 0..weight {
            let k = ew[j];
            blk[j] = _mm_set1_epi64x((k >> 1) as i64);
            let lane = _mm_cmpeq_epi64(_mm_set1_epi64x((k & 1) as i64), lane_id);
            bit[j] = _mm_and_si128(_mm_set1_epi64x(eb[j] as i64), lane);
        }

        // Round up: an odd acc_words (71 at HQC-1, 73 at HQC-3) makes the last
        // pair straddle limb `acc_words`. That is safe and needs no scalar
        // tail — `out.data` is always GF29009_NUM_U64 = 141 limbs, far wider
        // than any acc_words, and the straddling lane accumulates zero because
        // the degree bound puts no support element there. A scalar tail here
        // was measurably worse than useless: LLVM compiled its `ct_eq_mask`
        // into a conditional jump on secret data (caught by valgrind), which
        // is exactly the leak this function exists to remove.
        let npair = acc_words.div_ceil(2);
        debug_assert!(2 * npair <= GF29009_NUM_U64);
        let base = out.data.as_mut_ptr();
        let mut i = 0usize;

        while i + 4 <= npair {
            let z = _mm_setzero_si128();
            let (mut a0, mut a1, mut a2, mut a3) = (z, z, z, z);
            let v0 = _mm_set1_epi64x(i as i64);
            let v1 = _mm_set1_epi64x((i + 1) as i64);
            let v2 = _mm_set1_epi64x((i + 2) as i64);
            let v3 = _mm_set1_epi64x((i + 3) as i64);
            for j in 0..weight {
                let (b, k) = (bit[j], blk[j]);
                a0 = _mm_xor_si128(a0, _mm_and_si128(b, _mm_cmpeq_epi64(k, v0)));
                a1 = _mm_xor_si128(a1, _mm_and_si128(b, _mm_cmpeq_epi64(k, v1)));
                a2 = _mm_xor_si128(a2, _mm_and_si128(b, _mm_cmpeq_epi64(k, v2)));
                a3 = _mm_xor_si128(a3, _mm_and_si128(b, _mm_cmpeq_epi64(k, v3)));
            }
            let p = base.add(2 * i) as *mut __m128i;
            for (off, a) in [(0, a0), (1, a1), (2, a2), (3, a3)] {
                let q = p.add(off);
                _mm_storeu_si128(q, _mm_xor_si128(_mm_loadu_si128(q), a));
            }
            i += 4;
        }

        while i < npair {
            let mut a = _mm_setzero_si128();
            let v = _mm_set1_epi64x(i as i64);
            for j in 0..weight {
                a = _mm_xor_si128(a, _mm_and_si128(bit[j], _mm_cmpeq_epi64(blk[j], v)));
            }
            let q = base.add(2 * i) as *mut __m128i;
            _mm_storeu_si128(q, _mm_xor_si128(_mm_loadu_si128(q), a));
            i += 1;
        }
    }
}

/// All-ones if `a == b`, zero otherwise, without branching.
///
/// Uses `subtle` rather than the hand-rolled `(t | -t) >> 31` idiom: LLVM
/// recognises that pattern as `t != 0` and is free to lower it back to a
/// branch, which it did here until valgrind caught it. `subtle::Choice`
/// carries an optimisation barrier that prevents exactly that.
#[inline(always)]
fn ct_eq_mask(a: u32, b: u32) -> u64 {
    use subtle::ConstantTimeEq;
    (a.ct_eq(&b).unwrap_u8() as u64).wrapping_neg()
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

    /// Per-scheme (VEC_N_SIZE_64, PARAM_N, PARAM_OMEGA_R, POINTS_NUM).
    const SCHEMES: [(usize, usize, usize, u8); 3] = [
        (277, 17669, 75, 7),
        (561, 35851, 114, 15),
        (901, 57637, 149, 25),
    ];

    /// Number of accumulator words the evaluation can reach, mirroring
    /// `encoding::public_eval_limbs`.
    fn acc_words(nwords: usize, points: u8) -> usize {
        let num_blocks = (nwords * 64).div_ceil(W).max(1);
        (W + points as usize * (num_blocks - 1)).div_ceil(64)
    }

    /// A distinct-index support of the given weight, as
    /// `vect_generate_random_support2` produces.
    fn random_support(rng: &mut XorShift, weight: usize, n: usize) -> Vec<u32> {
        let mut sup: Vec<u32> = Vec::with_capacity(weight);
        while sup.len() < weight {
            let c = (rng.next() % n as u64) as u32;
            if !sup.contains(&c) {
                sup.push(c);
            }
        }
        sup
    }

    /// Evaluating straight from the support must equal expanding that support
    /// into a dense bit vector and running the existing dense evaluator. This
    /// is the property that lets the server skip the dense vector entirely.
    #[test]
    fn test_evaluate_support_matches_dense() {
        let mut rng = XorShift(0x5EED_1234_ABCD_9876);
        for &(nwords, n, weight, points) in &SCHEMES {
            let sup = random_support(&mut rng, weight, n);
            let mut poly = vec![0u64; nwords];
            for &p in &sup {
                poly[p as usize / 64] |= 1u64 << (p as usize % 64);
            }
            let aw = acc_words(nwords, points);
            for idx in 1..=points {
                let mut expected = Gf2_9009::zero();
                evaluate_poly_at_generator(&poly, idx, &mut expected);
                let mut got = Gf2_9009::zero();
                evaluate_support_at_generator(&sup, idx, aw, &mut got);
                assert_eq!(got, expected, "mismatch nwords={nwords} idx={idx}");
            }
        }
    }

    /// The vectorised accumulate must agree with the scalar one bit for bit,
    /// including at odd `acc_words` (71, 73) where the final limb takes the
    /// scalar tail and must not be written two limbs wide.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_accumulate_masked_sse_matches_scalar() {
        if !std::arch::is_x86_feature_detected!("sse4.1") {
            eprintln!("skipped: no SSE4.1 on this host");
            return;
        }
        let mut rng = XorShift(0x1DEA_5EED_0BAD_F00D);
        for &(nwords, n, weight, points) in &SCHEMES {
            let aw = acc_words(nwords, points);
            for idx in 1..=points {
                let sup = random_support(&mut rng, weight, n);
                let mut ew = [0u32; MAX_SUPPORT_WEIGHT];
                let mut eb = [0u64; MAX_SUPPORT_WEIGHT];
                for (j, &pos) in sup.iter().enumerate() {
                    let pos = pos as usize;
                    let exponent = pos % W + idx as usize * (pos / W);
                    ew[j] = (exponent / 64) as u32;
                    eb[j] = 1u64 << (exponent % 64);
                }
                let (ew, eb) = (&ew[..weight], &eb[..weight]);

                let mut want = Gf2_9009::zero();
                accumulate_masked_scalar(ew, eb, aw, &mut want);
                let mut got = Gf2_9009::zero();
                unsafe { accumulate_masked_sse41(ew, eb, aw, &mut got) };

                assert_eq!(got, want, "mismatch acc_words={aw} idx={idx}");
                // Nothing above acc_words may be touched, in particular no
                // two-limb store straddling the odd tail.
                assert!(
                    got.data[aw..].iter().all(|&w| w == 0),
                    "wrote past acc_words={aw}"
                );
            }
        }
    }
}
