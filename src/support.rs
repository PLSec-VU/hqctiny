//! Constant-time handling of the fixed-weight supports of HQC (the sorted-out
//! position lists that stand for `r1`, `r2` and `e`).
//!
//! Every loop bound and every memory index in this module comes from public
//! values (the weight, the vector size, the loop counters). A position is
//! only ever used as an operand of a comparison or a shift.

use core::simd::cmp::SimdPartialEq;
use core::simd::num::SimdUint;
use core::simd::{Select, u32x8, u64x4};

pub(crate) const MAX_SUPPORT_WEIGHT: usize = 149;

const SUPPORT_LANES: usize = 8;

const NO_POSITION: u32 = u32::MAX;

const WORD_LANES: usize = 4;

const WORD_GROUPS: usize = 4;

const WORDS_PER_BLOCK: usize = WORD_LANES * WORD_GROUPS;

/// Turns `weight` uniform random 32-bit words into a support of distinct
/// positions below `n`, exactly like HQC's `vect_generate_random_support2`.
pub(crate) fn finish_support(random: &[u32], n: u32, support: &mut [u32]) {
    #[cfg(target_arch = "x86_64")]
    if crate::cpu::has_avx2_and_pclmulqdq() {
        return unsafe { finish_support_wide_simd(random, n, support) };
    }
    finish_support_body(random, n, support)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,bmi2")]
fn finish_support_wide_simd(random: &[u32], n: u32, support: &mut [u32]) {
    finish_support_body(random, n, support)
}

#[inline(always)]
fn finish_support_body(random: &[u32], n: u32, support: &mut [u32]) {
    let weight = support.len();
    debug_assert_eq!(random.len(), weight);
    debug_assert!(weight <= MAX_SUPPORT_WEIGHT);

    let mut padded = [NO_POSITION; MAX_SUPPORT_WEIGHT + SUPPORT_LANES];
    for (i, (slot, &word)) in padded.iter_mut().zip(random).enumerate() {
        *slot = i as u32 + ((word as u64 * (n - i as u32) as u64) >> 32) as u32;
    }

    let all_ones = u32x8::splat(u32::MAX);
    let none = u32x8::splat(0);
    for i in (0..weight.saturating_sub(1)).rev() {
        let target = u32x8::splat(padded[i]);
        let mut seen = none;
        let mut j = i + 1;
        while j < weight {
            let later = u32x8::from_slice(&padded[j..j + SUPPORT_LANES]);
            seen |= later.simd_eq(target).select(all_ones, none);
            j += SUPPORT_LANES;
        }
        let found = seen.reduce_or();
        padded[i] = (padded[i] & !found) | (i as u32 & found);
    }

    support.copy_from_slice(&padded[..weight]);
}

#[inline(always)]
fn equal_mask(a: u64, b: u64) -> u64 {
    let difference = core::hint::black_box(a ^ b);
    let nonzero = (difference | difference.wrapping_neg()) >> 63;
    nonzero.wrapping_sub(1)
}

/// XORs the bit of every position into `out`, where `out[k]` stands for word
/// `first_word + k` of the dense vector. Positions outside the window leave
/// `out` unchanged.
pub(crate) fn scatter_window(support: &[u32], first_word: usize, out: &mut [u64]) {
    #[cfg(target_arch = "x86_64")]
    if crate::cpu::has_avx2_and_pclmulqdq() {
        return unsafe { scatter_window_wide_simd(support, first_word, out) };
    }
    scatter_window_body(support, first_word, out)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,bmi2")]
fn scatter_window_wide_simd(support: &[u32], first_word: usize, out: &mut [u64]) {
    scatter_window_body(support, first_word, out)
}

#[inline(always)]
fn scatter_window_body(support: &[u32], first_word: usize, out: &mut [u64]) {
    debug_assert!(support.len() <= MAX_SUPPORT_WEIGHT);
    let mut words = [0u64; MAX_SUPPORT_WEIGHT];
    let mut bits = [0u64; MAX_SUPPORT_WEIGHT];
    for (j, &position) in support.iter().enumerate() {
        words[j] = (position >> 6) as u64;
        bits[j] = 1u64 << (position & 63);
    }
    let words = &words[..support.len()];
    let bits = &bits[..support.len()];

    let lane_offsets = u64x4::from_array([0, 1, 2, 3]);
    let zero = u64x4::splat(0);
    let (blocks, tail) = out.as_chunks_mut::<WORDS_PER_BLOCK>();

    for (block_index, block) in blocks.iter_mut().enumerate() {
        let base = (first_word + block_index * WORDS_PER_BLOCK) as u64;
        let ids: [u64x4; WORD_GROUPS] =
            core::array::from_fn(|g| u64x4::splat(base + (g * WORD_LANES) as u64) + lane_offsets);
        let mut acc = [zero; WORD_GROUPS];
        for (&word, &bit) in words.iter().zip(bits) {
            let word = u64x4::splat(word);
            let bit = u64x4::splat(bit);
            for g in 0..WORD_GROUPS {
                acc[g] ^= ids[g].simd_eq(word).select(bit, zero);
            }
        }
        for (g, lane_group) in block.as_chunks_mut::<WORD_LANES>().0.iter_mut().enumerate() {
            let current = u64x4::from_array(*lane_group);
            *lane_group = (current ^ acc[g]).to_array();
        }
    }

    let tail_base = first_word + blocks.len() * WORDS_PER_BLOCK;
    for (k, out_word) in tail.iter_mut().enumerate() {
        let word_index = (tail_base + k) as u64;
        let mut acc = 0u64;
        for (&word, &bit) in words.iter().zip(bits) {
            acc ^= bit & equal_mask(word, word_index);
        }
        *out_word ^= acc;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545F4914F6CDD1D)
        }
    }

    fn reference_finish(random: &[u32], n: u32) -> Vec<u32> {
        let weight = random.len();
        let mut support: Vec<u32> = random
            .iter()
            .enumerate()
            .map(|(i, &word)| i as u32 + ((word as u64 * (n - i as u32) as u64) >> 32) as u32)
            .collect();
        for i in (0..weight.saturating_sub(1)).rev() {
            let duplicated = (i + 1..weight).any(|j| support[j] == support[i]);
            if duplicated {
                support[i] = i as u32;
            }
        }
        support
    }

    #[test]
    fn finish_support_matches_scalar_reference() {
        let mut rng = XorShift(0x5EED_5EED_1234_4321);
        for (n, weight) in [
            (17669u32, 66usize),
            (35851, 114),
            (57637, 149),
            (17669, 75),
            (100, 60),
        ] {
            for _ in 0..50 {
                let random: Vec<u32> = (0..weight).map(|_| rng.next() as u32).collect();
                let mut got = vec![0u32; weight];
                finish_support(&random, n, &mut got);
                assert_eq!(got, reference_finish(&random, n));
            }
        }
    }

    #[test]
    fn finish_support_resolves_forced_collisions() {
        let random = vec![0u32; 40];
        let mut got = vec![0u32; 40];
        finish_support(&random, 1000, &mut got);
        assert_eq!(got, reference_finish(&random, 1000));
    }

    #[test]
    fn scatter_window_matches_bit_by_bit_expansion() {
        let mut rng = XorShift(0xABCD_EF01_2345_6789);
        let n = 17669u32;
        let words = (n as usize).div_ceil(64);
        for _ in 0..20 {
            let support: Vec<u32> = (0..66).map(|_| (rng.next() % n as u64) as u32).collect();
            let mut dense = vec![0u64; words];
            for &position in &support {
                dense[(position / 64) as usize] ^= 1 << (position % 64);
            }
            for (first_word, len) in [(0, words), (0, 40), (13, 77), (100, 151), (words - 5, 5)] {
                let mut got = vec![0u64; len];
                scatter_window(&support, first_word, &mut got);
                assert_eq!(got, dense[first_word..first_word + len]);
            }
        }
    }
}
