use core::simd::cmp::SimdPartialEq;
use core::simd::{Select, u64x4};

pub const MAX_SCATTER_WEIGHT: usize = 149;
const LANES: usize = 4;
const WORD_BITS: usize = 64;
const UNROLL: usize = 4;

pub fn scatter_quads(words: usize) -> usize {
    words.div_ceil(LANES)
}

pub fn scatter_buffer_words(words: usize) -> usize {
    scatter_quads(words) * LANES
}

#[inline(always)]
pub fn scatter_support(support: &[u32], out: &mut [u64]) {
    debug_assert!(support.len() <= MAX_SCATTER_WEIGHT);
    let weight = support.len();
    let lane_id = u64x4::from_array([0, 1, 2, 3]);
    let zero = u64x4::splat(0);

    let mut quad_of = [u64x4::splat(0); MAX_SCATTER_WEIGHT];
    let mut bit_in_lane = [u64x4::splat(0); MAX_SCATTER_WEIGHT];
    for (j, &position) in support.iter().enumerate() {
        let position = position as usize;
        let word = position / WORD_BITS;
        quad_of[j] = u64x4::splat((word / LANES) as u64);
        let lane_hit = u64x4::splat((word % LANES) as u64).simd_eq(lane_id);
        bit_in_lane[j] = lane_hit.select(u64x4::splat(1u64 << (position % WORD_BITS)), zero);
    }

    let quads = out.len() / LANES;
    let mut quad = 0;
    while quad + UNROLL <= quads {
        let ids = [0, 1, 2, 3].map(|k| u64x4::splat((quad + k) as u64));
        let mut acc = [zero; UNROLL];
        for j in 0..weight {
            for k in 0..UNROLL {
                acc[k] ^= quad_of[j].simd_eq(ids[k]).select(bit_in_lane[j], zero);
            }
        }
        for (k, a) in acc.iter().enumerate() {
            let at = (quad + k) * LANES;
            a.copy_to_slice(&mut out[at..at + LANES]);
        }
        quad += UNROLL;
    }
    while quad < quads {
        let id = u64x4::splat(quad as u64);
        let mut acc = zero;
        for j in 0..weight {
            acc ^= quad_of[j].simd_eq(id).select(bit_in_lane[j], zero);
        }
        acc.copy_to_slice(&mut out[quad * LANES..quad * LANES + LANES]);
        quad += 1;
    }
}
