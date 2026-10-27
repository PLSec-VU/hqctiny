//! Carry-less multiplication of GF(2) polynomials stored as u64 limbs.
//!
//! The recursion (Toom-3 over Karatsuba over a schoolbook base) exists in up
//! to two copies. The portable copy computes each 64x64 carry-less product in
//! software. The hardware copy is compiled with the CPU's carry-less multiply
//! instruction enabled, so the product inlines into the schoolbook base case.
//! `poly_mul` picks the copy once per call.

use super::xor::simd_xor_assign;

pub const SCRATCH_WORDS: usize = 768;

const SCHOOLBOOK_MAX_WORDS: usize = 8;

const TOOM3_MIN_WORDS: usize = 100;

const NEON_SCHOOLBOOK_MAX_WORDS: usize = 6;

const NEON_TOOM3_MIN_WORDS: usize = 64;

const fn scratch_words_for(words: usize, schoolbook_max: usize, toom3_min: usize) -> usize {
    if words <= schoolbook_max {
        0
    } else if words < toom3_min {
        let half = words.div_ceil(2);
        4 * half + scratch_words_for(half, schoolbook_max, toom3_min)
    } else {
        let third = words.div_ceil(3);
        8 * third + 12 + scratch_words_for(third + 2, schoolbook_max, toom3_min)
    }
}

const fn max_words(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

pub const fn scratch_words(words: usize) -> usize {
    max_words(
        scratch_words_for(words, SCHOOLBOOK_MAX_WORDS, TOOM3_MIN_WORDS),
        scratch_words_for(words, NEON_SCHOOLBOOK_MAX_WORDS, NEON_TOOM3_MIN_WORDS),
    )
}

#[cfg(test)]
fn software_clmul(a: u64, b: u64) -> u128 {
    let mut shifted = b as u128;
    let mut product = 0u128;
    for bit in 0..u64::BITS {
        let mask = 0u128.wrapping_sub(((a >> bit) & 1) as u128);
        product ^= shifted & mask;
        shifted <<= 1;
    }
    product
}

const HOLE_MASKS: [u64; 4] = [
    0x1111_1111_1111_1111,
    0x2222_2222_2222_2222,
    0x4444_4444_4444_4444,
    0x8888_8888_8888_8888,
];

#[inline(always)]
fn low_half_clmul_with_holes(a: u64, b: u64) -> u64 {
    let a = HOLE_MASKS.map(|mask| a & mask);
    let b = HOLE_MASKS.map(|mask| b & mask);
    let mut folded = 0u64;
    for (target, mask) in HOLE_MASKS.iter().enumerate() {
        let lane = a.iter().enumerate().fold(0u64, |lane, (i, &a_part)| {
            let j = (target + HOLE_MASKS.len() - i) % HOLE_MASKS.len();
            lane ^ a_part.wrapping_mul(b[j])
        });
        folded |= lane & mask;
    }
    folded
}

#[inline(always)]
fn holes_clmul(a: u64, b: u64) -> u128 {
    let low = low_half_clmul_with_holes(a, b);
    let reversed_high = low_half_clmul_with_holes(a.reverse_bits(), b.reverse_bits());
    let high = reversed_high.reverse_bits() >> 1;
    ((high as u128) << 64) | low as u128
}

macro_rules! product_schoolbook {
    ($(#[$feature:meta])*) => {
        $(#[$feature])*
        fn schoolbook_mul(a: &[u64], b: &[u64], out: &mut [u64]) {
            let columns = a.len() + b.len() - 1;
            let mut carry = 0u64;
            for column in 0..columns {
                let first = column.saturating_sub(b.len() - 1);
                let last = column.min(a.len() - 1);
                let mut sum = product_zero();
                for i in first..=last {
                    sum = product_xor(sum, product_mul(a[i], b[column - i]));
                }
                out[column] ^= product_low(sum) ^ carry;
                carry = product_high(sum);
            }
            out[columns] ^= carry;
        }
    };
}

macro_rules! poly_mul_family {
    ($(#[$feature:meta])*) => {
    /// Multiplies two equal-length slices of u64 that represent GF(2)
    /// polynomials. `out[..2n]` must be zero on entry; the product is XORed into
    /// it.
    $(#[$feature])*
    pub(super) fn poly_mul(a: &[u64], b: &[u64], out: &mut [u64], scratch: &mut [u64]) {
        debug_assert_eq!(a.len(), b.len());
        debug_assert!(out.len() >= 2 * a.len());

        if a.len() <= SCHOOLBOOK_MAX_WORDS {
            schoolbook_mul(a, b, out);
        } else if a.len() < TOOM3_MIN_WORDS {
            karatsuba_step(a, b, out, scratch);
        } else {
            toom3_step(a, b, out, scratch);
        }
    }

    /// One Karatsuba level. The halves are split at ceil(n/2), so no
    /// power-of-two padding is needed.
    $(#[$feature])*
    pub(super) fn karatsuba_step(a: &[u64], b: &[u64], out: &mut [u64], scratch: &mut [u64]) {
        let n = a.len();
        let m = n.div_ceil(2);
        let (a_lo, a_hi) = a.split_at(m);
        let (b_lo, b_hi) = b.split_at(m);

        let (z1, scratch) = scratch.split_at_mut(2 * m);
        let (a_sum, scratch) = scratch.split_at_mut(m);
        let (b_sum, scratch) = scratch.split_at_mut(m);

        // z0 = a_lo*b_lo and z2 = a_hi*b_hi land in disjoint ranges of out,
        // which is zero on entry, so they need no scratch buffers.
        {
            let (out_z0, out_z2) = out[..2 * n].split_at_mut(2 * m);
            poly_mul(a_lo, b_lo, out_z0, scratch);
            poly_mul(a_hi, b_hi, out_z2, scratch);
        }

        // a_hi/b_hi have floor(n/2) limbs, one fewer than the low halves
        // when n is odd.
        a_sum.copy_from_slice(a_lo);
        b_sum.copy_from_slice(b_lo);
        simd_xor_assign(&mut a_sum[..n - m], a_hi);
        simd_xor_assign(&mut b_sum[..n - m], b_hi);

        z1.fill(0);
        poly_mul(a_sum, b_sum, z1, scratch);

        // Fold z0 and z2 into the middle term before touching out[m..], since
        // the write range overlaps both of their positions.
        simd_xor_assign(z1, &out[..2 * m]);
        simd_xor_assign(&mut z1[..2 * (n - m)], &out[2 * m..2 * m + 2 * (n - m)]);
        simd_xor_assign(&mut out[m..m + 2 * m], z1);
    }

    /// One word-aligned Toom-3 level (Bodrato's TC3W).
    ///
    /// The operands are split into three parts of k = ceil(n/3) words in the
    /// outer variable y = x^(64k), and C(y) = A(y)*B(y) is recovered from five
    /// evaluations at y = 0, 1, W, W+1, and infinity, where W = x^64. With
    /// these points every interpolation step is a word shift, an XOR, or an
    /// exact division by W^2 + W (a prefix scan), and the five sub-products
    /// have ~n/3 words each:
    ///
    ///   E1 = C(1) + c0 + c4                    = c1 + c2 + c3
    ///   E2 = C(W) + c0 + W^4*c4                = W*c1 + W^2*c2 + W^3*c3
    ///   E3 = C(W+1) + c0 + (W^4+1)*c4          = (W+1)*c1 + (W+1)^2*c2 + (W+1)^3*c3
    ///   U  = (E2 + W*E1) / (W^2 + W)           = c2 + (W+1)*c3
    ///   V  = (E3 + (W+1)*E1) / (W^2 + W)       = c2 + W*c3
    ///   c3 = U + V,  c2 = V + W*c3,  c1 = E1 + c2 + c3
    $(#[$feature])*
    pub(super) fn toom3_step(a: &[u64], b: &[u64], out: &mut [u64], scratch: &mut [u64]) {
        let n = a.len();
        let k = n.div_ceil(3);
        let n2 = n - 2 * k;

        let (a0, rest) = a.split_at(k);
        let (a1, a2) = rest.split_at(k);
        let (b0, rest) = b.split_at(k);
        let (b1, b2) = rest.split_at(k);

        let (ta, scratch) = scratch.split_at_mut(k + 2);
        let (tb, scratch) = scratch.split_at_mut(k + 2);
        let (e1, scratch) = scratch.split_at_mut(2 * k);
        let (e2, scratch) = scratch.split_at_mut(2 * k + 4);
        let (e3, scratch) = scratch.split_at_mut(2 * k + 4);

        // c0 = a0*b0 and c4 = a2*b2 land in disjoint ranges of out, which is
        // zero on entry, so they need no scratch buffers.
        {
            let (out_c0, rest) = out[..2 * n].split_at_mut(2 * k);
            let (_, out_c4) = rest.split_at_mut(2 * k);
            poly_mul(a0, b0, out_c0, scratch);
            poly_mul(a2, b2, out_c4, scratch);
        }

        // C(1) = (a0 + a1 + a2)(b0 + b1 + b2)
        ta[..k].copy_from_slice(a0);
        tb[..k].copy_from_slice(b0);
        simd_xor_assign(&mut ta[..k], a1);
        simd_xor_assign(&mut tb[..k], b1);
        simd_xor_assign(&mut ta[..n2], a2);
        simd_xor_assign(&mut tb[..n2], b2);
        e1.fill(0);
        poly_mul(&ta[..k], &tb[..k], e1, scratch);

        // C(W): A(W) = a0 + W*a1 + W^2*a2 spans k + 2 words
        ta.fill(0);
        tb.fill(0);
        ta[..k].copy_from_slice(a0);
        tb[..k].copy_from_slice(b0);
        simd_xor_assign(&mut ta[1..1 + k], a1);
        simd_xor_assign(&mut tb[1..1 + k], b1);
        simd_xor_assign(&mut ta[2..2 + n2], a2);
        simd_xor_assign(&mut tb[2..2 + n2], b2);
        e2.fill(0);
        poly_mul(ta, tb, e2, scratch);

        // C(W+1): A(W+1) = A(W) + a1 + a2
        simd_xor_assign(&mut ta[..k], a1);
        simd_xor_assign(&mut tb[..k], b1);
        simd_xor_assign(&mut ta[..n2], a2);
        simd_xor_assign(&mut tb[..n2], b2);
        e3.fill(0);
        poly_mul(ta, tb, e3, scratch);

        // Strip the known c0 and c4 contributions from the three evaluations.
        simd_xor_assign(&mut e1[..2 * k], &out[..2 * k]);
        simd_xor_assign(&mut e2[..2 * k], &out[..2 * k]);
        simd_xor_assign(&mut e3[..2 * k], &out[..2 * k]);

        simd_xor_assign(&mut e1[..2 * n2], &out[4 * k..4 * k + 2 * n2]);
        simd_xor_assign(&mut e2[4..4 + 2 * n2], &out[4 * k..4 * k + 2 * n2]);
        simd_xor_assign(&mut e3[..2 * n2], &out[4 * k..4 * k + 2 * n2]);
        simd_xor_assign(&mut e3[4..4 + 2 * n2], &out[4 * k..4 * k + 2 * n2]);

        // U = (E2 + W*E1) / (W^2 + W), placed at e2[1..2k+2]
        simd_xor_assign(&mut e2[1..1 + 2 * k], &e1[..2 * k]);
        exact_div_w2_plus_w(e2);

        // V = (E3 + (W+1)*E1) / (W^2 + W), placed at e3[1..2k+2]
        simd_xor_assign(&mut e3[..2 * k], &e1[..2 * k]);
        simd_xor_assign(&mut e3[1..1 + 2 * k], &e1[..2 * k]);
        exact_div_w2_plus_w(e3);

        // c3 = U + V, overwriting U's slot: c3[j] = e2[1 + j]
        simd_xor_assign(&mut e2[1..2 * k + 2], &e3[1..2 * k + 2]);
        debug_assert_eq!(e2[2 * k + 1], 0, "c3 exceeds 2k words");

        // c2 = V + W*c3, overwriting V's slot: c2[j] = e3[1 + j]
        simd_xor_assign(&mut e3[2..2 + 2 * k], &e2[1..1 + 2 * k]);

        // Recompose out += c1*y + c2*y^2 + c3*y^3, with c1 = E1 + c2 + c3.
        simd_xor_assign(&mut out[k..k + 2 * k], &e1[..2 * k]);
        simd_xor_assign(&mut out[k..k + 2 * k], &e3[1..1 + 2 * k]);
        simd_xor_assign(&mut out[k..k + 2 * k], &e2[1..1 + 2 * k]);
        simd_xor_assign(&mut out[2 * k..4 * k], &e3[1..1 + 2 * k]);
        simd_xor_assign(&mut out[3 * k..5 * k], &e2[1..1 + 2 * k]);
    }

    /// Exact division by W^2 + W = x^128 + x^64, in place. The quotient ends
    /// up shifted down one word: q[j] = buf[1 + j].
    $(#[$feature])*
    pub(super) fn exact_div_w2_plus_w(buf: &mut [u64]) {
        // The bottom word is the W-division remainder and must be zero.
        debug_assert_eq!(buf[0], 0, "division by W^2 + W is not exact");
        // Division by W + 1 is the prefix scan q[j] = r[j] + q[j-1].
        for i in 2..buf.len() {
            buf[i] ^= buf[i - 1];
        }
        debug_assert_eq!(
            buf[buf.len() - 1],
            0,
            "division by W^2 + W left a remainder"
        );
    }
    };
}

mod portable {
    use super::*;

    type Product = u128;

    #[inline(always)]
    fn product_zero() -> Product {
        0
    }

    #[inline(always)]
    fn product_mul(a: u64, b: u64) -> Product {
        holes_clmul(a, b)
    }

    #[inline(always)]
    fn product_xor(x: Product, y: Product) -> Product {
        x ^ y
    }

    #[inline(always)]
    fn product_low(x: Product) -> u64 {
        x as u64
    }

    #[inline(always)]
    fn product_high(x: Product) -> u64 {
        (x >> 64) as u64
    }

    product_schoolbook!();
    poly_mul_family!();
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::*;
    use core::arch::x86_64::*;

    type Product = __m128i;

    #[target_feature(enable = "pclmulqdq,avx2,bmi2")]
    fn product_zero() -> Product {
        _mm_setzero_si128()
    }

    #[target_feature(enable = "pclmulqdq,avx2,bmi2")]
    fn product_mul(a: u64, b: u64) -> Product {
        _mm_clmulepi64_si128::<0>(_mm_cvtsi64_si128(a as i64), _mm_cvtsi64_si128(b as i64))
    }

    #[target_feature(enable = "pclmulqdq,avx2,bmi2")]
    fn product_xor(x: Product, y: Product) -> Product {
        _mm_xor_si128(x, y)
    }

    #[target_feature(enable = "pclmulqdq,avx2,bmi2")]
    fn product_low(x: Product) -> u64 {
        _mm_cvtsi128_si64(x) as u64
    }

    #[target_feature(enable = "pclmulqdq,avx2,bmi2")]
    fn product_high(x: Product) -> u64 {
        _mm_cvtsi128_si64(_mm_unpackhi_epi64(x, x)) as u64
    }

    product_schoolbook!(#[target_feature(enable = "pclmulqdq,avx2,bmi2")]);
    poly_mul_family!(#[target_feature(enable = "pclmulqdq,avx2,bmi2")]);

    pub(super) fn available() -> bool {
        crate::cpu::has_avx2_and_pclmulqdq()
    }
}

#[cfg(target_arch = "aarch64")]
mod arm {
    use super::*;
    use core::arch::aarch64::*;

    type Product = u128;

    #[target_feature(enable = "neon,aes")]
    fn product_zero() -> Product {
        0
    }

    #[target_feature(enable = "neon,aes")]
    fn product_mul(a: u64, b: u64) -> Product {
        vmull_p64(a, b)
    }

    #[target_feature(enable = "neon,aes")]
    fn product_xor(x: Product, y: Product) -> Product {
        x ^ y
    }

    #[target_feature(enable = "neon,aes")]
    fn product_low(x: Product) -> u64 {
        x as u64
    }

    #[target_feature(enable = "neon,aes")]
    fn product_high(x: Product) -> u64 {
        (x >> 64) as u64
    }

    product_schoolbook!(#[target_feature(enable = "neon,aes")]);
    poly_mul_family!(#[target_feature(enable = "neon,aes")]);

    pub(super) fn available() -> bool {
        std::arch::is_aarch64_feature_detected!("aes")
    }
}

#[cfg(target_arch = "aarch64")]
macro_rules! for_each_index {
    ($($index:literal)*; |$name:ident| $body:block) => {
        $({
            const $name: usize = $index;
            $body
        })*
    };
}

#[cfg(target_arch = "aarch64")]
mod neon_p8 {
    use super::*;
    use core::arch::aarch64::*;

    const SCHOOLBOOK_MAX_WORDS: usize = NEON_SCHOOLBOOK_MAX_WORDS;
    const TOOM3_MIN_WORDS: usize = NEON_TOOM3_MIN_WORDS;
    const BYTES_PER_WORD: usize = 8;
    const VECTOR_BYTES: usize = 16;
    const ZERO_LOOKUP: u8 = u8::MAX;

    type Rotations = [uint8x8_t; BYTES_PER_WORD];
    type Accumulators = [uint8x16_t; BYTES_PER_WORD];

    const UNWRAPPED_INDICES: [[u8; VECTOR_BYTES]; BYTES_PER_WORD] = {
        let mut table = [[ZERO_LOOKUP; VECTOR_BYTES]; BYTES_PER_WORD];
        let mut rotation = 1;
        while rotation < BYTES_PER_WORD {
            let kept_bytes = 2 * (BYTES_PER_WORD - rotation);
            let mut destination = rotation;
            while destination < rotation + kept_bytes {
                table[rotation][destination] = (destination - rotation) as u8;
                destination += 1;
            }
            rotation += 1;
        }
        table
    };

    const WRAPPED_INDICES: [[u8; VECTOR_BYTES]; BYTES_PER_WORD] = {
        let mut table = [[ZERO_LOOKUP; VECTOR_BYTES]; BYTES_PER_WORD];
        let mut rotation = 1;
        while rotation < BYTES_PER_WORD {
            let shift = BYTES_PER_WORD - rotation;
            let mut source = 2 * shift;
            while source < VECTOR_BYTES {
                table[rotation][source - shift] = source as u8;
                source += 1;
            }
            rotation += 1;
        }
        table
    };

    #[target_feature(enable = "neon")]
    fn load_indices(indices: &[u8; VECTOR_BYTES]) -> uint8x16_t {
        unsafe { vld1q_u8(indices.as_ptr()) }
    }

    #[target_feature(enable = "neon")]
    fn word_bytes(word: u64) -> uint8x8_t {
        vcreate_u8(word)
    }

    #[target_feature(enable = "neon")]
    fn rotations(word: u64) -> Rotations {
        let bytes = word_bytes(word);
        [
            vext_u8::<0>(bytes, bytes),
            vext_u8::<1>(bytes, bytes),
            vext_u8::<2>(bytes, bytes),
            vext_u8::<3>(bytes, bytes),
            vext_u8::<4>(bytes, bytes),
            vext_u8::<5>(bytes, bytes),
            vext_u8::<6>(bytes, bytes),
            vext_u8::<7>(bytes, bytes),
        ]
    }

    #[target_feature(enable = "neon")]
    fn byte_products(a: uint8x8_t, b: uint8x8_t) -> uint8x16_t {
        vreinterpretq_u8_p16(vmull_p8(vreinterpret_p8_u8(a), vreinterpret_p8_u8(b)))
    }

    #[target_feature(enable = "neon")]
    fn place_in_product(accumulator: uint8x16_t, rotation: usize) -> uint8x16_t {
        let unwrapped = vqtbl1q_u8(accumulator, load_indices(&UNWRAPPED_INDICES[rotation]));
        let wrapped = vqtbl1q_u8(accumulator, load_indices(&WRAPPED_INDICES[rotation]));
        veorq_u8(unwrapped, wrapped)
    }

    #[target_feature(enable = "neon")]
    fn collect_product(accumulators: &Accumulators) -> uint8x16_t {
        let mut product = accumulators[0];
        for (rotation, &accumulator) in accumulators.iter().enumerate().skip(1) {
            product = veorq_u8(product, place_in_product(accumulator, rotation));
        }
        product
    }

    const fn is_column_of_product(words: usize, column: usize) -> bool {
        column < 2 * words - 1
    }

    const fn is_pair_in_column(words: usize, column: usize, i: usize) -> bool {
        i < words && column >= i && column - i < words
    }

    #[target_feature(enable = "neon")]
    fn unrolled_schoolbook<const WORDS: usize>(a: &[u64], b: &[u64], out: &mut [u64]) {
        let a = &a[..WORDS];
        let b = &b[..WORDS];
        let out = &mut out[..2 * WORDS];
        let rotated: [Rotations; WORDS] = core::array::from_fn(|j| rotations(b[j]));
        let mut carry = 0u64;
        for_each_index!(0 1 2 3 4 5 6 7 8 9 10 11; |COLUMN| {
            if is_column_of_product(WORDS, COLUMN) {
                let mut accumulators = [vdupq_n_u8(0); BYTES_PER_WORD];
                for_each_index!(0 1 2 3 4 5; |I| {
                    const PARTNER: usize = COLUMN.wrapping_sub(I);
                    if is_pair_in_column(WORDS, COLUMN, I) {
                        let a_bytes = word_bytes(a[I]);
                        let products = rotated[PARTNER].map(|rotation| byte_products(a_bytes, rotation));
                        for (accumulator, product) in accumulators.iter_mut().zip(products) {
                            *accumulator = veorq_u8(*accumulator, product);
                        }
                    }
                });
                let product = vreinterpretq_u64_u8(collect_product(&accumulators));
                out[COLUMN] ^= vgetq_lane_u64::<0>(product) ^ carry;
                carry = vgetq_lane_u64::<1>(product);
            }
        });
        out[2 * WORDS - 1] ^= carry;
    }

    #[target_feature(enable = "neon")]
    fn schoolbook_mul(a: &[u64], b: &[u64], out: &mut [u64]) {
        match a.len() {
            1 => unrolled_schoolbook::<1>(a, b, out),
            2 => unrolled_schoolbook::<2>(a, b, out),
            3 => unrolled_schoolbook::<3>(a, b, out),
            4 => unrolled_schoolbook::<4>(a, b, out),
            5 => unrolled_schoolbook::<5>(a, b, out),
            _ => unrolled_schoolbook::<6>(a, b, out),
        }
    }

    poly_mul_family!(#[target_feature(enable = "neon")]);
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Portable,
    #[cfg(target_arch = "x86_64")]
    Pclmulqdq,
    #[cfg(target_arch = "aarch64")]
    Pmull,
    #[cfg(target_arch = "aarch64")]
    NeonP8,
}

#[cfg(test)]
thread_local! {
    static FORCED_BACKEND: std::cell::Cell<Option<Backend>> = const { std::cell::Cell::new(None) };
}

impl Backend {
    const ALL: &'static [Backend] = &[
        Backend::Portable,
        #[cfg(target_arch = "x86_64")]
        Backend::Pclmulqdq,
        #[cfg(target_arch = "aarch64")]
        Backend::NeonP8,
        #[cfg(target_arch = "aarch64")]
        Backend::Pmull,
    ];

    #[cfg(test)]
    pub(crate) fn run_forced<T>(self, body: impl FnOnce() -> T) -> T {
        let previous = FORCED_BACKEND.with(|slot| slot.replace(Some(self)));
        let result = body();
        FORCED_BACKEND.with(|slot| slot.set(previous));
        result
    }

    pub fn is_available(self) -> bool {
        match self {
            Backend::Portable => true,
            #[cfg(target_arch = "x86_64")]
            Backend::Pclmulqdq => x86::available(),
            #[cfg(target_arch = "aarch64")]
            Backend::NeonP8 => true,
            #[cfg(target_arch = "aarch64")]
            Backend::Pmull => arm::available(),
        }
    }

    pub fn available() -> Vec<Backend> {
        Self::ALL
            .iter()
            .copied()
            .filter(|backend| backend.is_available())
            .collect()
    }

    pub fn fastest() -> Backend {
        #[cfg(test)]
        if let Some(forced) = FORCED_BACKEND.with(|slot| slot.get()) {
            return forced;
        }
        Self::ALL
            .iter()
            .rev()
            .copied()
            .find(|backend| backend.is_available())
            .unwrap_or(Backend::Portable)
    }

    pub fn name(self) -> &'static str {
        match self {
            Backend::Portable => "portable",
            #[cfg(target_arch = "x86_64")]
            Backend::Pclmulqdq => "pclmulqdq",
            #[cfg(target_arch = "aarch64")]
            Backend::NeonP8 => "neon_p8",
            #[cfg(target_arch = "aarch64")]
            Backend::Pmull => "pmull",
        }
    }

    pub fn multiply(self, a: &[u64], b: &[u64], out: &mut [u64], scratch: &mut [u64]) {
        assert!(self.is_available(), "{} is not available", self.name());
        match self {
            Backend::Portable => portable::poly_mul(a, b, out, scratch),
            #[cfg(target_arch = "x86_64")]
            Backend::Pclmulqdq => unsafe { x86::poly_mul(a, b, out, scratch) },
            #[cfg(target_arch = "aarch64")]
            Backend::NeonP8 => unsafe { neon_p8::poly_mul(a, b, out, scratch) },
            #[cfg(target_arch = "aarch64")]
            Backend::Pmull => unsafe { arm::poly_mul(a, b, out, scratch) },
        }
    }
}

/// Multiplies two equal-length slices of u64 that represent GF(2)
/// polynomials. `out[..2n]` must be zero on entry; the product is XORed into
/// it. `scratch` must hold at least [`SCRATCH_WORDS`] words.
pub(crate) fn poly_mul(a: &[u64], b: &[u64], out: &mut [u64], scratch: &mut [u64]) {
    Backend::fastest().multiply(a, b, out, scratch)
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

    #[test]
    fn test_holes_clmul_matches_bit_loop() {
        let mut rng = XorShift(0x5851_F42D_4C95_7F2D);
        let edges = [
            0,
            1,
            u64::MAX,
            1 << 63,
            0x8000_0000_0000_0001,
            0x5555_5555_5555_5555,
        ];
        for &a in &edges {
            for &b in &edges {
                assert_eq!(holes_clmul(a, b), software_clmul(a, b), "a={a:#x} b={b:#x}");
            }
        }
        for _ in 0..10_000 {
            let (a, b) = (rng.next(), rng.next());
            assert_eq!(holes_clmul(a, b), software_clmul(a, b), "a={a:#x} b={b:#x}");
        }
    }

    #[test]
    fn test_scratch_words_suffices_for_every_backend() {
        let mut rng = XorShift(0x2545_F491_4F6C_DD1D);
        for n in (1..=330).chain([561, 901]) {
            let a: Vec<u64> = (0..n).map(|_| rng.next()).collect();
            let b: Vec<u64> = (0..n).map(|_| rng.next()).collect();
            let mut expected = vec![0u64; 2 * n];
            Backend::Portable.multiply(&a, &b, &mut expected, &mut vec![0u64; 8192]);
            for backend in Backend::available() {
                let mut got = vec![0u64; 2 * n];
                let mut scratch = vec![0u64; scratch_words(n)];
                backend.multiply(&a, &b, &mut got, &mut scratch);
                assert_eq!(got, expected, "{} n={n}", backend.name());
            }
        }
    }

    #[test]
    fn test_scratch_constant_covers_largest_residue() {
        assert!(scratch_words(crate::crt::MAX_RESIDUE_WORDS) <= SCRATCH_WORDS);
    }

    fn reference_product(a: &[u64], b: &[u64], out: &mut [u64]) {
        for (i, &ai) in a.iter().enumerate() {
            for (j, &bj) in b.iter().enumerate() {
                let product = software_clmul(ai, bj);
                out[i + j] ^= product as u64;
                out[i + j + 1] ^= (product >> 64) as u64;
            }
        }
    }

    /// Multiplies with every available implementation and compares with the
    /// reference product.
    fn check_poly_mul(a: &[u64], b: &[u64], context: &str) {
        let n = a.len();
        let mut expected = vec![0u64; 2 * n];
        reference_product(a, b, &mut expected);

        for backend in Backend::available() {
            let mut got = vec![0u64; 2 * n];
            let mut scratch = vec![0u64; 4096];
            backend.multiply(a, b, &mut got, &mut scratch);
            assert_eq!(got, expected, "{} mismatch: {context}", backend.name());
        }
    }

    /// Cross-check the Karatsuba and Toom-3 paths against schoolbook on
    /// random operands. Sizes cover the dispatch thresholds (8, 100), odd
    /// and even splits, the field element size (141), and sizes above 200
    /// where Toom-3 recurses into itself.
    #[test]
    fn test_poly_mul_matches_schoolbook_random() {
        let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
        let sizes = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 31, 47, 48, 49, 64, 71, 99, 100, 101, 140,
            141, 142, 150, 200, 300,
        ];
        for &n in &sizes {
            for trial in 0..5 {
                let a: Vec<u64> = (0..n).map(|_| rng.next()).collect();
                let b: Vec<u64> = (0..n).map(|_| rng.next()).collect();
                check_poly_mul(&a, &b, &format!("n={n} trial={trial}"));
            }
        }
    }

    /// Structured edge patterns that random operands are unlikely to hit:
    /// all-ones (maximal carries into every interpolation step), single
    /// bits at the extremes of each Toom-3 part, and sparse words.
    #[test]
    fn test_poly_mul_matches_schoolbook_edge_patterns() {
        let mut rng = XorShift(0x0DD0_BEEF_CAFE_F00D);
        for &n in &[100usize, 141, 300] {
            let ones = vec![u64::MAX; n];
            check_poly_mul(&ones, &ones, &format!("n={n} all-ones"));

            let mut lo = vec![0u64; n];
            lo[0] = 1;
            let mut hi = vec![0u64; n];
            hi[n - 1] = 1u64 << 63;
            check_poly_mul(&lo, &hi, &format!("n={n} lo*hi"));
            check_poly_mul(&hi, &hi, &format!("n={n} hi*hi"));

            let random: Vec<u64> = (0..n).map(|_| rng.next()).collect();
            let zero = vec![0u64; n];
            check_poly_mul(&random, &zero, &format!("n={n} rand*zero"));
            check_poly_mul(&random, &ones, &format!("n={n} rand*ones"));
            check_poly_mul(&random, &hi, &format!("n={n} rand*hi"));
        }
    }
}
