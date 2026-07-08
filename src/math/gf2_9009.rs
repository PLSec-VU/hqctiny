//! GF(2^9009) finite field implementation.
//!
//! The field is defined as GF(2)[x] / (x^9009 + x^29 + 1).
//! Elements are represented as `[u64; 141]` (9024 bits), where only the
//! bottom 9009 bits are used. Addition is bitwise XOR. Multiplication uses
//! Karatsuba's algorithm with CLMUL for the base case.

use clmul::clmul;

/// Number of u64 limbs in a field element (ceil(9009 / 64) = 141).
pub const GF29009_NUM_U64: usize = 141;

/// The degree of the field extension.
pub const DEGREE: usize = 9009;

/// GF(2^9009) field element.
///
/// Represented as an array of 141 u64 values. The i-th u64 holds bits
/// i*64 through i*64+63 of the polynomial coefficient vector.
/// Bits at positions >= DEGREE (9009) are always zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf2_9009 {
    pub data: [u64; GF29009_NUM_U64],
}

// Implement Serialize/Deserialize for Gf2_9009 using hex string representation
impl serde::Serialize for Gf2_9009 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for Gf2_9009 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex_str = String::deserialize(deserializer)?;
        Gf2_9009::try_from_hex(&hex_str).map_err(serde::de::Error::custom)
    }
}

impl Gf2_9009 {
    /// Construct a new field element from raw u64 limbs.
    /// Bits >= DEGREE are cleared.
    #[inline]
    pub fn new(data: [u64; GF29009_NUM_U64]) -> Self {
        let mut result = Self { data };
        result.normalize();
        result
    }

    #[inline(always)]
    pub fn add(&mut self, rhs: &Self) {
        for i in 0..GF29009_NUM_U64 {
            self.data[i] ^= rhs.data[i];
        }
    }

    #[inline]
    pub fn mul(&mut self, rhs: &Self) {
        let mut prod = [0u64; 2 * GF29009_NUM_U64];
        let mut scratch = [0u64; POLY_MUL_SCRATCH];
        poly_mul(&self.data, &rhs.data, &mut prod, &mut scratch);
        reduce(&mut prod, self);
    }

    /// Multiply by a `rhs` known to have no significant bits at or beyond
    /// `eff_words` (e.g. both operands are bounded-degree evaluation
    /// results). Runs `poly_mul` on `eff_words` limbs instead of all 141,
    /// which is asymptotically cheaper since Toom-3/Karatsuba cost is
    /// superlinear in operand size.
    pub fn mul_bounded(&mut self, rhs: &Self, eff_words: usize) {
        debug_assert!(eff_words > 0 && eff_words <= GF29009_NUM_U64);
        debug_assert!(
            2 * eff_words > GF29009_NUM_U64,
            "product of {eff_words}-word operands is too small for reduce's buffer contract"
        );
        debug_assert!(
            self.data[eff_words..].iter().all(|&w| w == 0),
            "self has significant bits beyond eff_words"
        );
        debug_assert!(
            rhs.data[eff_words..].iter().all(|&w| w == 0),
            "rhs has significant bits beyond eff_words"
        );

        let mut prod = [0u64; 2 * GF29009_NUM_U64];
        let mut scratch = [0u64; POLY_MUL_SCRATCH];
        poly_mul(
            &self.data[..eff_words],
            &rhs.data[..eff_words],
            &mut prod[..2 * eff_words],
            &mut scratch,
        );
        reduce(&mut prod[..2 * eff_words], self);
    }

    #[inline]
    pub fn zero() -> Self {
        Self {
            data: [0u64; GF29009_NUM_U64],
        }
    }

    /// The one element (multiplicative identity).
    #[inline]
    pub fn one() -> Self {
        let mut data = [0u64; GF29009_NUM_U64];
        data[0] = 1;
        Self { data }
    }

    /// Clear bits at positions >= DEGREE.
    #[inline(always)]
    fn normalize(&mut self) {
        const FULL_U64S: usize = DEGREE / 64; // 140
        const REMAINING_BITS: usize = DEGREE % 64; // 49
        const MASK: u64 = if REMAINING_BITS == 0 {
            u64::MAX
        } else {
            (1u64 << REMAINING_BITS) - 1
        };

        self.data[FULL_U64S] &= MASK;
    }

    /// Check if this element is zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.data.iter().all(|&x| x == 0)
    }

    /// Check if this element is one.
    #[inline]
    pub fn is_one(&self) -> bool {
        self.data[0] == 1 && self.data[1..].iter().all(|&x| x == 0)
    }

    /// Multiply by x^pow, where x is the field generator.
    ///
    /// This is a left-shift by `pow` bits followed by reduction modulo
    /// the field polynomial. Much faster than general multiplication
    /// because it avoids Karatsuba.
    pub fn mul_by_x_pow(&self, pow: usize, out: &mut Gf2_9009) {
        if pow == 0 {
            out.data.copy_from_slice(&self.data);
            return;
        }

        let word_shift = pow / 64;
        let bit_shift = pow % 64;

        // The shifted element can have bits up to (DEGREE - 1 + pow).
        let max_word = GF29009_NUM_U64 + word_shift + 1;
        debug_assert!(max_word <= 512, "max_word {} exceeds buffer size", max_word);

        // Dispatch on buffer size so small shifts (the common case in
        // point evaluation) don't pay for zero-initializing 512 words.
        match max_word {
            ..=160 => self.shift_reduce::<160>(word_shift, bit_shift, max_word, out),
            161..=256 => self.shift_reduce::<256>(word_shift, bit_shift, max_word, out),
            _ => self.shift_reduce::<512>(word_shift, bit_shift, max_word, out),
        }
    }

    fn shift_reduce<const N: usize>(
        &self,
        word_shift: usize,
        bit_shift: usize,
        max_word: usize,
        out: &mut Gf2_9009,
    ) {
        let mut buf = [0u64; N];

        if bit_shift == 0 {
            buf[word_shift..(GF29009_NUM_U64 + word_shift)]
                .copy_from_slice(&self.data[..GF29009_NUM_U64]);
        } else {
            let inv_shift = 64 - bit_shift;
            for i in 0..GF29009_NUM_U64 {
                let val = self.data[i];
                buf[i + word_shift] |= val << bit_shift;
                if i + word_shift + 1 < max_word {
                    buf[i + word_shift + 1] |= val >> inv_shift;
                }
            }
        }

        reduce(&mut buf[..max_word], out);
    }

    /// Shift `self` left by `x^pow`, reduce, and XOR the result into `out`.
    ///
    /// `eff_words`: number of significant limbs in `self` (limbs at indices
    /// `eff_words..GF29009_NUM_U64` must be zero).  Using a tighter bound
    /// avoids shifting zero limbs, keeping the intermediate buffer small and
    /// the dispatch in the fastest bucket.
    #[inline]
    pub fn mul_by_x_pow_xor_into(&self, pow: usize, eff_words: usize, out: &mut Gf2_9009) {
        debug_assert!(eff_words <= GF29009_NUM_U64);

        if pow == 0 {
            for i in 0..eff_words {
                out.data[i] ^= self.data[i];
            }
            return;
        }

        let word_shift = pow / 64;
        let bit_shift = pow % 64;
        let max_word = eff_words + word_shift + 1;
        debug_assert!(max_word <= 512, "max_word {} exceeds buffer size", max_word);

        match max_word {
            ..=160 => self.shift_xor_into::<160>(eff_words, word_shift, bit_shift, max_word, out),
            161..=256 => {
                self.shift_xor_into::<256>(eff_words, word_shift, bit_shift, max_word, out)
            }
            _ => self.shift_xor_into::<512>(eff_words, word_shift, bit_shift, max_word, out),
        }
    }

    fn shift_xor_into<const N: usize>(
        &self,
        eff_words: usize,
        word_shift: usize,
        bit_shift: usize,
        max_word: usize,
        out: &mut Gf2_9009,
    ) {
        let mut buf = [0u64; N];

        if bit_shift == 0 {
            buf[word_shift..word_shift + eff_words].copy_from_slice(&self.data[..eff_words]);
        } else {
            let inv_shift = 64 - bit_shift;
            for i in 0..eff_words {
                let val = self.data[i];
                buf[i + word_shift] ^= val << bit_shift;
                // i + word_shift + 1 <= eff_words + word_shift = max_word - 1 < N
                buf[i + word_shift + 1] ^= val >> inv_shift;
            }
        }

        // reduce requires buf.len() > GF29009_NUM_U64; N >= 160 > 141 satisfies this.
        // Zeros beyond max_word are harmless for reduction.
        let reduce_len = max_word.max(GF29009_NUM_U64 + 1);
        reduce_xor(&mut buf[..reduce_len], out);
    }
}

// ---------------------------------------------------------------------------
// Addition (XOR)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Multiplication
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Toom-3 / Karatsuba multiplication for GF(2) polynomials
// ---------------------------------------------------------------------------

/// Scratch for `poly_mul`: the Toom-3 level at n = 141 reserves 8k+12 = 388
/// words (k = 47), and its children are Karatsuba multiplies of 49 words
/// needing 4*(25 + 13 + 7) = 180 more along the deepest path; rounded up.
pub(crate) const POLY_MUL_SCRATCH: usize = 768;

/// Below this operand size (in words), Karatsuba splitting is used instead
/// of Toom-3.
const TOOM3_THRESHOLD: usize = 100;

/// Multiply two equal-length slices of u64 representing GF(2) polynomials.
///
/// `out[..2n]` must be zero-filled on entry; the product is XORed into it.
pub(crate) fn poly_mul(a: &[u64], b: &[u64], out: &mut [u64], scratch: &mut [u64]) {
    debug_assert_eq!(a.len(), b.len());
    let n = a.len();
    debug_assert!(out.len() >= 2 * n);

    const BASE_THRESHOLD: usize = 8;

    if n <= BASE_THRESHOLD {
        schoolbook_mul(a, b, out);
    } else if n < TOOM3_THRESHOLD {
        karatsuba_step(a, b, out, scratch);
    } else {
        toom3_step(a, b, out, scratch);
    }
}

/// One Karatsuba level. The halves are split at ceil(n/2), so no
/// power-of-two padding is needed.
fn karatsuba_step(a: &[u64], b: &[u64], out: &mut [u64], scratch: &mut [u64]) {
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
    for i in 0..n - m {
        a_sum[i] ^= a_hi[i];
        b_sum[i] ^= b_hi[i];
    }

    z1.fill(0);
    poly_mul(a_sum, b_sum, z1, scratch);

    // Fold z0 and z2 into the middle term before touching out[m..], since
    // the write range overlaps both of their positions.
    for (i, z) in z1.iter_mut().enumerate() {
        *z ^= out[i];
    }
    for i in 0..2 * (n - m) {
        z1[i] ^= out[2 * m + i];
    }
    for (i, z) in z1.iter().enumerate() {
        out[m + i] ^= z;
    }
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
fn toom3_step(a: &[u64], b: &[u64], out: &mut [u64], scratch: &mut [u64]) {
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
    for i in 0..k {
        ta[i] ^= a1[i];
        tb[i] ^= b1[i];
    }
    for i in 0..n2 {
        ta[i] ^= a2[i];
        tb[i] ^= b2[i];
    }
    e1.fill(0);
    poly_mul(&ta[..k], &tb[..k], e1, scratch);

    // C(W): A(W) = a0 + W*a1 + W^2*a2 spans k + 2 words
    ta.fill(0);
    tb.fill(0);
    ta[..k].copy_from_slice(a0);
    tb[..k].copy_from_slice(b0);
    for i in 0..k {
        ta[i + 1] ^= a1[i];
        tb[i + 1] ^= b1[i];
    }
    for i in 0..n2 {
        ta[i + 2] ^= a2[i];
        tb[i + 2] ^= b2[i];
    }
    e2.fill(0);
    poly_mul(ta, tb, e2, scratch);

    // C(W+1): A(W+1) = A(W) + a1 + a2
    for i in 0..k {
        ta[i] ^= a1[i];
        tb[i] ^= b1[i];
    }
    for i in 0..n2 {
        ta[i] ^= a2[i];
        tb[i] ^= b2[i];
    }
    e3.fill(0);
    poly_mul(ta, tb, e3, scratch);

    // Strip the known c0 and c4 contributions from the three evaluations.
    for i in 0..2 * k {
        let c0_i = out[i];
        e1[i] ^= c0_i;
        e2[i] ^= c0_i;
        e3[i] ^= c0_i;
    }
    for i in 0..2 * n2 {
        let c4_i = out[4 * k + i];
        e1[i] ^= c4_i;
        e2[4 + i] ^= c4_i;
        e3[i] ^= c4_i;
        e3[4 + i] ^= c4_i;
    }

    // U = (E2 + W*E1) / (W^2 + W), placed at e2[1..2k+2]
    for i in 0..2 * k {
        e2[1 + i] ^= e1[i];
    }
    exact_div_w2_plus_w(e2);

    // V = (E3 + (W+1)*E1) / (W^2 + W), placed at e3[1..2k+2]
    for i in 0..2 * k {
        e3[i] ^= e1[i];
        e3[1 + i] ^= e1[i];
    }
    exact_div_w2_plus_w(e3);

    // c3 = U + V, overwriting U's slot: c3[j] = e2[1 + j]
    for i in 1..2 * k + 2 {
        e2[i] ^= e3[i];
    }
    debug_assert_eq!(e2[2 * k + 1], 0, "c3 exceeds 2k words");

    // c2 = V + W*c3, overwriting V's slot: c2[j] = e3[1 + j]
    for i in 1..2 * k + 1 {
        e3[1 + i] ^= e2[i];
    }

    // Recompose out += c1*y + c2*y^2 + c3*y^3, with c1 = E1 + c2 + c3.
    for i in 0..2 * k {
        let c2_i = e3[1 + i];
        let c3_i = e2[1 + i];
        out[k + i] ^= e1[i] ^ c2_i ^ c3_i;
        out[2 * k + i] ^= c2_i;
        out[3 * k + i] ^= c3_i;
    }
}

/// Exact division by W^2 + W = x^128 + x^64, in place. The quotient ends
/// up shifted down one word: q[j] = buf[1 + j].
fn exact_div_w2_plus_w(buf: &mut [u64]) {
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

/// Schoolbook polynomial multiplication using CLMUL for u64 words.
fn schoolbook_mul(a: &[u64], b: &[u64], out: &mut [u64]) {
    debug_assert!(out.len() >= a.len() + b.len());
    for i in 0..a.len() {
        let ai = a[i];
        for j in 0..b.len() {
            let prod = clmul(ai, b[j]);
            out[i + j] ^= prod as u64;
            out[i + j + 1] ^= (prod >> 64) as u64;
        }
    }
}

// ---------------------------------------------------------------------------
// Reduction modulo x^9009 + x^29 + 1
// ---------------------------------------------------------------------------

/// Reduce a polynomial modulo the field polynomial, in place.
///
/// `buf` is used as scratch and is clobbered. It must hold at least
/// GF29009_NUM_U64 + 1 words so the folding writes stay in bounds.
pub(crate) fn reduce(buf: &mut [u64], result: &mut Gf2_9009) {
    debug_assert!(buf.len() > GF29009_NUM_U64, "reduce buffer too small");

    const START_WORD: usize = 140;
    const START_BIT: usize = 49;

    // Descending, so each word above the boundary is folded exactly once
    // and its targets (always strictly lower) are folded in later passes.
    for wi in (141..buf.len()).rev() {
        let w = buf[wi];

        let target_idx = wi - 141;

        // For off = 0: shift = 15
        buf[target_idx] ^= w << 15;
        buf[target_idx + 1] ^= w >> 49;

        // For off = 29: shift = 44
        buf[target_idx] ^= w << 44;
        buf[target_idx + 1] ^= w >> 20;
    }

    // Finally, reduce the start_word (140)
    let w_high = buf[START_WORD] >> START_BIT;

    // For off = 0 and off = 29:
    buf[0] ^= w_high ^ (w_high << 29);

    result.data.copy_from_slice(&buf[..GF29009_NUM_U64]);
    result.normalize();
}

/// Like `reduce`, but XORs the reduced result into `result` instead of
/// overwriting it. Avoids an intermediate `Gf2_9009` copy when the caller
/// wants to accumulate (e.g. `shift_xor_into`).
pub(crate) fn reduce_xor(buf: &mut [u64], result: &mut Gf2_9009) {
    debug_assert!(buf.len() > GF29009_NUM_U64, "reduce buffer too small");

    const START_WORD: usize = 140;
    const START_BIT: usize = 49;

    for wi in (141..buf.len()).rev() {
        let w = buf[wi];
        let target_idx = wi - 141;
        buf[target_idx] ^= w << 15;
        buf[target_idx + 1] ^= w >> 49;
        buf[target_idx] ^= w << 44;
        buf[target_idx + 1] ^= w >> 20;
    }

    let w_high = buf[START_WORD] >> START_BIT;
    buf[0] ^= w_high ^ (w_high << 29);

    // XOR the reduced low limbs into result instead of overwriting.
    for (dst, &src) in result.data.iter_mut().zip(&buf[..GF29009_NUM_U64]) {
        *dst ^= src;
    }
    // Clear any bits >= DEGREE that leaked from the XOR.
    result.normalize();
}

// ---------------------------------------------------------------------------
// Display / Hex conversion
// ---------------------------------------------------------------------------

impl std::fmt::Display for Gf2_9009 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Gf2_9009 {
    pub fn to_hex(&self) -> String {
        let num_bytes = DEGREE.div_ceil(8);
        let mut bytes = [0u8; 1127];
        for i in 0..GF29009_NUM_U64 {
            let val = self.data[i];
            for b in 0..8 {
                let offset_from_end = i * 8 + b;
                if offset_from_end < num_bytes {
                    bytes[num_bytes - 1 - offset_from_end] = (val >> (b * 8)) as u8;
                }
            }
        }
        hex::encode(&bytes[..num_bytes])
    }

    /// Parse a hex string into a field element.
    ///
    /// # Panics
    /// Panics if `hex_str` is not valid hex. Use `try_from_hex` for
    /// untrusted input (e.g. deserialization).
    pub fn from_hex(hex_str: &str) -> Self {
        Self::try_from_hex(hex_str).expect("Invalid hex string")
    }

    pub fn try_from_hex(hex_str: &str) -> Result<Self, hex::FromHexError> {
        let num_bytes = DEGREE.div_ceil(8);
        let hex_str = hex_str.trim();
        let required_hex = num_bytes * 2;
        let padded = if hex_str.len() < required_hex {
            "0".repeat(required_hex - hex_str.len()) + hex_str
        } else {
            hex_str.to_string()
        };

        let bytes = hex::decode(&padded)?;
        let mut data = [0u64; GF29009_NUM_U64];

        for (i, d) in data.iter_mut().enumerate() {
            let mut val: u64 = 0;
            for b in (0..8).rev() {
                let offset_from_end = i * 8 + b;
                if offset_from_end < num_bytes && offset_from_end < bytes.len() {
                    let byte_idx = num_bytes - 1 - offset_from_end;
                    val = (val << 8) | (bytes[byte_idx] as u64);
                }
            }
            *d = val;
        }

        let mut result = Self { data };
        result.normalize();
        Ok(result)
    }

    pub fn to_bytes(&self) -> [u8; GF29009_NUM_U64 * 8] {
        let mut bytes = [0u8; GF29009_NUM_U64 * 8];
        for (i, limb) in self.data.iter().enumerate() {
            let start = i * 8;
            bytes[start..start + 8].copy_from_slice(&limb.to_le_bytes());
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8; GF29009_NUM_U64 * 8]) -> Self {
        let mut data = [0u64; GF29009_NUM_U64];
        for (i, limb) in data.iter_mut().enumerate() {
            let start = i * 8;
            *limb = u64::from_le_bytes(bytes[start..start + 8].try_into().unwrap());
        }
        let mut result = Self { data };
        result.normalize();
        result
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::fs;

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

    /// Multiply via `poly_mul` and via `schoolbook_mul` and compare.
    /// Schoolbook is the ground truth: one CLMUL per word pair, no
    /// splitting logic to share bugs with.
    fn check_poly_mul(a: &[u64], b: &[u64], context: &str) {
        let n = a.len();
        let mut expected = vec![0u64; 2 * n];
        schoolbook_mul(a, b, &mut expected);

        let mut got = vec![0u64; 2 * n];
        let mut scratch = vec![0u64; 4096];
        poly_mul(a, b, &mut got, &mut scratch);

        assert_eq!(got, expected, "poly_mul mismatch: {}", context);
    }

    /// Cross-check the Karatsuba and Toom-3 paths against schoolbook on
    /// random operands. Sizes cover the dispatch thresholds (8, 100), odd
    /// and even splits, the field element size (141), and sizes above 200
    /// where Toom-3 recurses into itself.
    #[test]
    fn test_poly_mul_matches_schoolbook_random() {
        let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
        let sizes = [
            1, 2, 3, 7, 8, 9, 10, 15, 16, 17, 31, 47, 48, 49, 64, 71, 99, 100, 101, 140, 141, 142,
            150, 200, 300,
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

    #[derive(Deserialize)]
    struct TestVectors {
        info: TestInfo,
        arithmetic: Vec<ArithmeticCase>,
    }

    #[derive(Deserialize)]
    struct TestInfo {
        degree: u32,
        modulus: String,
    }

    #[derive(Deserialize)]
    struct ArithmeticCase {
        a: String,
        b: String,
        sum: String,
        prod: String,
    }

    fn load_test_vectors() -> TestVectors {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/math/test_vectors.json");
        let content = fs::read_to_string(path).expect("Failed to read test_vectors.json");
        serde_json::from_str(&content).expect("Failed to parse test_vectors.json")
    }

    #[test]
    fn test_info() {
        let tv = load_test_vectors();
        assert_eq!(tv.info.degree, 9009);
        assert_eq!(tv.info.modulus, "x^9009 + x^29 + 1");
    }

    #[test]
    fn test_from_hex_roundtrip() {
        let tv = load_test_vectors();
        for case in &tv.arithmetic {
            let a = Gf2_9009::from_hex(&case.a);
            assert_eq!(a.to_hex(), case.a, "roundtrip failed for a");

            let b = Gf2_9009::from_hex(&case.b);
            assert_eq!(b.to_hex(), case.b, "roundtrip failed for b");
        }
    }

    #[test]
    fn test_addition() {
        let tv = load_test_vectors();
        for case in &tv.arithmetic {
            let a = Gf2_9009::from_hex(&case.a);
            let b = Gf2_9009::from_hex(&case.b);
            let expected_sum = Gf2_9009::from_hex(&case.sum);
            let mut computed_sum = a;
            computed_sum.add(&b);
            assert_eq!(computed_sum, expected_sum, "addition failed for test case");
        }
    }

    #[test]
    fn test_multiplication() {
        let tv = load_test_vectors();
        for (i, case) in tv.arithmetic.iter().enumerate() {
            let a = Gf2_9009::from_hex(&case.a);
            let b = Gf2_9009::from_hex(&case.b);
            let expected_prod = Gf2_9009::from_hex(&case.prod);
            let mut computed_prod = a;
            computed_prod.mul(&b);
            assert_eq!(
                computed_prod, expected_prod,
                "multiplication failed for test case {}",
                i
            );
        }
    }

    #[test]
    fn test_basic_mul() {
        let mut data1 = [0u64; GF29009_NUM_U64];
        let mut data2 = [0u64; GF29009_NUM_U64];
        data1[0] = 3;
        data2[0] = 3;

        let a = Gf2_9009::new(data1);
        let b = Gf2_9009::new(data2);
        let mut c = a;
        c.mul(&b);
        assert_eq!(c.data[0], 5);
    }

    #[test]
    fn test_mul_identity() {
        let tv = load_test_vectors();
        let one = Gf2_9009::one();
        for case in &tv.arithmetic {
            let a = Gf2_9009::from_hex(&case.a);
            let mut a_copy = a;
            a_copy.mul(&one);
            assert_eq!(a_copy, a, "a * 1 != a");
            let mut one_copy = one;
            one_copy.mul(&a);
            assert_eq!(one_copy, a, "1 * a != a");
        }
    }

    #[test]
    fn test_mul_zero() {
        let tv = load_test_vectors();
        let zero = Gf2_9009::zero();
        for case in &tv.arithmetic {
            let a = Gf2_9009::from_hex(&case.a);
            let mut a_copy = a;
            a_copy.mul(&zero);
            assert_eq!(a_copy, zero, "a * 0 != 0");
            let mut zero_copy = zero;
            zero_copy.mul(&a);
            assert_eq!(zero_copy, zero, "0 * a != 0");
        }
    }

    #[test]
    fn test_mul_bounded_matches_mul() {
        let mut rng = XorShift(0x1357_9BDF_2468_ACE0);
        for &eff_words in &[71usize, 73, 76, 141] {
            for _ in 0..10 {
                let mut a_data = [0u64; GF29009_NUM_U64];
                let mut b_data = [0u64; GF29009_NUM_U64];
                for w in a_data[..eff_words].iter_mut() {
                    *w = rng.next();
                }
                for w in b_data[..eff_words].iter_mut() {
                    *w = rng.next();
                }
                let a = Gf2_9009::new(a_data);
                let b = Gf2_9009::new(b_data);

                let mut expected = a;
                expected.mul(&b);

                let mut got = a;
                got.mul_bounded(&b, eff_words.max(71));
                assert_eq!(got, expected, "mismatch eff_words={eff_words}");
            }
        }
    }

    #[test]
    fn test_mul_by_x_pow_reduction() {
        let mut data = [0u64; GF29009_NUM_U64];
        data[9008 / 64] = 1u64 << (9008 % 64);
        let elem = Gf2_9009::new(data);
        let mut result = Gf2_9009::zero();
        elem.mul_by_x_pow(1, &mut result);
        assert_eq!(result.data[0], (1 << 29) | 1);
    }

    #[test]
    fn test_bytes_roundtrip() {
        let tv = load_test_vectors();
        for case in &tv.arithmetic {
            let a = Gf2_9009::from_hex(&case.a);
            let bytes = a.to_bytes();
            let back = Gf2_9009::from_bytes(&bytes);
            assert_eq!(a, back, "bytes roundtrip failed");
        }
    }
}
