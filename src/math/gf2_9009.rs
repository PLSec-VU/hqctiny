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
        Ok(Gf2_9009::from_hex(&hex_str))
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
        let mut out = Gf2_9009::zero();
        multiply(&self.data, &rhs.data, &mut out);
        *self = out;
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
        let mut buf = [0u64; 512];

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

        reduce(&buf[..max_word], out);
    }
}

// ---------------------------------------------------------------------------
// Addition (XOR)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Multiplication
// ---------------------------------------------------------------------------

/// Multiply two field elements and reduce modulo the field polynomial.
fn multiply(a: &[u64; GF29009_NUM_U64], b: &[u64; GF29009_NUM_U64], out: &mut Gf2_9009) {
    let mut prod = [0u64; 512];
    karatsuba_mul(a, b, &mut prod);
    let n = a.len().max(b.len());
    let padded = n.next_power_of_two();
    reduce(&prod[..2 * padded], out);
}

// ---------------------------------------------------------------------------
// Karatsuba multiplication for GF(2) polynomials
// ---------------------------------------------------------------------------

/// Multiply two slices of u64 representing GF(2) polynomials.
/// Returns the product in a fixed-size array on the stack.
fn karatsuba_mul(a: &[u64], b: &[u64], out: &mut [u64; 512]) {
    let n = a.len().max(b.len());

    let padded = n.next_power_of_two();
    debug_assert!(padded <= 256, "padded size {} exceeds 256", padded);

    let mut a_padded = [0u64; 256];
    let mut b_padded = [0u64; 256];
    a_padded[..a.len()].copy_from_slice(a);
    b_padded[..b.len()].copy_from_slice(b);

    let mut scratch = [0u64; 256 * 4 * 10];
    karatsuba_recursive(
        &a_padded[..padded],
        &b_padded[..padded],
        &mut out[..2 * padded],
        &mut scratch,
    );
}

/// Recursive Karatsuba for two equal-length slices (length is power of 2).
fn karatsuba_recursive(a: &[u64], b: &[u64], out: &mut [u64], scratch: &mut [u64]) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert!(a.len().is_power_of_two());
    let n = a.len();
    debug_assert!(out.len() >= 2 * n);

    const BASE_THRESHOLD: usize = 8;

    if n <= BASE_THRESHOLD {
        schoolbook_mul(a, b, out);
        return;
    }

    let m = n / 2;
    let (a_lo, a_hi) = a.split_at(m);
    let (b_lo, b_hi) = b.split_at(m);

    let (z0, scratch) = scratch.split_at_mut(n);
    let (z1, scratch) = scratch.split_at_mut(n);
    let (z2, scratch) = scratch.split_at_mut(n);
    let (a_sum, scratch) = scratch.split_at_mut(m);
    let (b_sum, scratch) = scratch.split_at_mut(m);

    z0.fill(0);
    z1.fill(0);
    z2.fill(0);

    karatsuba_recursive(a_lo, b_lo, z0, scratch);
    karatsuba_recursive(a_hi, b_hi, z2, scratch);

    for i in 0..m {
        a_sum[i] = a_lo[i] ^ a_hi[i];
        b_sum[i] = b_lo[i] ^ b_hi[i];
    }

    karatsuba_recursive(a_sum, b_sum, z1, scratch);

    for i in 0..n {
        out[i] ^= z0[i];
        out[2 * m + i] ^= z2[i];
    }

    for i in 0..n {
        let mid = z0[i] ^ z1[i] ^ z2[i];
        out[m + i] ^= mid;
    }
}

/// Schoolbook polynomial multiplication using CLMUL for u64 words.
fn schoolbook_mul(a: &[u64], b: &[u64], out: &mut [u64]) {
    let result_len = a.len() + b.len();
    for i in 0..a.len() {
        let ai = a[i];
        for j in 0..b.len() {
            let bj = b[j];
            let prod = clmul(ai, bj);
            let lo = prod as u64;
            let hi = (prod >> 64) as u64;
            out[i + j] ^= lo;
            if i + j + 1 < result_len {
                out[i + j + 1] ^= hi;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Reduction modulo x^9009 + x^29 + 1
// ---------------------------------------------------------------------------

fn reduce(poly: &[u64], result: &mut Gf2_9009) {
    let min_len = GF29009_NUM_U64 + 2;
    let len = poly.len().max(min_len);
    debug_assert!(len <= 512, "reduce len {} exceeds buffer size", len);

    let mut buf = [0u64; 512];
    buf[..poly.len()].copy_from_slice(poly);

    const START_WORD: usize = 140;
    const START_BIT: usize = 49;

    for wi in (141..len).rev() {
        let w = buf[wi];
        if w == 0 {
            continue;
        }
        buf[wi] = 0;

        let target_idx = wi - 141;

        // For off = 0: shift = 15
        buf[target_idx] ^= w << 15;
        buf[target_idx + 1] ^= w >> 49;

        // For off = 29: shift = 44
        buf[target_idx] ^= w << 44;
        buf[target_idx + 1] ^= w >> 20;
    }

    // Finally, reduce the start_word (140)
    let w = buf[START_WORD];
    if w > 0 {
        let w_high = w >> START_BIT;
        buf[START_WORD] = w & ((1u64 << START_BIT) - 1);

        // For off = 0 and off = 29:
        buf[0] ^= w_high ^ (w_high << 29);
    }

    let copy_len = GF29009_NUM_U64.min(len);
    result.data.fill(0);
    result.data[..copy_len].copy_from_slice(&buf[..copy_len]);
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

    pub fn from_hex(hex_str: &str) -> Self {
        let num_bytes = DEGREE.div_ceil(8);
        let hex_str = hex_str.trim();
        let required_hex = num_bytes * 2;
        let padded = if hex_str.len() < required_hex {
            "0".repeat(required_hex - hex_str.len()) + hex_str
        } else {
            hex_str.to_string()
        };

        let bytes = hex::decode(&padded).expect("Invalid hex string");
        let mut data = [0u64; GF29009_NUM_U64];

        for (i, d) in data.iter_mut().enumerate() {
            let mut val: u64 = 0;
            for b in (0..8).rev() {
                let offset_from_end = i * 8 + b;
                if offset_from_end < num_bytes {
                    let byte_idx = num_bytes - 1 - offset_from_end;
                    val = (val << 8) | (bytes[byte_idx] as u64);
                }
            }
            *d = val;
        }

        let mut result = Self { data };
        result.normalize();
        result
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

    #[test]
    fn test_from_hex_roundtrip() {
        let mut data = [0u64; GF29009_NUM_U64];
        data[0] = 0x123456789abcdef0;
        data[140] = 0x1ffffffffff;
        let a = Gf2_9009::new(data);
        let hex = a.to_hex();
        let b = Gf2_9009::from_hex(&hex);
        assert_eq!(a, b);
    }

    #[test]
    fn test_addition() {
        let mut data1 = [0u64; GF29009_NUM_U64];
        let mut data2 = [0u64; GF29009_NUM_U64];
        data1[0] = 1;
        data2[0] = 3;
        let mut a = Gf2_9009::new(data1);
        let b = Gf2_9009::new(data2);
        a.add(&b);
        assert_eq!(a.data[0], 2);
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
    fn test_mul_by_x_pow_reduction() {
        let mut data = [0u64; GF29009_NUM_U64];
        data[9008 / 64] = 1u64 << (9008 % 64);
        let elem = Gf2_9009::new(data);
        let mut result = Gf2_9009::zero();
        elem.mul_by_x_pow(1, &mut result);
        assert_eq!(result.data[0], (1 << 29) | 1);
    }
}
