//! GF(2^8984) finite field implementation.
//!
//! The field is defined as GF(2)[x] / (x^8984 + x^9 + x^8 + x^6 + 1).
//! Elements are represented as `[u64; 141]` (9024 bits), where only the
//! bottom 8984 bits are used. Addition is bitwise XOR. Multiplication uses
//! Karatsuba's algorithm with CLMUL for the base case.

use clmul::clmul;

/// Number of u64 limbs in a field element (ceil(8984 / 64) = 141).
pub const GF28984_NUM_U64: usize = 141;

/// The degree of the field extension.
pub const DEGREE: usize = 8984;

/// GF(2^8984) field element.
///
/// Represented as an array of 141 u64 values. The i-th u64 holds bits
/// i*64 through i*64+63 of the polynomial coefficient vector.
/// Bits at positions >= DEGREE (8984) are always zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf2_8984 {
    pub data: [u64; GF28984_NUM_U64],
}

// Implement Serialize/Deserialize for Gf2_8984 using hex string representation
impl serde::Serialize for Gf2_8984 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for Gf2_8984 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex_str = String::deserialize(deserializer)?;
        Ok(Gf2_8984::from_hex(&hex_str))
    }
}

impl Gf2_8984 {
    /// Construct a new field element from raw u64 limbs.
    /// Bits >= DEGREE are cleared.
    pub fn new(data: [u64; GF28984_NUM_U64]) -> Self {
        let mut result = Self { data };
        result.normalize();
        result
    }

    pub fn add(&mut self, rhs: &Self) {
        for i in 0..GF28984_NUM_U64 {
            self.data[i] ^= rhs.data[i];
        }
    }

    pub fn mul(&mut self, rhs: &Self) {
        let mut out = Gf2_8984::zero();
        multiply(&self.data, &rhs.data, &mut out);
        *self = out;
    }

    pub fn zero() -> Self {
        Self {
            data: [0u64; GF28984_NUM_U64],
        }
    }

    /// The one element (multiplicative identity).
    pub fn one() -> Self {
        let mut data = [0u64; GF28984_NUM_U64];
        data[0] = 1;
        Self { data }
    }

    /// Clear bits at positions >= DEGREE.
    fn normalize(&mut self) {
        // DEGREE = 8984 = 140 * 64 + 24
        // So data[140] uses only bits 0..24 (position 8960..8983)
        // Bits 24..63 of data[140] must be zero.
        const FULL_U64S: usize = DEGREE / 64; // 140
        const REMAINING_BITS: usize = DEGREE % 64; // 24
        const MASK: u64 = if REMAINING_BITS == 0 {
            u64::MAX
        } else {
            (1u64 << REMAINING_BITS) - 1
        };

        self.data[FULL_U64S] &= MASK;
        // FULL_U64S + 1 == NUM_U64, so no further words to zero.
    }

    /// Check if this element is zero.
    pub fn is_zero(&self) -> bool {
        self.data.iter().all(|&x| x == 0)
    }

    /// Check if this element is one.
    pub fn is_one(&self) -> bool {
        self.data[0] == 1 && self.data[1..].iter().all(|&x| x == 0)
    }

    /// Multiply by x^pow, where x is the field generator.
    ///
    /// This is a left-shift by `pow` bits followed by reduction modulo
    /// the field polynomial. Much faster than general multiplication
    /// because it avoids Karatsuba.
    pub fn mul_by_x_pow(&self, pow: usize, out: &mut Gf2_8984) {
        if pow == 0 {
            out.data.copy_from_slice(&self.data);
            return;
        }

        let word_shift = pow / 64;
        let bit_shift = pow % 64;

        // The shifted element can have bits up to (DEGREE - 1 + pow).
        let max_word = GF28984_NUM_U64 + word_shift + 1;
        // Allocate enough for up to pow ~23000 (360 words). 512 words is safe.
        assert!(max_word <= 512, "max_word {} exceeds buffer size", max_word);
        let mut buf = [0u64; 512];

        if bit_shift == 0 {
            buf[word_shift..(GF28984_NUM_U64 + word_shift)]
                .copy_from_slice(&self.data[..GF28984_NUM_U64]);
        } else {
            let inv_shift = 64 - bit_shift;
            for i in 0..GF28984_NUM_U64 {
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
fn multiply(a: &[u64; GF28984_NUM_U64], b: &[u64; GF28984_NUM_U64], out: &mut Gf2_8984) {
    // Compute polynomial product (unreduced, degree up to 2*8983 = 17966)
    let mut prod = [0u64; 512];
    karatsuba_mul(a, b, &mut prod);
    let n = a.len().max(b.len());
    let padded = n.next_power_of_two();
    // Reduce modulo x^8984 + x^9 + x^8 + x^6 + 1
    reduce(&prod[..2 * padded], out);
}

// ---------------------------------------------------------------------------
// Karatsuba multiplication for GF(2) polynomials
// ---------------------------------------------------------------------------

/// Multiply two slices of u64 representing GF(2) polynomials.
/// Returns the product in a fixed-size array on the stack.
fn karatsuba_mul(a: &[u64], b: &[u64], out: &mut [u64; 512]) {
    let n = a.len().max(b.len());

    // Pad to power of two for clean Karatsuba split.
    let padded = n.next_power_of_two();
    assert!(padded <= 256, "padded size {} exceeds 256", padded);

    let mut a_padded = [0u64; 256];
    let mut b_padded = [0u64; 256];
    a_padded[..a.len()].copy_from_slice(a);
    b_padded[..b.len()].copy_from_slice(b);

    let mut scratch = [0u64; 256 * 4 * 10]; // Rough sizing for recursion depth
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

    // Base case: use schoolbook with CLMUL.
    const BASE_THRESHOLD: usize = 8;

    if n <= BASE_THRESHOLD {
        schoolbook_mul(a, b, out);
        return;
    }

    let m = n / 2;
    let (a_lo, a_hi) = a.split_at(m);
    let (b_lo, b_hi) = b.split_at(m);

    // Split scratchpad into z0, z1, z2, a_sum, b_sum, and remaining scratch space
    let (z0, scratch) = scratch.split_at_mut(n);
    let (z1, scratch) = scratch.split_at_mut(n);
    let (z2, scratch) = scratch.split_at_mut(n);
    let (a_sum, scratch) = scratch.split_at_mut(m);
    let (b_sum, scratch) = scratch.split_at_mut(m);

    z0.fill(0);
    z1.fill(0);
    z2.fill(0);

    // Z0 = a_lo * b_lo
    karatsuba_recursive(a_lo, b_lo, z0, scratch);

    // Z2 = a_hi * b_hi
    karatsuba_recursive(a_hi, b_hi, z2, scratch);

    // a_sum = a_lo + a_hi (XOR)
    // b_sum = b_lo + b_hi (XOR)
    for i in 0..m {
        a_sum[i] = a_lo[i] ^ a_hi[i];
        b_sum[i] = b_lo[i] ^ b_hi[i];
    }

    // Z1 = (a_lo + a_hi) * (b_lo + b_hi)
    karatsuba_recursive(a_sum, b_sum, z1, scratch);

    // result = Z0 + (Z1 + Z0 + Z2) * X^m + Z2 * X^{2m}
    // In GF(2), subtraction is XOR.

    // Set Z0 and Z2 into output first
    for i in 0..n {
        out[i] ^= z0[i];
        out[2 * m + i] ^= z2[i];
    }

    // Add middle term
    for i in 0..n {
        let mid = z0[i] ^ z1[i] ^ z2[i];
        out[m + i] ^= mid;
    }
}

/// Schoolbook polynomial multiplication using CLMUL for u64 words.
/// Constant‑time: always iterates over all i, j, never skips zeros.
fn schoolbook_mul(a: &[u64], b: &[u64], out: &mut [u64]) {
    let result_len = a.len() + b.len();
    for i in 0..a.len() {
        let ai = a[i];
        for j in 0..b.len() {
            let bj = b[j];
            // Always compute — clmul(0, ·) = 0, XOR with 0 is a no‑op.
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
// Reduction modulo x^8984 + x^9 + x^8 + x^6 + 1
// ---------------------------------------------------------------------------

/// Reduce a polynomial product (degree < 2*DEGREE) modulo
/// x^8984 + x^9 + x^8 + x^6 + 1.
///
/// Constant‑time: iterates over every bit position unconditionally.
fn reduce(poly: &[u64], result: &mut Gf2_8984) {
    const RED_OFFSETS: [u64; 4] = [9, 8, 6, 0];

    let min_len = GF28984_NUM_U64 + 2;
    let len = poly.len().max(min_len);
    assert!(len <= 512, "reduce len {} exceeds buffer size", len);

    let mut buf = [0u64; 512];
    buf[..poly.len()].copy_from_slice(poly);

    let start_word = DEGREE / 64; // 140
    let start_bit = DEGREE % 64; // 24

    // Two passes always suffice for degree < 2·DEGREE.
    let max_passes = 2;
    for _pass in 0..max_passes {
        // Iterate over every high word / bit unconditionally.
        for wi in (start_word..len).rev() {
            let w = buf[wi];
            if wi == start_word {
                buf[wi] = w & ((1u64 << start_bit) - 1); // keep low 24 bits
            } else {
                buf[wi] = 0;
            }

            // Check every bit position in this word — unconditional.
            let first_bi: usize = if wi == start_word { start_bit } else { 0 };
            for bi in first_bi..64 {
                let bit = (w >> bi) & 1;
                let i = wi * 64 + bi;
                let base = i - DEGREE;
                for &off in &RED_OFFSETS {
                    let pos = base as u64 + off;
                    let pw = (pos / 64) as usize;
                    let pb = (pos % 64) as usize;
                    if pw < len {
                        buf[pw] ^= bit << pb;
                    }
                }
            }
        }
    }

    let copy_len = GF28984_NUM_U64.min(len);
    result.data.fill(0);
    result.data[..copy_len].copy_from_slice(&buf[..copy_len]);
    result.normalize();
}

// ---------------------------------------------------------------------------
// Display / Hex conversion
// ---------------------------------------------------------------------------

impl std::fmt::Display for Gf2_8984 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Gf2_8984 {
    /// Convert to a hex string (uppercase, matching test vector format).
    /// The hex string is big-endian: the first character is the MSB (coefficient
    /// of x^8983), the last character is the LSB (coefficient of x^0).
    pub fn to_hex(&self) -> String {
        let num_bytes = DEGREE.div_ceil(8); // 1123
        let mut bytes = [0u8; 1123];
        for i in 0..GF28984_NUM_U64 {
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
        let mut data = [0u64; GF28984_NUM_U64];

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

    /// Serialize to a fixed-size byte array (141 × 8 = 1128 bytes).
    /// Each u64 limb is stored in little-endian order, sequentially.
    pub fn to_bytes(&self) -> [u8; GF28984_NUM_U64 * 8] {
        let mut bytes = [0u8; GF28984_NUM_U64 * 8];
        for (i, limb) in self.data.iter().enumerate() {
            let start = i * 8;
            bytes[start..start + 8].copy_from_slice(&limb.to_le_bytes());
        }
        bytes
    }

    /// Deserialize from a fixed-size byte array (141 × 8 = 1128 bytes).
    /// Each u64 limb is read in little-endian order, sequentially.
    pub fn from_bytes(bytes: &[u8; GF28984_NUM_U64 * 8]) -> Self {
        let mut data = [0u64; GF28984_NUM_U64];
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
        assert_eq!(tv.info.degree, 8984);
        assert_eq!(tv.info.modulus, "x^8984 + x^9 + x^8 + x^6 + 1");
    }

    #[test]
    fn test_from_hex_roundtrip() {
        let tv = load_test_vectors();
        for case in &tv.arithmetic {
            let a = Gf2_8984::from_hex(&case.a);
            assert_eq!(a.to_hex(), case.a, "roundtrip failed for a");

            let b = Gf2_8984::from_hex(&case.b);
            assert_eq!(b.to_hex(), case.b, "roundtrip failed for b");
        }
    }

    #[test]
    fn test_addition() {
        let tv = load_test_vectors();
        for case in &tv.arithmetic {
            let a = Gf2_8984::from_hex(&case.a);
            let b = Gf2_8984::from_hex(&case.b);
            let expected_sum = Gf2_8984::from_hex(&case.sum);
            let mut computed_sum = a;
            computed_sum.add(&b);
            assert_eq!(computed_sum, expected_sum, "addition failed for test case");
        }
    }

    #[test]
    fn test_multiplication() {
        let tv = load_test_vectors();
        for (i, case) in tv.arithmetic.iter().enumerate() {
            let a = Gf2_8984::from_hex(&case.a);
            let b = Gf2_8984::from_hex(&case.b);
            let expected_prod = Gf2_8984::from_hex(&case.prod);
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
        // (1 + x) * (1 + x) = 1 + x^2 in GF(2)[x], no reduction needed
        let mut data1 = [0u64; GF28984_NUM_U64];
        let mut data2 = [0u64; GF28984_NUM_U64];
        data1[0] = 3; // 1 + x
        data2[0] = 3; // 1 + x

        let a = Gf2_8984::new(data1);
        let b = Gf2_8984::new(data2);
        let mut c = a;
        c.mul(&b);

        // (1+x)^2 = 1 + x^2 = binary 101 = 5
        assert_eq!(c.data[0], 5, "expected 5, got {}", c.data[0]);
    }

    #[test]
    fn test_mul_identity() {
        let tv = load_test_vectors();
        let one = Gf2_8984::one();
        for case in &tv.arithmetic {
            let a = Gf2_8984::from_hex(&case.a);
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
        let zero = Gf2_8984::zero();
        for case in &tv.arithmetic {
            let a = Gf2_8984::from_hex(&case.a);
            let mut a_copy = a;
            a_copy.mul(&zero);
            assert_eq!(a_copy, zero, "a * 0 != 0");
            let mut zero_copy = zero;
            zero_copy.mul(&a);
            assert_eq!(zero_copy, zero, "0 * a != 0");
        }
    }

    #[test]
    fn test_mul_by_x_pow_basic() {
        // 1 * x^k = element with bit k set
        let one = Gf2_8984::one();
        for k in [0, 1, 5, 63, 64, 100, 500, 2000] {
            let mut result = Gf2_8984::zero();
            one.mul_by_x_pow(k, &mut result);
            let w = k / 64;
            let b = k % 64;
            assert_eq!(result.data[w], 1u64 << b, "bit at position {} not set", k);
            for i in 0..GF28984_NUM_U64 {
                if i != w {
                    assert_eq!(result.data[i], 0, "unexpected bits in word {}", i);
                }
            }
        }
    }

    #[test]
    fn test_mul_by_x_pow_reduction() {
        // x^8983 * x = x^8984 ≡ x^9 + x^8 + x^6 + 1
        let mut data = [0u64; GF28984_NUM_U64];
        data[8983 / 64] = 1u64 << (8983 % 64);
        let elem = Gf2_8984::new(data);
        let mut result = Gf2_8984::zero();
        elem.mul_by_x_pow(1, &mut result);
        assert_eq!(result.data[0], (1 << 9) | (1 << 8) | (1 << 6) | 1);
    }

    #[test]
    fn test_mul_by_x_pow_agrees_with_mul() {
        // mul_by_x_pow(k) should match multiplication by the element with bit k set
        let coeff = {
            let mut d = [0u64; GF28984_NUM_U64];
            d[0] = 0xDEADBEEF_CAFE1234;
            d[1] = 0x12345678_9ABCDEF0;
            Gf2_8984::new(d)
        };

        for k in [0, 1, 7, 63, 64, 128, 500, 2000] {
            let mut z_pow = [0u64; GF28984_NUM_U64];
            z_pow[k / 64] = 1u64 << (k % 64);
            let z_pow = Gf2_8984::new(z_pow);

            let mut expected = coeff;
            expected.mul(&z_pow);
            let mut computed = Gf2_8984::zero();
            coeff.mul_by_x_pow(k, &mut computed);
            assert_eq!(computed, expected, "mismatch at k={}", k);
        }
    }

    #[test]
    fn test_mul_by_x_pow_accumulate() {
        // mul_by_x_pow(a) + mul_by_x_pow(b) should work as expected
        let one = Gf2_8984::one();
        let mut x3 = Gf2_8984::zero();
        one.mul_by_x_pow(3, &mut x3);
        let mut x5 = Gf2_8984::zero();
        one.mul_by_x_pow(5, &mut x5);
        let mut sum = x3;
        sum.add(&x5);
        assert_eq!(sum.data[0], (1 << 3) | (1 << 5));
    }

    #[test]
    fn test_bytes_roundtrip() {
        let tv = load_test_vectors();
        for case in &tv.arithmetic {
            let a = Gf2_8984::from_hex(&case.a);
            let bytes = a.to_bytes();
            let back = Gf2_8984::from_bytes(&bytes);
            assert_eq!(a, back, "bytes roundtrip failed");
        }
    }
}
