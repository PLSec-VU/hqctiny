use super::params::{MAX_RESIDUE_WORDS, Modulus};
use crate::math::poly_mul::SCRATCH_WORDS;
use crate::math::poly_mul::poly_mul;
use crate::math::xor::xor_shifted_into;

const WORD_BITS: usize = 64;

#[inline(always)]
fn read_word_at(buf: &[u64], bit: usize) -> u64 {
    let word = bit / WORD_BITS;
    let shift = bit % WORD_BITS;
    let low = buf[word] >> shift;
    if shift != 0 && word + 1 < buf.len() {
        low | (buf[word + 1] << (WORD_BITS - shift))
    } else {
        low
    }
}

#[inline(always)]
pub fn xor_word_at(buf: &mut [u64], bit: usize, value: u64) {
    let word = bit / WORD_BITS;
    let shift = bit % WORD_BITS;
    buf[word] ^= value << shift;
    if shift != 0 && word + 1 < buf.len() {
        buf[word + 1] ^= value >> (WORD_BITS - shift);
    }
}

fn clear_from_bit(buf: &mut [u64], bit: usize) {
    let word = bit / WORD_BITS;
    let shift = bit % WORD_BITS;
    if word >= buf.len() {
        return;
    }
    buf[word] &= (1u64 << shift) - 1;
    buf[word + 1..].fill(0);
}

pub fn reduce_in_place(buf: &mut [u64], modulus: Modulus) {
    let high_bits = (buf.len() * WORD_BITS).saturating_sub(modulus.degree);
    for chunk in (0..high_bits.div_ceil(WORD_BITS)).rev() {
        let value = read_word_at(buf, modulus.degree + chunk * WORD_BITS);
        xor_word_at(buf, chunk * WORD_BITS, value);
        xor_word_at(buf, chunk * WORD_BITS + modulus.middle, value);
    }
    clear_from_bit(buf, modulus.degree);
}

pub fn mul_mod(a: &[u64], b: &[u64], modulus: Modulus, out: &mut [u64]) {
    let words = modulus.words();
    let mut product = [0u64; 2 * MAX_RESIDUE_WORDS];
    let mut scratch = [0u64; SCRATCH_WORDS];
    poly_mul(
        &a[..words],
        &b[..words],
        &mut product[..2 * words],
        &mut scratch,
    );
    reduce_in_place(&mut product[..2 * words], modulus);
    out[..words].copy_from_slice(&product[..words]);
}

pub fn xor_into(dst: &mut [u64], src: &[u64]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= s;
    }
}

pub fn mul_by_sparse_modulus(value: &[u64], factor: Modulus, out: &mut [u64]) {
    xor_shifted_into(out, value, factor.degree);
    xor_shifted_into(out, value, factor.middle);
    xor_shifted_into(out, value, 0);
}
