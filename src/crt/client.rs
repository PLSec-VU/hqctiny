use super::gf2x::{mul_by_sparse_modulus, mul_mod, reduce_in_place, xor_into};
use super::params::{
    MAX_RESIDUE_WORDS, Modulus, residue_bytes_from_words, words_from_residue_bytes,
};
use crate::blinding;
use crate::hqc::HqcScheme;

const WORD_BYTES: usize = 8;

pub fn residues_of<SCHEME: HqcScheme>(poly: &[u64]) -> Vec<Vec<u8>> {
    SCHEME::CRT_MODULI
        .iter()
        .map(|&modulus| {
            let mut work = poly.to_vec();
            reduce_in_place(&mut work, modulus);
            let mut bytes = vec![0u8; modulus.residue_bytes()];
            residue_bytes_from_words(&work, modulus, &mut bytes);
            bytes
        })
        .collect()
}

fn garner_constants<SCHEME: HqcScheme>() -> Vec<[u64; MAX_RESIDUE_WORDS]> {
    let mut offset = 0;
    SCHEME::CRT_MODULI[1..]
        .iter()
        .map(|modulus| {
            let len = modulus.words() * WORD_BYTES;
            let mut words = [0u64; MAX_RESIDUE_WORDS];
            words_from_residue_bytes(
                &SCHEME::CRT_GARNER[offset..offset + len],
                *modulus,
                &mut words,
            );
            offset += len;
            words
        })
        .collect()
}

fn partial_sum_mod(
    digits: &[[u64; MAX_RESIDUE_WORDS]],
    moduli: &[Modulus],
    target: Modulus,
) -> [u64; MAX_RESIDUE_WORDS] {
    let words = target.words();
    let mut sum = [0u64; MAX_RESIDUE_WORDS];
    let mut work = [0u64; 2 * MAX_RESIDUE_WORDS + 2];
    let last = digits.len() - 1;
    work[..digits[last].len()].copy_from_slice(&digits[last]);
    reduce_in_place(&mut work, target);
    sum[..words].copy_from_slice(&work[..words]);
    for j in (0..last).rev() {
        work.fill(0);
        mul_by_sparse_modulus(&sum[..words], moduli[j], &mut work);
        xor_into(&mut work, &digits[j]);
        reduce_in_place(&mut work, target);
        sum[..words].copy_from_slice(&work[..words]);
    }
    sum
}

fn mixed_radix_digits<SCHEME: HqcScheme>(
    residues: &[[u64; MAX_RESIDUE_WORDS]],
) -> Vec<[u64; MAX_RESIDUE_WORDS]> {
    let moduli = SCHEME::CRT_MODULI;
    let constants = garner_constants::<SCHEME>();
    let mut digits = vec![residues[0]];
    for (i, modulus) in moduli.iter().enumerate().skip(1) {
        let words = modulus.words();
        let mut difference = partial_sum_mod(&digits, moduli, *modulus);
        xor_into(&mut difference[..words], &residues[i][..words]);
        let mut digit = [0u64; MAX_RESIDUE_WORDS];
        mul_mod(&difference, &constants[i - 1], *modulus, &mut digit);
        digits.push(digit);
    }
    digits
}

fn assemble_unreduced<SCHEME: HqcScheme>(digits: &[[u64; MAX_RESIDUE_WORDS]]) -> Vec<u64> {
    let moduli = SCHEME::CRT_MODULI;
    let capacity = 2 * SCHEME::VEC_N_SIZE_64 + 2;
    let mut current = vec![0u64; capacity];
    let mut next = vec![0u64; capacity];
    let top = moduli.len() - 1;
    current[..MAX_RESIDUE_WORDS].copy_from_slice(&digits[top]);
    let mut covered_bits = moduli[top].degree;
    for i in (0..top).rev() {
        next.fill(0);
        let covered_words = covered_bits.div_ceil(64);
        mul_by_sparse_modulus(&current[..covered_words], moduli[i], &mut next);
        xor_into(&mut next, &digits[i][..moduli[i].words()]);
        std::mem::swap(&mut current, &mut next);
        covered_bits += moduli[i].degree;
    }
    current.truncate(2 * SCHEME::VEC_N_SIZE_64);
    current
}

pub fn unreduced_from_residues<SCHEME: HqcScheme>(residues: &[Vec<u8>]) -> Vec<u64> {
    let words: Vec<[u64; MAX_RESIDUE_WORDS]> = SCHEME::CRT_MODULI
        .iter()
        .zip(residues)
        .map(|(&modulus, bytes)| {
            let mut w = [0u64; MAX_RESIDUE_WORDS];
            words_from_residue_bytes(bytes, modulus, &mut w);
            w
        })
        .collect();
    assemble_unreduced::<SCHEME>(&mixed_radix_digits::<SCHEME>(&words))
}

pub fn reconstruct_v<SCHEME: HqcScheme>(residues: &[Vec<u8>]) -> Vec<u64> {
    let unreduced = unreduced_from_residues::<SCHEME>(residues);
    let mut v = vec![0u64; SCHEME::VEC_N_SIZE_64];
    blinding::reduce_mod_xn_minus_1(&unreduced, SCHEME::PARAM_N, &mut v);
    v
}
