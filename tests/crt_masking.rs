use std::collections::{BTreeSet, HashMap};

const RING_BITS: usize = 7;
const MESSAGE_BITS: usize = 4;
const EXACT_MODULI: [u32; 3] = [0b10011, 0b11001, 0b100101];
const REDUNDANT_MODULI: [u32; 3] = [0b100101, 0b101001, 0b111101];

#[derive(Clone, Copy)]
struct MaskWidths {
    quotient: usize,
    truncate: usize,
}

const FULL_MASKS: MaskWidths = MaskWidths {
    quotient: RING_BITS - 1,
    truncate: RING_BITS - MESSAGE_BITS,
};

fn degree(poly: u32) -> usize {
    31 - poly.leading_zeros() as usize
}

fn reduce(mut value: u32, modulus: u32) -> u32 {
    while value != 0 && degree(value) >= degree(modulus) {
        value ^= modulus << (degree(value) - degree(modulus));
    }
    value
}

fn multiply(a: u32, b: u32) -> u32 {
    (0..32)
        .filter(|bit| b >> bit & 1 == 1)
        .fold(0, |acc, bit| acc ^ (a << bit))
}

fn ring_modulus() -> u32 {
    (1 << RING_BITS) | 1
}

fn visible_part(unreduced: u32) -> u32 {
    let mut folded = 0;
    let mut rest = unreduced;
    while rest != 0 {
        folded ^= rest & ((1 << RING_BITS) - 1);
        rest >>= RING_BITS;
    }
    folded & ((1 << MESSAGE_BITS) - 1)
}

fn pack_residues(unreduced: u32, moduli: &[u32]) -> u32 {
    moduli.iter().fold(0, |packed, &modulus| {
        (packed << degree(modulus)) | reduce(unreduced, modulus)
    })
}

type Distribution = HashMap<u32, u32>;

fn distribution(unmasked: u32, moduli: &[u32], widths: MaskWidths) -> Distribution {
    let mut counts = Distribution::new();
    for truncate in 0..1u32 << widths.truncate {
        for quotient in 0..1u32 << widths.quotient {
            let masked = unmasked ^ (truncate << MESSAGE_BITS) ^ multiply(quotient, ring_modulus());
            *counts.entry(pack_residues(masked, moduli)).or_default() += 1;
        }
    }
    counts
}

struct Verdict {
    depends_only_on_visible_part: bool,
    uniform_on_support: bool,
}

fn judge(moduli: &[u32], widths: MaskWidths) -> Verdict {
    let mut by_visible_part: HashMap<u32, Vec<u32>> = HashMap::new();
    for unmasked in 0..1u32 << (2 * RING_BITS - 1) {
        by_visible_part
            .entry(visible_part(unmasked))
            .or_default()
            .push(unmasked);
    }
    let mut verdict = Verdict {
        depends_only_on_visible_part: true,
        uniform_on_support: true,
    };
    for members in by_visible_part.values() {
        let reference = distribution(members[0], moduli, widths);
        for &member in members {
            let observed = distribution(member, moduli, widths);
            verdict.depends_only_on_visible_part &= observed == reference;
            let counts: BTreeSet<u32> = observed.values().copied().collect();
            verdict.uniform_on_support &= counts.len() == 1;
        }
    }
    verdict
}

fn leaks(verdict: &Verdict) -> bool {
    !verdict.depends_only_on_visible_part
}

#[test]
fn exact_moduli_with_full_masks_reveal_only_the_visible_part() {
    let verdict = judge(&EXACT_MODULI, FULL_MASKS);
    assert!(!leaks(&verdict));
    assert!(verdict.uniform_on_support);
}

#[test]
fn redundant_moduli_with_full_masks_reveal_only_the_visible_part() {
    let verdict = judge(&REDUNDANT_MODULI, FULL_MASKS);
    assert!(!leaks(&verdict));
    assert!(verdict.uniform_on_support);
}

#[test]
fn a_quotient_mask_of_n_bits_still_hides() {
    let widths = MaskWidths {
        quotient: RING_BITS,
        ..FULL_MASKS
    };
    assert!(!leaks(&judge(&EXACT_MODULI, widths)));
}

#[test]
fn no_quotient_mask_leaks() {
    let widths = MaskWidths {
        quotient: 0,
        ..FULL_MASKS
    };
    assert!(leaks(&judge(&EXACT_MODULI, widths)));
}

#[test]
fn no_truncate_mask_leaks() {
    let widths = MaskWidths {
        truncate: 0,
        ..FULL_MASKS
    };
    assert!(leaks(&judge(&EXACT_MODULI, widths)));
}

#[test]
fn a_quotient_mask_one_bit_too_short_leaks() {
    let widths = MaskWidths {
        quotient: RING_BITS - 2,
        ..FULL_MASKS
    };
    assert!(leaks(&judge(&EXACT_MODULI, widths)));
}

fn span_dimension(moduli: &[u32]) -> usize {
    let mut basis: Vec<u32> = Vec::new();
    for bit in 0..2 * RING_BITS - 1 {
        let mut vector = pack_residues(1 << bit, moduli);
        for &row in &basis {
            vector = vector.min(vector ^ row);
        }
        if vector != 0 {
            basis.push(vector);
        }
    }
    basis.len()
}

#[test]
fn exact_moduli_give_a_bijection_and_redundant_moduli_an_injection() {
    let unreduced_bits = 2 * RING_BITS - 1;
    assert_eq!(span_dimension(&EXACT_MODULI), unreduced_bits);
    assert_eq!(span_dimension(&REDUNDANT_MODULI), unreduced_bits);
    let exact_total: usize = EXACT_MODULI.iter().map(|&f| degree(f)).sum();
    let redundant_total: usize = REDUNDANT_MODULI.iter().map(|&f| degree(f)).sum();
    assert_eq!(exact_total, unreduced_bits);
    assert!(redundant_total > unreduced_bits);
}
