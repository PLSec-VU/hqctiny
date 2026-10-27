#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Modulus {
    pub degree: usize,
    pub middle: usize,
}

impl Modulus {
    pub const fn new(degree: usize, middle: usize) -> Self {
        Self { degree, middle }
    }

    pub const fn words(self) -> usize {
        self.degree.div_ceil(64)
    }

    pub const fn residue_bytes(self) -> usize {
        self.degree.div_ceil(8)
    }

    pub fn top_word_mask(self) -> u64 {
        match self.degree % 64 {
            0 => u64::MAX,
            bits => (1u64 << bits) - 1,
        }
    }
}

pub const MAX_RESIDUE_WORDS: usize = 129;
pub const MAX_RESIDUE_BYTES: usize = 1030;

pub const HQC1_MODULI: [Modulus; 5] = [
    Modulus::new(7068, 1),
    Modulus::new(7068, 2),
    Modulus::new(7067, 1),
    Modulus::new(7067, 2),
    Modulus::new(7067, 3),
];

pub const HQC3_MODULI: [Modulus; 9] = [
    Modulus::new(7967, 1),
    Modulus::new(7967, 2),
    Modulus::new(7967, 3),
    Modulus::new(7967, 5),
    Modulus::new(7967, 6),
    Modulus::new(7967, 8),
    Modulus::new(7967, 9),
    Modulus::new(7966, 1),
    Modulus::new(7966, 3),
];

pub const HQC5_MODULI: [Modulus; 14] = [
    Modulus::new(8234, 1),
    Modulus::new(8234, 2),
    Modulus::new(8234, 3),
    Modulus::new(8234, 5),
    Modulus::new(8234, 6),
    Modulus::new(8234, 8),
    Modulus::new(8234, 9),
    Modulus::new(8234, 11),
    Modulus::new(8234, 12),
    Modulus::new(8234, 14),
    Modulus::new(8234, 15),
    Modulus::new(8233, 4),
    Modulus::new(8233, 9),
    Modulus::new(8233, 13),
];

pub fn request_payload_bytes(moduli: &[Modulus]) -> usize {
    moduli.iter().map(|m| m.residue_bytes()).max().unwrap_or(0)
}

pub fn words_from_residue_bytes(bytes: &[u8], modulus: Modulus, words: &mut [u64]) {
    words[..modulus.words()].fill(0);
    for (word, chunk) in words.iter_mut().zip(bytes.chunks(8)) {
        let mut le = [0u8; 8];
        le[..chunk.len()].copy_from_slice(chunk);
        *word = u64::from_le_bytes(le);
    }
}

pub fn residue_bytes_from_words(words: &[u64], modulus: Modulus, out: &mut [u8]) {
    for (chunk, word) in out[..modulus.residue_bytes()].chunks_mut(8).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
    }
}

pub fn residue_is_canonical(bytes: &[u8], modulus: Modulus) -> bool {
    let (residue, padding) = bytes.split_at(modulus.residue_bytes());
    let unused_top_bits = modulus.residue_bytes() * 8 - modulus.degree;
    let top_clear = residue
        .last()
        .is_none_or(|last| unused_top_bits == 0 || last >> (8 - unused_top_bits) == 0);
    top_clear && padding.iter().all(|&b| b == 0)
}
