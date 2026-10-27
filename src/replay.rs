use crate::encoding::Kind;
use crate::error::{Error, Result};
use crate::hqc::HqcScheme;
use crate::limits::COOKIE_ROTATION_SECS;
use crate::puzzle::NONCE_BYTES as CHALLENGE_NONCE_BYTES;
use std::f64::consts::LN_2;

pub const DEFAULT_FALSE_POSITIVE_RATE: f64 = 0.001;
pub const DEFAULT_DUPLICATES: u8 = 3;

const GENERATIONS: usize = 2;
const COUNTER_SLOTS_PER_INSERTION: f64 = 0.5;
const COUNTER_WIDTHS_BITS: [u32; 4] = [1, 2, 4, 8];
const WORD_BITS: u64 = 64;
const FINGERPRINT_KEY_BYTES: usize = 32;
const COOKIE_NONCE_BYTES: usize = 24;
const FINGERPRINT_INPUT_BYTES: usize = COOKIE_NONCE_BYTES + 1 + 1;
const SOLVED_HANDSHAKE_INDEX: u8 = 0;
const BYTES_PER_KIB: f64 = 1024.0;

const RATE_HQC1: u32 = 31_300;
const RATE_HQC3: u32 = 21_500;
const RATE_HQC5: u32 = 15_300;

pub fn default_rate<S: HqcScheme>() -> u32 {
    match S::PARAM_SECURITY_BYTES {
        16 => RATE_HQC1,
        24 => RATE_HQC3,
        _ => RATE_HQC5,
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReplayConfig {
    pub rotation_secs: u32,
    pub false_positive_rate: f64,
    pub max_rate: u32,
    pub duplicates: u8,
}

impl ReplayConfig {
    pub fn for_scheme<S: HqcScheme>() -> Self {
        Self {
            rotation_secs: COOKIE_ROTATION_SECS,
            false_positive_rate: DEFAULT_FALSE_POSITIVE_RATE,
            max_rate: default_rate::<S>(),
            duplicates: DEFAULT_DUPLICATES,
        }
    }

    pub fn expected_insertions(&self) -> u64 {
        u64::from(self.max_rate) * u64::from(self.rotation_secs)
    }

    pub fn sizing(&self) -> Result<ReplaySizing> {
        let valid = self.rotation_secs >= 1
            && self.max_rate >= 1
            && self.false_positive_rate > 0.0
            && self.false_positive_rate < 1.0;
        if !valid {
            return Err(Error::Other("invalid replay filter parameters"));
        }
        let bloom = bloom_sizing(self.false_positive_rate, self.expected_insertions());
        let counter_slots =
            ((bloom.insertions as f64 * COUNTER_SLOTS_PER_INSERTION).ceil() as u64).max(1);
        Ok(ReplaySizing {
            bloom,
            counter_slots,
            counter_bits: counter_width_bits(self.duplicates),
            duplicates: self.duplicates,
            rotation_secs: self.rotation_secs,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BloomSizing {
    pub insertions: u64,
    pub bits: u64,
    pub hashes: u32,
}

impl BloomSizing {
    pub fn bits_per_insertion(&self) -> f64 {
        self.bits as f64 / self.insertions as f64
    }
}

pub fn bloom_sizing(false_positive_rate: f64, insertions: u64) -> BloomSizing {
    let n = insertions as f64;
    let bits = (-n * false_positive_rate.ln() / (LN_2 * LN_2)).ceil() as u64;
    let hashes = ((bits as f64 / n) * LN_2).round().max(1.0) as u32;
    BloomSizing {
        insertions,
        bits,
        hashes,
    }
}

fn counter_width_bits(duplicates: u8) -> u32 {
    COUNTER_WIDTHS_BITS
        .into_iter()
        .find(|width| u64::from(duplicates) < 1 << width)
        .unwrap_or(8)
}

fn words_for(bits: u64) -> usize {
    bits.div_ceil(WORD_BITS) as usize
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReplaySizing {
    pub bloom: BloomSizing,
    pub counter_slots: u64,
    pub counter_bits: u32,
    pub duplicates: u8,
    pub rotation_secs: u32,
}

impl ReplaySizing {
    pub fn bloom_bytes_per_generation(&self) -> usize {
        words_for(self.bloom.bits) * 8
    }

    pub fn counter_bytes_per_generation(&self) -> usize {
        words_for(self.counter_slots * u64::from(self.counter_bits)) * 8
    }

    pub fn memory_bytes(&self) -> usize {
        GENERATIONS * (self.bloom_bytes_per_generation() + self.counter_bytes_per_generation())
    }

    pub fn describe(&self) -> String {
        format!(
            "replay filter: generation {} s (one cookie-key rotation), {} insertions per generation, m = {} bits, k = {} hashes, {} counters of {} bits, memory {:.1} KiB",
            self.rotation_secs,
            self.bloom.insertions,
            self.bloom.bits,
            self.bloom.hashes,
            self.counter_slots,
            self.counter_bits,
            self.memory_bytes() as f64 / BYTES_PER_KIB,
        )
    }
}

pub type FingerprintKey = [u8; FINGERPRINT_KEY_BYTES];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fingerprint {
    pub probe_base: u64,
    pub probe_step: u64,
    pub counter_hash: u64,
}

impl Fingerprint {
    pub fn of(
        key: &FingerprintKey,
        cookie_nonce: &[u8; COOKIE_NONCE_BYTES],
        kind: u8,
        index: u8,
    ) -> Self {
        let mut input = [0u8; FINGERPRINT_INPUT_BYTES];
        input[..COOKIE_NONCE_BYTES].copy_from_slice(cookie_nonce);
        input[COOKIE_NONCE_BYTES] = kind;
        input[COOKIE_NONCE_BYTES + 1] = index;
        let digest = blake3::keyed_hash(key, &input);
        let words = digest.as_bytes();
        let word = |at: usize| u64::from_le_bytes(words[at * 8..at * 8 + 8].try_into().unwrap());
        Self {
            probe_base: word(0),
            probe_step: word(1) | 1,
            counter_hash: word(2),
        }
    }

    pub fn of_challenge(
        key: &FingerprintKey,
        challenge_nonce: &[u8; CHALLENGE_NONCE_BYTES],
    ) -> Self {
        let mut subject = [0u8; COOKIE_NONCE_BYTES];
        subject[..CHALLENGE_NONCE_BYTES].copy_from_slice(challenge_nonce);
        Self::of(
            key,
            &subject,
            Kind::SolvedHandshake as u8,
            SOLVED_HANDSHAKE_INDEX,
        )
    }
}

fn scale_to(hash: u64, range: u64) -> u64 {
    ((u128::from(hash) * u128::from(range)) >> 64) as u64
}

struct Generation {
    bloom: Box<[u64]>,
    counters: Box<[u64]>,
}

impl Generation {
    fn new(sizing: &ReplaySizing) -> Self {
        Self {
            bloom: vec![0; words_for(sizing.bloom.bits)].into_boxed_slice(),
            counters: vec![0; words_for(sizing.counter_slots * u64::from(sizing.counter_bits))]
                .into_boxed_slice(),
        }
    }

    fn clear(&mut self) {
        self.bloom.fill(0);
        self.counters.fill(0);
    }

    fn contains(&self, sizing: &ReplaySizing, fingerprint: &Fingerprint) -> bool {
        probe_positions(sizing, fingerprint).all(|bit| self.bloom_bit(bit))
    }

    fn insert(&mut self, sizing: &ReplaySizing, fingerprint: &Fingerprint) {
        for bit in probe_positions(sizing, fingerprint) {
            self.bloom[(bit / WORD_BITS) as usize] |= 1 << (bit % WORD_BITS);
        }
    }

    fn bloom_bit(&self, bit: u64) -> bool {
        self.bloom[(bit / WORD_BITS) as usize] >> (bit % WORD_BITS) & 1 == 1
    }

    fn counter(&self, sizing: &ReplaySizing, slot: u64) -> u64 {
        let (word, shift) = counter_location(sizing, slot);
        self.counters[word] >> shift & counter_mask(sizing)
    }

    fn increment_counter(&mut self, sizing: &ReplaySizing, slot: u64) {
        let (word, shift) = counter_location(sizing, slot);
        self.counters[word] += 1 << shift;
    }
}

fn probe_positions(
    sizing: &ReplaySizing,
    fingerprint: &Fingerprint,
) -> impl Iterator<Item = u64> + use<> {
    let (base, step, bits) = (
        fingerprint.probe_base,
        fingerprint.probe_step,
        sizing.bloom.bits,
    );
    (0..u64::from(sizing.bloom.hashes))
        .map(move |round| scale_to(base.wrapping_add(step.wrapping_mul(round)), bits))
}

fn counter_mask(sizing: &ReplaySizing) -> u64 {
    (1u64 << sizing.counter_bits) - 1
}

fn counter_location(sizing: &ReplaySizing, slot: u64) -> (usize, u64) {
    let bit = slot * u64::from(sizing.counter_bits);
    ((bit / WORD_BITS) as usize, bit % WORD_BITS)
}

fn counter_slot(sizing: &ReplaySizing, fingerprint: &Fingerprint) -> u64 {
    scale_to(fingerprint.counter_hash, sizing.counter_slots)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Fresh,
    Duplicate,
    Exhausted,
}

impl Admission {
    pub fn is_admitted(self) -> bool {
        self != Admission::Exhausted
    }
}

pub struct ReplayFilter {
    sizing: ReplaySizing,
    key: FingerprintKey,
    generations: [Generation; GENERATIONS],
    current: usize,
    cookie_rotations: Option<u32>,
}

impl ReplayFilter {
    pub fn new(sizing: ReplaySizing, key: FingerprintKey) -> Self {
        Self {
            sizing,
            key,
            generations: [Generation::new(&sizing), Generation::new(&sizing)],
            current: 0,
            cookie_rotations: None,
        }
    }

    pub fn empty_like(&self) -> Self {
        Self::new(self.sizing, self.key)
    }

    pub fn sizing(&self) -> &ReplaySizing {
        &self.sizing
    }

    pub fn fingerprint(
        &self,
        cookie_nonce: &[u8; COOKIE_NONCE_BYTES],
        kind: u8,
        index: u8,
    ) -> Fingerprint {
        Fingerprint::of(&self.key, cookie_nonce, kind, index)
    }

    pub fn challenge_fingerprint(
        &self,
        challenge_nonce: &[u8; CHALLENGE_NONCE_BYTES],
    ) -> Fingerprint {
        Fingerprint::of_challenge(&self.key, challenge_nonce)
    }

    pub fn remembers(&self, fingerprint: &Fingerprint) -> bool {
        self.generations
            .iter()
            .any(|generation| generation.contains(&self.sizing, fingerprint))
    }

    pub fn admit(&mut self, fingerprint: &Fingerprint, cookie_rotations: u32) -> Admission {
        self.advance_to(cookie_rotations);
        let current = self.current;
        let previous = self.other_generation();
        let in_current = self.generations[current].contains(&self.sizing, fingerprint);
        let in_previous = self.generations[previous].contains(&self.sizing, fingerprint);
        if !in_current && !in_previous {
            self.generations[current].insert(&self.sizing, fingerprint);
            return Admission::Fresh;
        }
        let slot = counter_slot(&self.sizing, fingerprint);
        let hits = [(current, in_current), (previous, in_previous)];
        let has_budget = hits.iter().all(|&(generation, hit)| {
            !hit || self.generations[generation].counter(&self.sizing, slot)
                < u64::from(self.sizing.duplicates)
        });
        if !has_budget {
            return Admission::Exhausted;
        }
        for (generation, hit) in hits {
            if hit {
                self.generations[generation].increment_counter(&self.sizing, slot);
            }
        }
        Admission::Duplicate
    }

    fn other_generation(&self) -> usize {
        1 - self.current
    }

    fn advance_to(&mut self, cookie_rotations: u32) {
        match self.cookie_rotations {
            Some(known) if known == cookie_rotations => return,
            Some(known) if known.wrapping_add(1) == cookie_rotations => {
                self.current = self.other_generation();
                self.generations[self.current].clear();
            }
            Some(_) => self.generations.iter_mut().for_each(Generation::clear),
            None => {}
        }
        self.cookie_rotations = Some(cookie_rotations);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngExt;

    fn config(rate: u32, rotation_secs: u32, duplicates: u8) -> ReplayConfig {
        ReplayConfig {
            rotation_secs,
            false_positive_rate: DEFAULT_FALSE_POSITIVE_RATE,
            max_rate: rate,
            duplicates,
        }
    }

    fn filter(rate: u32, rotation_secs: u32, duplicates: u8) -> ReplayFilter {
        let sizing = config(rate, rotation_secs, duplicates).sizing().unwrap();
        ReplayFilter::new(sizing, [7; FINGERPRINT_KEY_BYTES])
    }

    fn random_fingerprint() -> Fingerprint {
        let mut rng = rand::rng();
        Fingerprint {
            probe_base: rng.random(),
            probe_step: rng.random::<u64>() | 1,
            counter_hash: rng.random(),
        }
    }

    #[test]
    fn sizing_follows_the_formula_at_the_default_false_positive_rate() {
        let sizing = bloom_sizing(0.001, 100_000);
        assert_eq!(sizing.bits, 1_437_759);
        assert_eq!(sizing.hashes, 10);
        assert!((sizing.bits_per_insertion() - 14.378).abs() < 0.001);
    }

    #[test]
    fn worked_examples_match_the_documentation() {
        let examples = [
            (31_300u32, 313_000u64, 4_500_185u64, 1_203_312usize),
            (21_500, 215_000, 3_091_182, 826_560),
            (15_300, 153_000, 2_199_771, 588_208),
            (2_400, 24_000, 345_063, 92_272),
            (1_400, 14_000, 201_287, 53_840),
            (800, 8_000, 115_021, 30_768),
        ];
        for (rate, insertions, bits, memory) in examples {
            let sizing = config(rate, COOKIE_ROTATION_SECS, DEFAULT_DUPLICATES)
                .sizing()
                .unwrap();
            assert_eq!(sizing.bloom.insertions, insertions);
            assert_eq!(sizing.bloom.bits, bits);
            assert_eq!(sizing.bloom.hashes, 10);
            assert_eq!(sizing.memory_bytes(), memory);
        }
    }

    #[test]
    fn sizing_rejects_nonsense() {
        assert!(config(0, 5, 3).sizing().is_err());
        assert!(config(10, 0, 3).sizing().is_err());
        let mut bad = config(10, 5, 3);
        bad.false_positive_rate = 1.0;
        assert!(bad.sizing().is_err());
    }

    #[test]
    fn counter_width_covers_the_duplicate_budget() {
        assert_eq!(counter_width_bits(0), 1);
        assert_eq!(counter_width_bits(1), 1);
        assert_eq!(counter_width_bits(3), 2);
        assert_eq!(counter_width_bits(4), 4);
        assert_eq!(counter_width_bits(15), 4);
        assert_eq!(counter_width_bits(16), 8);
        assert_eq!(counter_width_bits(255), 8);
    }

    #[test]
    fn fresh_then_duplicates_then_exhausted() {
        let mut filter = filter(100, 5, 3);
        let fingerprint = random_fingerprint();
        assert_eq!(filter.admit(&fingerprint, 100), Admission::Fresh);
        for _ in 0..3 {
            assert_eq!(filter.admit(&fingerprint, 100), Admission::Duplicate);
        }
        for _ in 0..5 {
            assert_eq!(filter.admit(&fingerprint, 100), Admission::Exhausted);
        }
    }

    #[test]
    fn zero_duplicates_drops_every_repeat() {
        let mut filter = filter(100, 5, 0);
        let fingerprint = random_fingerprint();
        assert_eq!(filter.admit(&fingerprint, 100), Admission::Fresh);
        assert_eq!(filter.admit(&fingerprint, 100), Admission::Exhausted);
    }

    #[test]
    fn entry_lives_until_the_second_rotation_after_insertion() {
        let mut filter = filter(100, 10, 0);
        let fingerprint = random_fingerprint();
        assert_eq!(filter.admit(&fingerprint, 7), Admission::Fresh);
        assert_eq!(filter.admit(&fingerprint, 7), Admission::Exhausted);
        assert_eq!(filter.admit(&fingerprint, 8), Admission::Exhausted);
        assert_eq!(filter.admit(&fingerprint, 9), Admission::Fresh);
    }

    #[test]
    fn duplicates_counted_in_the_old_generation_survive_rotation() {
        let mut filter = filter(100, 5, 1);
        let fingerprint = random_fingerprint();
        assert_eq!(filter.admit(&fingerprint, 100), Admission::Fresh);
        assert_eq!(filter.admit(&fingerprint, 100), Admission::Duplicate);
        assert_eq!(filter.admit(&fingerprint, 101), Admission::Exhausted);
    }

    #[test]
    fn a_jump_of_more_than_one_rotation_forgets_everything() {
        let mut filter = filter(100, 10, 0);
        let fingerprint = random_fingerprint();
        assert_eq!(filter.admit(&fingerprint, 100), Admission::Fresh);
        assert_eq!(filter.admit(&fingerprint, 102), Admission::Fresh);
    }

    #[test]
    fn empirical_false_positive_rate_is_within_twice_the_target() {
        for rate in [2_000u32, 15_300, 31_300] {
            let config = config(rate, COOKIE_ROTATION_SECS, 3);
            let mut filter = ReplayFilter::new(config.sizing().unwrap(), [1; 32]);
            let insertions = config.expected_insertions();
            for _ in 0..insertions {
                filter.admit(&random_fingerprint(), 100);
            }
            let queries = 1_000_000u64;
            let hits = (0..queries)
                .filter(|_| filter.remembers(&random_fingerprint()))
                .count() as f64;
            let measured = hits / queries as f64;
            let target = config.false_positive_rate;
            assert!(
                measured <= 2.0 * target && measured >= target / 2.0,
                "rate {rate}: measured {measured}, target {target}"
            );
        }
    }

    #[test]
    fn real_fingerprints_separate_every_input() {
        let key = [3u8; FINGERPRINT_KEY_BYTES];
        let nonce = [9u8; 24];
        let base = Fingerprint::of(&key, &nonce, 1, 2);
        assert_eq!(base, Fingerprint::of(&key, &nonce, 1, 2));
        assert_ne!(base, Fingerprint::of(&key, &nonce, 2, 2));
        assert_ne!(base, Fingerprint::of(&key, &nonce, 1, 3));
        assert_ne!(base, Fingerprint::of(&[4u8; 32], &nonce, 1, 2));
        let mut other_nonce = nonce;
        other_nonce[0] ^= 1;
        assert_ne!(base, Fingerprint::of(&key, &other_nonce, 1, 2));
    }

    #[test]
    fn challenge_fingerprints_are_apart_from_cookie_fingerprints() {
        let key = [3u8; FINGERPRINT_KEY_BYTES];
        let challenge_nonce = [9u8; CHALLENGE_NONCE_BYTES];
        let mut padded = [0u8; COOKIE_NONCE_BYTES];
        padded[..CHALLENGE_NONCE_BYTES].copy_from_slice(&challenge_nonce);
        let solved = Fingerprint::of_challenge(&key, &challenge_nonce);
        assert_eq!(solved, Fingerprint::of_challenge(&key, &challenge_nonce));
        for kind in [Kind::UChunk, Kind::VResidue] {
            assert_ne!(solved, Fingerprint::of(&key, &padded, kind as u8, 0));
        }
        let mut other_nonce = challenge_nonce;
        other_nonce[15] ^= 1;
        assert_ne!(solved, Fingerprint::of_challenge(&key, &other_nonce));
    }
}
