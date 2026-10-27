pub mod client;
pub mod gf2x;
pub mod params;
pub mod scatter;
pub mod server;

pub use params::{MAX_RESIDUE_BYTES, MAX_RESIDUE_WORDS, Modulus};

#[cfg(test)]
mod tests {
    use super::client::{reconstruct_v, residues_of, unreduced_from_residues};
    use super::gf2x::{mul_mod, reduce_in_place};
    use super::params::Modulus;
    use super::scatter::{scatter_buffer_words, scatter_support};
    use crate::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};

    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545F4914F6CDD1D)
        }

        fn words(&mut self, count: usize) -> Vec<u64> {
            (0..count).map(|_| self.next()).collect()
        }
    }

    fn bit(words: &[u64], i: usize) -> bool {
        words[i / 64] >> (i % 64) & 1 == 1
    }

    fn flip(words: &mut [u64], i: usize) {
        words[i / 64] ^= 1u64 << (i % 64);
    }

    fn naive_reduce(words: &[u64], modulus: Modulus) -> Vec<u64> {
        let mut work = words.to_vec();
        for i in (modulus.degree..work.len() * 64).rev() {
            if bit(&work, i) {
                flip(&mut work, i);
                flip(&mut work, i - modulus.degree + modulus.middle);
                flip(&mut work, i - modulus.degree);
            }
        }
        work.truncate(modulus.words());
        work
    }

    fn naive_product(a: &[u64], b: &[u64]) -> Vec<u64> {
        let mut out = vec![0u64; a.len() + b.len() + 1];
        for i in 0..a.len() * 64 {
            if bit(a, i) {
                for (k, &word) in b.iter().enumerate() {
                    let at = i / 64 + k;
                    out[at] ^= word << (i % 64);
                    if i % 64 != 0 {
                        out[at + 1] ^= word >> (64 - i % 64);
                    }
                }
            }
        }
        out
    }

    fn all_moduli() -> Vec<(&'static str, usize, &'static [Modulus])> {
        vec![
            ("hqc1", Hqc1::PARAM_N, Hqc1::CRT_MODULI),
            ("hqc3", Hqc3::PARAM_N, Hqc3::CRT_MODULI),
            ("hqc5", Hqc5::PARAM_N, Hqc5::CRT_MODULI),
        ]
    }

    #[test]
    fn degrees_sum_to_the_unreduced_degree_bound() {
        for (name, n, moduli) in all_moduli() {
            let total: usize = moduli.iter().map(|m| m.degree).sum();
            assert_eq!(total, 2 * n - 1, "{name}");
        }
    }

    #[test]
    fn reduction_matches_the_bit_loop() {
        let mut rng = XorShift(0x1234_5678_9ABC_DEF1);
        for (_, _, moduli) in all_moduli() {
            for &modulus in moduli {
                for len in [modulus.words(), 2 * modulus.words() + 2, 900] {
                    let poly = rng.words(len);
                    let mut got = poly.clone();
                    reduce_in_place(&mut got, modulus);
                    assert!(got[modulus.words()..].iter().all(|&w| w == 0));
                    assert_eq!(&got[..modulus.words()], &naive_reduce(&poly, modulus)[..]);
                }
            }
        }
    }

    #[test]
    fn multiplication_mod_matches_the_bit_loop() {
        let mut rng = XorShift(0x0F0F_1234_5555_AAAA);
        for (_, _, moduli) in all_moduli() {
            for &modulus in moduli.iter().take(3) {
                let words = modulus.words();
                let mut a = rng.words(words);
                let mut b = rng.words(words);
                *a.last_mut().unwrap() &= modulus.top_word_mask();
                *b.last_mut().unwrap() &= modulus.top_word_mask();
                let mut got = vec![0u64; words];
                mul_mod(&a, &b, modulus, &mut got);
                let expected = naive_reduce(&naive_product(&a, &b), modulus);
                assert_eq!(got, expected);
            }
        }
    }

    #[test]
    fn scatter_matches_dense_construction() {
        let mut rng = XorShift(0xDEAD_BEEF_0123_4567);
        for (n, weight) in [(17669usize, 75usize), (35851, 114), (57637, 149)] {
            let n_words = n.div_ceil(64);
            let mut support: Vec<u32> = Vec::new();
            while support.len() < weight {
                let p = (rng.next() % n as u64) as u32;
                if !support.contains(&p) {
                    support.push(p);
                }
            }
            let mut got = vec![0u64; scatter_buffer_words(n_words)];
            scatter_support(&support, &mut got);
            let mut expected = vec![0u64; got.len()];
            for &p in &support {
                flip(&mut expected, p as usize);
            }
            assert_eq!(got, expected);
        }
    }

    fn reconstruction_roundtrip<S: HqcScheme>() {
        let mut rng = XorShift(0xC0FFEE_u64 ^ S::PARAM_N as u64);
        let total_bits = 2 * S::PARAM_N - 1;
        let mut unreduced = rng.words(2 * S::VEC_N_SIZE_64);
        for i in total_bits..unreduced.len() * 64 {
            if bit(&unreduced, i) {
                flip(&mut unreduced, i);
            }
        }
        let residues = residues_of::<S>(&unreduced);
        let rebuilt = unreduced_from_residues::<S>(&residues);
        assert_eq!(rebuilt, unreduced);
    }

    #[test]
    fn residues_reconstruct_the_unreduced_polynomial() {
        reconstruction_roundtrip::<Hqc1>();
        reconstruction_roundtrip::<Hqc3>();
        reconstruction_roundtrip::<Hqc5>();
    }

    fn reconstruction_reduces_modulo_xn_minus_1<S: HqcScheme>() {
        let mut rng = XorShift(0xFACE_u64 ^ S::PARAM_N as u64);
        let mut unreduced = rng.words(2 * S::VEC_N_SIZE_64);
        for i in 2 * S::PARAM_N - 1..unreduced.len() * 64 {
            if bit(&unreduced, i) {
                flip(&mut unreduced, i);
            }
        }
        let mut expected = vec![0u64; S::VEC_N_SIZE_64];
        for i in 0..2 * S::PARAM_N - 1 {
            if bit(&unreduced, i) {
                flip(&mut expected, i % S::PARAM_N);
            }
        }
        let got = reconstruct_v::<S>(&residues_of::<S>(&unreduced));
        assert_eq!(got, expected);
    }

    #[test]
    fn reconstruction_reduces_like_the_ring() {
        reconstruction_reduces_modulo_xn_minus_1::<Hqc1>();
        reconstruction_reduces_modulo_xn_minus_1::<Hqc3>();
        reconstruction_reduces_modulo_xn_minus_1::<Hqc5>();
    }
}
