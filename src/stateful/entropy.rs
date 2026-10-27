use crate::traits::EntropyProvider;
use rand::Rng;

#[derive(Clone, Copy, Default)]
pub struct OsEntropy;

impl EntropyProvider for OsEntropy {
    fn random_bytes(&self, out: &mut [u8]) {
        rand::rng().fill_bytes(out);
    }
}
