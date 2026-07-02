pub trait SessionStore {
    fn save_session(&self, hash_ek_kem: &[u8; 32], k_session: [u8; 32]);
    fn get_session(&self, hash_ek_kem: &[u8; 32]) -> Option<[u8; 32]>;
}

pub trait EntropyProvider {
    fn random_bytes(&self, out: &mut [u8]);
}

pub trait CookieKeyProvider {
    /// Get the index of the current active key (0 or 1).
    fn current_key_index(&self) -> u8;

    /// Get the key for the given index (0 or 1).
    /// Returns None if the key has expired or is invalid.
    fn get_key(&self, index: u8) -> Option<[u8; 32]>;
}
