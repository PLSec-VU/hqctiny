pub trait SessionStore {
    fn save_session(&self, k_session: [u8; 32]);
}

pub trait EntropyProvider {
    fn random_bytes(&self, out: &mut [u8]);
}
