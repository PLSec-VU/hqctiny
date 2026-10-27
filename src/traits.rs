pub trait SessionStore {
    fn save_session(&self, k_session: [u8; 32]);
}

pub trait EntropyProvider {
    fn random_bytes(&self, out: &mut [u8]);
}

pub trait Clock: Send + Sync {
    fn unix_seconds(&self) -> u32;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_seconds(&self) -> u32 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs() as u32)
    }
}
