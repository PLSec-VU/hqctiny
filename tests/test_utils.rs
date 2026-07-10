#![allow(dead_code)]

use HQCTiny::traits::*;
use rand::Rng;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct SharedSessionStore {
    pub sessions: Arc<Mutex<Vec<[u8; 32]>>>,
}

impl SharedSessionStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionStore for SharedSessionStore {
    fn save_session(&self, k_session: [u8; 32]) {
        self.sessions.lock().unwrap().push(k_session);
    }
}

pub struct MockEntropy;
impl EntropyProvider for MockEntropy {
    fn random_bytes(&self, out: &mut [u8]) {
        rand::rng().fill_bytes(out);
    }
}
