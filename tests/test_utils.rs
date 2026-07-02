#![allow(dead_code)]

use HQCTiny::traits::*;
use rand::Rng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

#[derive(Default)]
pub struct SharedSessionStore {
    pub sessions: Arc<Mutex<HashMap<[u8; 32], [u8; 32]>>>,
}

impl SharedSessionStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionStore for SharedSessionStore {
    fn save_session(&self, hash_ek_kem: &[u8; 32], k_session: [u8; 32]) {
        self.sessions
            .lock()
            .unwrap()
            .insert(*hash_ek_kem, k_session);
    }
    fn get_session(&self, hash_ek_kem: &[u8; 32]) -> Option<[u8; 32]> {
        self.sessions.lock().unwrap().get(hash_ek_kem).cloned()
    }
}

pub struct MockEntropy;
impl EntropyProvider for MockEntropy {
    fn random_bytes(&self, out: &mut [u8]) {
        rand::rng().fill_bytes(out);
    }
}

pub struct InMemoryKeyProvider {
    pub current_idx: RwLock<u8>,
    pub keys: [RwLock<Option<[u8; 32]>>; 2],
}

impl InMemoryKeyProvider {
    pub fn new(entropy: &impl EntropyProvider) -> Self {
        let mut k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        entropy.random_bytes(&mut k0);
        entropy.random_bytes(&mut k1);
        Self {
            current_idx: RwLock::new(0),
            keys: [RwLock::new(Some(k0)), RwLock::new(Some(k1))],
        }
    }
}

impl CookieKeyProvider for InMemoryKeyProvider {
    fn current_key_index(&self) -> u8 {
        *self.current_idx.read().unwrap()
    }

    fn get_key(&self, index: u8) -> Option<[u8; 32]> {
        if index > 1 {
            return None;
        }
        *self.keys[index as usize].read().unwrap()
    }
}
