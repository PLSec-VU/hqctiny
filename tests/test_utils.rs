#![allow(dead_code)]

use HQCLethe::traits::*;
use rand::Rng;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[derive(Default, Clone)]
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

#[derive(Clone)]
pub struct MockEntropy;
impl EntropyProvider for MockEntropy {
    fn random_bytes(&self, out: &mut [u8]) {
        rand::rng().fill_bytes(out);
    }
}

/// Serves a fixed byte stream first, then falls back to the OS generator.
pub struct ScriptedEntropy {
    script: Mutex<VecDeque<u8>>,
}

impl ScriptedEntropy {
    pub fn new(script: &[u8]) -> Self {
        Self {
            script: Mutex::new(script.iter().copied().collect()),
        }
    }
}

impl EntropyProvider for ScriptedEntropy {
    fn random_bytes(&self, out: &mut [u8]) {
        let mut script = self.script.lock().unwrap();
        for byte in out.iter_mut() {
            *byte = script.pop_front().unwrap_or_else(|| {
                let mut one = [0u8; 1];
                rand::rng().fill_bytes(&mut one);
                one[0]
            });
        }
    }
}

pub struct ManualClock {
    seconds: std::sync::atomic::AtomicU32,
}

impl ManualClock {
    pub fn at(seconds: u32) -> Arc<Self> {
        Arc::new(Self {
            seconds: std::sync::atomic::AtomicU32::new(seconds),
        })
    }

    pub fn advance(&self, seconds: u32) {
        self.seconds
            .fetch_add(seconds, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn set(&self, seconds: u32) {
        self.seconds
            .store(seconds, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn unix_seconds(&self) -> u32 {
        self.seconds.load(std::sync::atomic::Ordering::SeqCst)
    }
}
