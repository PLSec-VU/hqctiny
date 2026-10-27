#![allow(dead_code)]

use HQCLethe::auth::shared_keypair;
use HQCLethe::client::Client;
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::server::Server;
use HQCLethe::session::run_in_process;
use HQCLethe::traits::*;
use rand::Rng;

#[derive(Clone)]
struct Entropy;
impl EntropyProvider for Entropy {
    fn random_bytes(&self, out: &mut [u8]) {
        rand::rng().fill_bytes(out);
    }
}

#[derive(Clone, Default)]
struct NullSessionStore;
impl SessionStore for NullSessionStore {
    fn save_session(&self, _k_session: [u8; 32]) {}
}

pub fn run_round_trip<SCHEME: HqcScheme>() {
    let keys = shared_keypair::<SCHEME>();
    let server = Server::<SCHEME, _, _>::new(NullSessionStore, Entropy, keys.secret.clone());
    let client = Client::<SCHEME, _, _, _>::new(NullSessionStore, Entropy);
    run_in_process(&server, client, &keys.public).unwrap();
}

pub fn run_all(iterations: usize) {
    for _ in 0..iterations {
        run_round_trip::<Hqc1>();
        run_round_trip::<Hqc3>();
        run_round_trip::<Hqc5>();
    }
}
