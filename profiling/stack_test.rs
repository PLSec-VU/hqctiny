#[path = "workload.rs"]
mod workload;

use HQCLethe::auth::shared_keypair;
use HQCLethe::client::Client;
use HQCLethe::encoding::{Kind, MAX_UDP_PAYLOAD};
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::server::Server;
use HQCLethe::traits::*;
use rand::Rng;

const PEER: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

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

/// Answers one request of `kind` on a thread with exactly `stack_kib` KiB of
/// stack. A stack overflow kills the process, so a caller finds the minimum by
/// searching over `stack_kib` and watching the exit status.
fn serve_one_on_small_stack<S: HqcScheme>(kind: Kind, stack_kib: usize) {
    let keys = shared_keypair::<S>();
    let server = Server::<S, _, _>::new(NullSessionStore, Entropy, keys.secret.clone());
    let client = Client::<S, _, _, _>::new(NullSessionStore, Entropy);
    let (client, handshake) = client.initialize(&keys.public);
    let mut out = [0u8; MAX_UDP_PAYLOAD];
    let len = server.handle_packet(PEER, &handshake, &mut out).unwrap();
    let client = client.handle_handshake_response(&out[..len]).unwrap();
    let request = match kind {
        Kind::Handshake => handshake,
        _ => client
            .requests()
            .iter()
            .find(|r| r.kind == kind)
            .unwrap()
            .bytes
            .clone(),
    };

    std::thread::Builder::new()
        .stack_size(stack_kib * 1024)
        .spawn(move || {
            let mut out = [0u8; MAX_UDP_PAYLOAD];
            server.handle_packet(PEER, &request, &mut out).unwrap();
        })
        .unwrap()
        .join()
        .unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [level, kind, stack_kib] = args.as_slice() else {
        workload::run_round_trip::<Hqc5>();
        return;
    };
    let kind = match kind.as_str() {
        "handshake" => Kind::Handshake,
        "uchunk" => Kind::UChunk,
        "vresidue" => Kind::VResidue,
        _ => panic!("kind must be handshake, uchunk or vresidue"),
    };
    let stack_kib: usize = stack_kib.parse().unwrap();
    match level.as_str() {
        "hqc1" => serve_one_on_small_stack::<Hqc1>(kind, stack_kib),
        "hqc3" => serve_one_on_small_stack::<Hqc3>(kind, stack_kib),
        "hqc5" => serve_one_on_small_stack::<Hqc5>(kind, stack_kib),
        _ => panic!("level must be hqc1, hqc3 or hqc5"),
    }
}
