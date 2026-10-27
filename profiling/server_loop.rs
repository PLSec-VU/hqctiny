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

fn first_request_of<SCHEME: HqcScheme>(
    server: &Server<SCHEME, NullSessionStore, Entropy>,
    kind: Kind,
) -> Vec<u8> {
    let client = Client::<SCHEME, _, _, _>::new(NullSessionStore, Entropy);
    let (client, handshake) = client.initialize(&shared_keypair::<SCHEME>().public);
    let mut out = [0u8; MAX_UDP_PAYLOAD];
    let len = server.handle_packet(PEER, &handshake, &mut out).unwrap();
    let client = client.handle_handshake_response(&out[..len]).unwrap();
    client
        .requests()
        .iter()
        .find(|request| request.kind == kind)
        .unwrap()
        .bytes
        .clone()
}

fn run<SCHEME: HqcScheme>(kind: Kind, iterations: u64) {
    let server = Server::<SCHEME, _, _>::new(
        NullSessionStore,
        Entropy,
        shared_keypair::<SCHEME>().secret.clone(),
    );
    let request = match kind {
        Kind::Handshake => {
            let client = Client::<SCHEME, _, _, _>::new(NullSessionStore, Entropy);
            client.initialize(&shared_keypair::<SCHEME>().public).1
        }
        _ => first_request_of::<SCHEME>(&server, kind),
    };
    let mut out = [0u8; MAX_UDP_PAYLOAD];
    let started = std::time::Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(server.handle_packet(PEER, std::hint::black_box(&request), &mut out))
            .unwrap();
    }
    let per_request = started.elapsed() / iterations as u32;
    println!("{per_request:?} per request");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let iterations: u64 = args[3].parse().unwrap();
    let kind = match args[2].as_str() {
        "handshake" => Kind::Handshake,
        "uchunk" => Kind::UChunk,
        _ => Kind::VResidue,
    };
    match args[1].as_str() {
        "1" => run::<Hqc1>(kind, iterations),
        "3" => run::<Hqc3>(kind, iterations),
        _ => run::<Hqc5>(kind, iterations),
    }
}
