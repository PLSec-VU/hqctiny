//! Deterministic instruction-count / estimated-cycle measurements via
//! Cachegrind's cost model (through iai-callgrind), used as a
//! host-independent stand-in for "clock cycles" — wall-clock cycle counts
//! (rdtsc) aren't portable across the arm64/x86_64 hosts this project is
//! developed and deployed on, and criterion's wall-time medians (see
//! benches/kem_primitives.rs and benches/protocol_phases.rs) already cover
//! the variance side of that ask. This needs `valgrind` on PATH; see
//! eval/scripts/cpu_benchmarks.py, which runs it inside the eval Docker
//! image.
//!
//! iai-callgrind's `main!` macro takes bare group identifiers (no module
//! paths), so the three HQC variants are spelled out at file scope instead
//! of factored into a macro_rules! over a shared module — that would need
//! identifier concatenation (a `paste`-style dependency) this project
//! doesn't otherwise need.

use HQCLethe::auth::shared_keypair;
use HQCLethe::client::Client;
use HQCLethe::encoding::{Kind, MAX_UDP_PAYLOAD};
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::server::Server;
use HQCLethe::traits::*;
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use rand::Rng;
use std::hint::black_box;

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

type Srv<SCHEME> = Server<SCHEME, NullSessionStore, Entropy>;

fn make_server<SCHEME: HqcScheme>() -> Srv<SCHEME> {
    Server::new(
        NullSessionStore,
        Entropy,
        shared_keypair::<SCHEME>().secret.clone(),
    )
}

fn setup_handshake<SCHEME: HqcScheme>() -> (Srv<SCHEME>, Vec<u8>) {
    let server = make_server::<SCHEME>();
    let client = Client::<SCHEME, _, _, _>::new(NullSessionStore, Entropy);
    let (_client, req) = client.initialize(&shared_keypair::<SCHEME>().public);
    (server, req)
}

fn setup_request<SCHEME: HqcScheme>(kind: Kind) -> (Srv<SCHEME>, Vec<u8>) {
    let server = make_server::<SCHEME>();
    let client = Client::<SCHEME, _, _, _>::new(NullSessionStore, Entropy);
    let (client, req) = client.initialize(&shared_keypair::<SCHEME>().public);
    let mut out = [0u8; MAX_UDP_PAYLOAD];
    let len = server.handle_packet(PEER, &req, &mut out).unwrap();
    let client = client.handle_handshake_response(&out[..len]).unwrap();
    let req = client
        .requests()
        .iter()
        .find(|r| r.kind == kind)
        .unwrap()
        .bytes
        .clone();
    (server, req)
}

fn setup_keygen() -> [u8; 48] {
    let entropy = Entropy;
    let mut ent = [0u8; 48];
    entropy.random_bytes(&mut ent);
    ent
}

fn setup_dec<SCHEME: HqcScheme>() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let entropy = Entropy;
    let mut pk = vec![0u8; SCHEME::PUBLIC_KEY_BYTES];
    let mut sk = vec![0u8; SCHEME::SECRET_KEY_BYTES];
    let mut ent = [0u8; 48];
    entropy.random_bytes(&mut ent);
    unsafe {
        SCHEME::keypair(&ent, &mut pk, &mut sk);
    }
    let ct = vec![0u8; SCHEME::CIPHERTEXT_BYTES];
    let ss = vec![0u8; SCHEME::SHARED_SECRET_BYTES];
    (ss, ct, sk)
}

macro_rules! define_variant_benches {
    ($scheme:ty, $keygen:ident, $dec:ident, $handshake:ident, $uchunk:ident, $vresidue:ident, $group:ident) => {
        #[library_benchmark]
        #[bench::keygen(setup_keygen())]
        fn $keygen(ent: [u8; 48]) -> (Vec<u8>, Vec<u8>) {
            let mut pk = vec![0u8; <$scheme as HqcScheme>::PUBLIC_KEY_BYTES];
            let mut sk = vec![0u8; <$scheme as HqcScheme>::SECRET_KEY_BYTES];
            unsafe {
                <$scheme as HqcScheme>::keypair(black_box(&ent), &mut pk, &mut sk);
            }
            (pk, sk)
        }

        #[library_benchmark]
        #[bench::dec(setup_dec::<$scheme>())]
        fn $dec(input: (Vec<u8>, Vec<u8>, Vec<u8>)) -> Vec<u8> {
            let (mut ss, ct, sk) = input;
            <$scheme as HqcScheme>::dec(&mut ss, black_box(&ct), black_box(&sk));
            ss
        }

        #[library_benchmark]
        #[bench::handshake(setup_handshake::<$scheme>())]
        fn $handshake(input: (Srv<$scheme>, Vec<u8>)) {
            let (server, req) = input;
            let mut out = [0u8; MAX_UDP_PAYLOAD];
            black_box(server.handle_handshake(PEER, &req, &mut out).unwrap());
        }

        #[library_benchmark]
        #[bench::uchunk_request(setup_request::<$scheme>(Kind::UChunk))]
        fn $uchunk(input: (Srv<$scheme>, Vec<u8>)) {
            let (server, req) = input;
            let mut out = [0u8; MAX_UDP_PAYLOAD];
            black_box(server.handle_uchunk(&req, &mut out).unwrap());
        }

        #[library_benchmark]
        #[bench::vresidue_request(setup_request::<$scheme>(Kind::VResidue))]
        fn $vresidue(input: (Srv<$scheme>, Vec<u8>)) {
            let (server, req) = input;
            let mut out = [0u8; MAX_UDP_PAYLOAD];
            black_box(server.handle_vresidue(&req, &mut out).unwrap());
        }

        library_benchmark_group!(
            name = $group;
            benchmarks = $keygen, $dec, $handshake, $uchunk, $vresidue
        );
    };
}

define_variant_benches!(
    Hqc1,
    hqc1_keygen,
    hqc1_dec,
    hqc1_handshake,
    hqc1_uchunk_request,
    hqc1_vresidue_request,
    hqc1_group
);
define_variant_benches!(
    Hqc3,
    hqc3_keygen,
    hqc3_dec,
    hqc3_handshake,
    hqc3_uchunk_request,
    hqc3_vresidue_request,
    hqc3_group
);
define_variant_benches!(
    Hqc5,
    hqc5_keygen,
    hqc5_dec,
    hqc5_handshake,
    hqc5_uchunk_request,
    hqc5_vresidue_request,
    hqc5_group
);

main!(
    library_benchmark_groups = hqc1_group,
    hqc3_group,
    hqc5_group
);
