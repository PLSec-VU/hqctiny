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

use HQCLethe::client::Client;
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::protocol::{HandshakeRequest, PointRequest, PointType};
use HQCLethe::server::Server;
use HQCLethe::traits::*;
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use rand::Rng;
use std::hint::black_box;

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
    Server::new(NullSessionStore, Entropy)
}

fn setup_handshake<SCHEME: HqcScheme>() -> (Srv<SCHEME>, HandshakeRequest) {
    let server = make_server::<SCHEME>();
    let client = Client::<SCHEME, _, _, _>::new(NullSessionStore, Entropy);
    let (_client, req) = client.initialize();
    (server, req)
}

fn setup_point_request<SCHEME: HqcScheme>(point_type: PointType) -> (Srv<SCHEME>, PointRequest) {
    let server = make_server::<SCHEME>();
    let client = Client::<SCHEME, _, _, _>::new(NullSessionStore, Entropy);
    let (client, req) = client.initialize();
    let res = server.handle_handshake(req).unwrap();
    let (_client, point_reqs) = client.handle_handshake_response(res).unwrap();
    let req = point_reqs
        .into_iter()
        .find(|r| r.point_index == 1 && r.point_type == point_type)
        .unwrap();
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
    ($scheme:ty, $keygen:ident, $dec:ident, $handshake:ident, $point_u:ident, $point_v:ident, $group:ident) => {
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
        fn $handshake(input: (Srv<$scheme>, HandshakeRequest)) {
            let (server, req) = input;
            black_box(server.handle_handshake(req).unwrap());
        }

        #[library_benchmark]
        #[bench::point_request_u(setup_point_request::<$scheme>(PointType::U))]
        fn $point_u(input: (Srv<$scheme>, PointRequest)) {
            let (server, req) = input;
            black_box(server.handle_point_request(req).unwrap());
        }

        #[library_benchmark]
        #[bench::point_request_v(setup_point_request::<$scheme>(PointType::V))]
        fn $point_v(input: (Srv<$scheme>, PointRequest)) {
            let (server, req) = input;
            black_box(server.handle_point_request(req).unwrap());
        }

        library_benchmark_group!(
            name = $group;
            benchmarks = $keygen, $dec, $handshake, $point_u, $point_v
        );
    };
}

define_variant_benches!(
    Hqc1,
    hqc1_keygen,
    hqc1_dec,
    hqc1_handshake,
    hqc1_point_request_u,
    hqc1_point_request_v,
    hqc1_group
);
define_variant_benches!(
    Hqc3,
    hqc3_keygen,
    hqc3_dec,
    hqc3_handshake,
    hqc3_point_request_u,
    hqc3_point_request_v,
    hqc3_group
);
define_variant_benches!(
    Hqc5,
    hqc5_keygen,
    hqc5_dec,
    hqc5_handshake,
    hqc5_point_request_u,
    hqc5_point_request_v,
    hqc5_group
);

main!(
    library_benchmark_groups = hqc1_group,
    hqc3_group,
    hqc5_group
);
