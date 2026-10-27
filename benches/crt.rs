#[path = "../profiling/workload.rs"]
mod workload;

use HQCLethe::auth::shared_keypair;
use HQCLethe::client::Client;
use HQCLethe::crt::client::{reconstruct_v, residues_of};
use HQCLethe::encoding::{Kind, MAX_UDP_PAYLOAD};
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::server::Server;
use HQCLethe::session::run_in_process;
use HQCLethe::traits::*;
use criterion::{Criterion, criterion_group, criterion_main};
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

type BenchServer<S> = Server<S, NullSessionStore, Entropy>;

fn make_server<S: HqcScheme>() -> BenchServer<S> {
    Server::new(
        NullSessionStore,
        Entropy,
        shared_keypair::<S>().secret.clone(),
    )
}

fn requests_of_kind<S: HqcScheme>(
    server: &BenchServer<S>,
    client: Client<S, NullSessionStore, Entropy, HQCLethe::client::Initial>,
    kind: Kind,
) -> Vec<Vec<u8>> {
    let (client, request) = client.initialize(&shared_keypair::<S>().public);
    let mut out = [0u8; MAX_UDP_PAYLOAD];
    let len = server.handle_packet(PEER, &request, &mut out).unwrap();
    let client = client.handle_handshake_response(&out[..len]).unwrap();
    client
        .requests()
        .iter()
        .filter(|r| r.kind == kind)
        .map(|r| r.bytes.clone())
        .collect()
}

fn random_poly(words: usize, bits: usize) -> Vec<u64> {
    let mut poly: Vec<u64> = (0..words).map(|_| rand::rng().next_u64()).collect();
    if !bits.is_multiple_of(64) {
        poly[bits / 64] &= (1u64 << (bits % 64)) - 1;
        poly[bits / 64 + 1..].fill(0);
    }
    poly
}

fn bench_server<S: HqcScheme>(c: &mut Criterion, name: &str) {
    let server = make_server::<S>();
    let requests = requests_of_kind(
        &server,
        Client::new(NullSessionStore, Entropy),
        Kind::VResidue,
    );
    let mut out = [0u8; MAX_UDP_PAYLOAD];

    c.bench_function(&format!("{name}_server_v_residue_request"), |b| {
        b.iter(|| {
            server
                .handle_vresidue(black_box(&requests[0]), &mut out)
                .unwrap()
        })
    });
    c.bench_function(&format!("{name}_server_v_residue_all_requests"), |b| {
        b.iter(|| {
            for request in &requests {
                server
                    .handle_vresidue(black_box(request), &mut out)
                    .unwrap();
            }
        })
    });
}

fn bench_client<S: HqcScheme>(c: &mut Criterion, name: &str) {
    let s = random_poly(S::VEC_N_SIZE_64, S::PARAM_N);
    c.bench_function(&format!("{name}_client_residues"), |b| {
        b.iter(|| residues_of::<S>(black_box(&s)))
    });

    let unreduced = random_poly(2 * S::VEC_N_SIZE_64, 2 * S::PARAM_N - 1);
    let residues = residues_of::<S>(&unreduced);
    c.bench_function(&format!("{name}_client_reconstruct"), |b| {
        b.iter(|| reconstruct_v::<S>(black_box(&residues)))
    });
}

fn bench_session<S: HqcScheme>(c: &mut Criterion, name: &str) {
    let keys = shared_keypair::<S>();
    let server = make_server::<S>();
    c.bench_function(&format!("{name}_full_session"), |b| {
        b.iter(|| {
            run_in_process(
                &server,
                Client::<S, _, _, _>::new(NullSessionStore, Entropy),
                &keys.public,
            )
            .unwrap()
        })
    });
}

fn bench_hqc1(c: &mut Criterion) {
    bench_server::<Hqc1>(c, "hqc1");
    bench_client::<Hqc1>(c, "hqc1");
    bench_session::<Hqc1>(c, "hqc1");
}
fn bench_hqc3(c: &mut Criterion) {
    bench_server::<Hqc3>(c, "hqc3");
    bench_client::<Hqc3>(c, "hqc3");
    bench_session::<Hqc3>(c, "hqc3");
}
fn bench_hqc5(c: &mut Criterion) {
    bench_server::<Hqc5>(c, "hqc5");
    bench_client::<Hqc5>(c, "hqc5");
    bench_session::<Hqc5>(c, "hqc5");
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_hqc1, bench_hqc3, bench_hqc5
}
criterion_main!(benches);
