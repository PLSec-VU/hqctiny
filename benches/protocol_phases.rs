//! Microbenchmarks for HQCLethe's per-packet protocol work on the server
//! (handshake including the ML-KEM decapsulation, u-chunk request, v-residue
//! request), the client's building blocks (HQC key generation, ML-KEM
//! encapsulation, HQC decapsulation), and a complete client+server transaction.
//!
//! Names: `hqcN_server_handshake`, `hqcN_server_uchunk_request`,
//! `hqcN_server_vresidue_request`, `hqcN_server_mlkem_decap`,
//! `hqcN_client_keygen`, `hqcN_client_initialize`, `hqcN_client_mlkem_encap`,
//! `hqcN_client_decap`, `hqcN_full_transaction`.

#[path = "../profiling/workload.rs"]
mod workload;

use HQCLethe::auth::shared_keypair;
use HQCLethe::client::Client;
use HQCLethe::encoding::{Kind, MAX_UDP_PAYLOAD};
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::server::Server;
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

fn make_server<SCHEME: HqcScheme>() -> Server<SCHEME, NullSessionStore, Entropy> {
    Server::new(
        NullSessionStore,
        Entropy,
        shared_keypair::<SCHEME>().secret.clone(),
    )
}

/// Runs a real client through the handshake and returns the handshake
/// request plus the first u-chunk request and the first v-residue request. The
/// cookie must be a genuine ciphertext the server can open, so these cannot
/// be made without going through the actual protocol.
fn setup<SCHEME: HqcScheme>(
    server: &Server<SCHEME, NullSessionStore, Entropy>,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let client = Client::<SCHEME, _, _, _>::new(NullSessionStore, Entropy);
    let (client, handshake_request) = client.initialize(&shared_keypair::<SCHEME>().public);
    let mut out = [0u8; MAX_UDP_PAYLOAD];
    let len = server
        .handle_packet(PEER, &handshake_request, &mut out)
        .unwrap();
    let client = client.handle_handshake_response(&out[..len]).unwrap();
    let first_of = |kind| {
        client
            .requests()
            .iter()
            .find(|r| r.kind == kind)
            .unwrap()
            .bytes
            .clone()
    };
    (
        handshake_request,
        first_of(Kind::UChunk),
        first_of(Kind::VResidue),
    )
}

fn bench_variant<SCHEME: HqcScheme>(c: &mut Criterion, name: &str) {
    let server = make_server::<SCHEME>();
    let (handshake_request, uchunk_request, vresidue_request) = setup::<SCHEME>(&server);
    let mut out = [0u8; MAX_UDP_PAYLOAD];

    c.bench_function(&format!("{name}_server_handshake"), |b| {
        b.iter(|| {
            server
                .handle_handshake(PEER, black_box(&handshake_request), &mut out)
                .unwrap()
        })
    });
    c.bench_function(&format!("{name}_server_uchunk_request"), |b| {
        b.iter(|| {
            server
                .handle_uchunk(black_box(&uchunk_request), &mut out)
                .unwrap()
        })
    });
    c.bench_function(&format!("{name}_server_vresidue_request"), |b| {
        b.iter(|| {
            server
                .handle_vresidue(black_box(&vresidue_request), &mut out)
                .unwrap()
        })
    });

    let keys = shared_keypair::<SCHEME>();
    let (auth_ct, _) = keys.public.encapsulate();
    c.bench_function(&format!("{name}_server_mlkem_decap"), |b| {
        b.iter(|| keys.secret.decapsulate(black_box(&auth_ct)).unwrap())
    });
    c.bench_function(&format!("{name}_client_mlkem_encap"), |b| {
        b.iter(|| keys.public.encapsulate())
    });

    let mut pk = vec![0u8; SCHEME::PUBLIC_KEY_BYTES];
    let mut sk = vec![0u8; SCHEME::SECRET_KEY_BYTES];
    let mut entropy = [0u8; 48];
    c.bench_function(&format!("{name}_client_keygen"), |b| {
        b.iter(|| {
            Entropy.random_bytes(&mut entropy);
            unsafe { SCHEME::keypair(&entropy, &mut pk, &mut sk) }
        })
    });
    c.bench_function(&format!("{name}_client_initialize"), |b| {
        b.iter(|| {
            Client::<SCHEME, _, _, _>::new(NullSessionStore, Entropy).initialize(&keys.public)
        })
    });

    let mut ct = vec![0u8; SCHEME::CIPHERTEXT_BYTES];
    let mut ss = vec![0u8; SCHEME::SHARED_SECRET_BYTES];
    unsafe { SCHEME::enc(&entropy, &mut ct, &mut ss, &pk) };
    c.bench_function(&format!("{name}_client_decap"), |b| {
        b.iter(|| SCHEME::dec(&mut ss, black_box(&ct), &sk))
    });

    c.bench_function(&format!("{name}_full_transaction"), |b| {
        b.iter(workload::run_round_trip::<SCHEME>)
    });
}

fn bench_hqc1(c: &mut Criterion) {
    bench_variant::<Hqc1>(c, "hqc1");
}
fn bench_hqc3(c: &mut Criterion) {
    bench_variant::<Hqc3>(c, "hqc3");
}
fn bench_hqc5(c: &mut Criterion) {
    bench_variant::<Hqc5>(c, "hqc5");
}

criterion_group!(benches, bench_hqc1, bench_hqc3, bench_hqc5);
criterion_main!(benches);
