//! Microbenchmarks for HQCTiny's actual per-packet protocol-layer work
//! (handshake, and the segmented per-point evaluation that stands in for
//! monolithic HQC encryption — see hqc/README's Phase 2), plus a
//! macrobenchmark for a complete client+server transaction.

#[path = "../profiling/workload.rs"]
mod workload;

use HQCTiny::client::Client;
use HQCTiny::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCTiny::protocol::{HandshakeRequest, PointRequest, PointType};
use HQCTiny::server::Server;
use HQCTiny::traits::*;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
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

fn make_server<SCHEME: HqcScheme>() -> Server<SCHEME, NullSessionStore, Entropy> {
    Server::new(NullSessionStore, Entropy)
}

/// Runs a real client through the handshake and returns the request plus
/// one U-type and one V-type PointRequest (point_index = 1) — the cookie
/// must be a genuine AEAD ciphertext the server can decrypt, so these can't
/// be synthesized without going through the actual protocol.
fn setup<SCHEME: HqcScheme>(
    server: &Server<SCHEME, NullSessionStore, Entropy>,
) -> (HandshakeRequest, PointRequest, PointRequest) {
    let client = Client::<SCHEME, _, _, _>::new(NullSessionStore, Entropy);
    let (client, req) = client.initialize();
    let handshake_req = req.clone();
    let res = server.handle_handshake(req).unwrap();
    let (_client, point_reqs) = client.handle_handshake_response(res).unwrap();

    let u_req = *point_reqs
        .iter()
        .find(|r| r.point_index == 1 && r.point_type == PointType::U)
        .unwrap();
    let v_req = *point_reqs
        .iter()
        .find(|r| r.point_index == 1 && r.point_type == PointType::V)
        .unwrap();

    (handshake_req, u_req, v_req)
}

fn bench_variant<SCHEME: HqcScheme>(c: &mut Criterion, name: &str) {
    let server = make_server::<SCHEME>();
    let (handshake_req, u_req, v_req) = setup::<SCHEME>(&server);

    c.bench_function(&format!("{name}_server_handshake"), |b| {
        b.iter_batched(
            || handshake_req.clone(),
            |req| server.handle_handshake(req).unwrap(),
            BatchSize::SmallInput,
        )
    });

    c.bench_function(&format!("{name}_server_point_request_u"), |b| {
        b.iter_batched(
            || u_req,
            |req| server.handle_point_request(req).unwrap(),
            BatchSize::SmallInput,
        )
    });

    c.bench_function(&format!("{name}_server_point_request_v"), |b| {
        b.iter_batched(
            || v_req,
            |req| server.handle_point_request(req).unwrap(),
            BatchSize::SmallInput,
        )
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

fn bench_macro_roundtrip(c: &mut Criterion) {
    c.bench_function("hqc1_full_transaction", |b| {
        b.iter(workload::run_round_trip::<Hqc1>)
    });
    c.bench_function("hqc3_full_transaction", |b| {
        b.iter(workload::run_round_trip::<Hqc3>)
    });
    c.bench_function("hqc5_full_transaction", |b| {
        b.iter(workload::run_round_trip::<Hqc5>)
    });
}

criterion_group!(
    benches,
    bench_hqc1,
    bench_hqc3,
    bench_hqc5,
    bench_macro_roundtrip
);
criterion_main!(benches);
