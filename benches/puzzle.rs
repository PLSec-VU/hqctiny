//! Server cost of the Phase-0 client puzzle, next to the ML-KEM
//! decapsulation it protects, and the client cost of solving it.
//!
//! Names: `hqcN_puzzle_issue_challenge`, `hqcN_puzzle_reject_bad_mac`,
//! `hqcN_puzzle_reject_stale`, `hqcN_puzzle_reject_wrong_solution`,
//! `hqcN_puzzle_verify_only`, `hqcN_puzzle_accept_valid_solution`,
//! `hqcN_puzzle_off_handshake`, `hqcN_puzzle_mlkem_decap`,
//! `hqcN_puzzle_client_solve_dD`, `hqcN_puzzle_session_dD`.

use HQCLethe::auth::shared_keypair;
use HQCLethe::client::{AwaitingHandshake, Client, Initial};
use HQCLethe::encoding::{self, HEADER_BYTES, MAX_UDP_PAYLOAD};
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::limits::PUZZLE_MAX_AGE_SECS;
use HQCLethe::puzzle::{self, CHALLENGE_BYTES};
use HQCLethe::server::Server;
use HQCLethe::session::run_in_process;
use HQCLethe::traits::*;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use rand::Rng;
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

const PEER: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

const BENCH_DIFFICULTY: u8 = 16;
const SOLVE_DIFFICULTIES: [u8; 4] = [8, 12, 16, 20];
const SESSION_DIFFICULTIES: [u8; 2] = [0, 16];
const FIRST_SECOND: u32 = 1_800_000_000;
const MAX_CLIENT_DIFFICULTY: u8 = 32;
const LONG_SOLVE_DIFFICULTY: u8 = 20;
const LONG_SOLVE_SAMPLES: usize = 30;

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

struct SettableClock(AtomicU32);
impl Clock for SettableClock {
    fn unix_seconds(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }
}

type BenchServer<S> = Server<S, NullSessionStore, Entropy>;

fn server_at<S: HqcScheme>(difficulty: u8, clock: &Arc<SettableClock>) -> BenchServer<S> {
    Server::new(
        NullSessionStore,
        Entropy,
        shared_keypair::<S>().secret.clone(),
    )
    .with_puzzle_difficulty(difficulty)
    .with_clock(clock.clone())
}

fn new_client<S: HqcScheme>() -> Client<S, NullSessionStore, Entropy, Initial> {
    Client::new(NullSessionStore, Entropy)
}

fn awaiting<S: HqcScheme>() -> (
    Client<S, NullSessionStore, Entropy, AwaitingHandshake>,
    Vec<u8>,
) {
    new_client::<S>().initialize(&shared_keypair::<S>().public)
}

fn body_digest<S: HqcScheme>(plain: &[u8]) -> [u8; 32] {
    HQCLethe::kdf::request_digest(
        &plain[HEADER_BYTES..HEADER_BYTES + encoding::handshake_request_body_len::<S>()],
    )
}

fn bench_server<S: HqcScheme>(c: &mut Criterion, name: &str) {
    let clock = Arc::new(SettableClock(AtomicU32::new(FIRST_SECOND)));
    let server = server_at::<S>(BENCH_DIFFICULTY, &clock);
    let (client, plain) = awaiting::<S>();
    let mut out = [0u8; MAX_UDP_PAYLOAD];
    let challenge_len = server.handle_packet(PEER, &plain, &mut out).unwrap();
    let challenge_packet = out[..challenge_len].to_vec();
    let solved = client
        .solve_challenge(&challenge_packet, MAX_CLIENT_DIFFICULTY)
        .unwrap();

    c.bench_function(&format!("{name}_puzzle_issue_challenge"), |b| {
        b.iter(|| {
            server
                .handle_packet(PEER, black_box(&plain), &mut out)
                .unwrap()
        })
    });

    let mac_byte = HEADER_BYTES + encoding::handshake_request_body_len::<S>() + CHALLENGE_BYTES - 1;
    let mut bad_mac = solved.clone();
    bad_mac[mac_byte] ^= 1;
    c.bench_function(&format!("{name}_puzzle_reject_bad_mac"), |b| {
        b.iter(|| {
            server
                .handle_packet(PEER, black_box(&bad_mac), &mut out)
                .unwrap_err()
        })
    });

    let stale_clock = Arc::new(SettableClock(AtomicU32::new(
        FIRST_SECOND + PUZZLE_MAX_AGE_SECS + 1,
    )));
    let stale_server = server_at::<S>(BENCH_DIFFICULTY, &stale_clock);
    c.bench_function(&format!("{name}_puzzle_reject_stale"), |b| {
        b.iter(|| {
            stale_server
                .handle_packet(PEER, black_box(&solved), &mut out)
                .unwrap_err()
        })
    });

    let (_, challenge, peer) = encoding::parse_challenge_response(&challenge_packet).unwrap();
    let digest = body_digest::<S>(&plain);
    let wrong_counter = (0u64..)
        .find(|counter| !puzzle::is_solution(&challenge, &peer, &digest, *counter))
        .unwrap();
    let mut wrong_solution = vec![0u8; solved.len()];
    encoding::write_solved_handshake_request::<S>(
        &mut wrong_solution,
        &plain,
        0,
        &challenge,
        wrong_counter,
    )
    .unwrap();
    c.bench_function(&format!("{name}_puzzle_reject_wrong_solution"), |b| {
        b.iter(|| {
            server
                .handle_packet(PEER, black_box(&wrong_solution), &mut out)
                .unwrap_err()
        })
    });

    let mac_key = puzzle::mac_key(&[7u8; 32]);
    let issued =
        puzzle::Challenge::issue(&mac_key, &peer, [1u8; 16], BENCH_DIFFICULTY, FIRST_SECOND);
    let solving_counter = puzzle::solve(&issued, &peer, &digest);
    c.bench_function(&format!("{name}_puzzle_verify_only"), |b| {
        b.iter(|| {
            let key = puzzle::mac_key(black_box(&[7u8; 32]));
            let digest = body_digest::<S>(black_box(&plain));
            issued.is_authentic(&key, &peer)
                && puzzle::is_solution(&issued, &peer, &digest, solving_counter)
        })
    });

    c.bench_function(&format!("{name}_puzzle_accept_valid_solution"), |b| {
        b.iter(|| {
            server
                .handle_packet(PEER, black_box(&solved), &mut out)
                .unwrap()
        })
    });

    let plain_server = server_at::<S>(0, &clock);
    c.bench_function(&format!("{name}_puzzle_off_handshake"), |b| {
        b.iter(|| {
            plain_server
                .handle_packet(PEER, black_box(&plain), &mut out)
                .unwrap()
        })
    });

    let keys = shared_keypair::<S>();
    let (auth_ct, _) = keys.public.encapsulate();
    c.bench_function(&format!("{name}_puzzle_mlkem_decap"), |b| {
        b.iter(|| keys.secret.decapsulate(black_box(&auth_ct)).unwrap())
    });
}

fn bench_client_solve<S: HqcScheme>(c: &mut Criterion, name: &str) {
    let clock = Arc::new(SettableClock(AtomicU32::new(FIRST_SECOND)));
    for difficulty in SOLVE_DIFFICULTIES {
        let server = server_at::<S>(difficulty, &clock);
        let (client, plain) = awaiting::<S>();
        let mut out = [0u8; MAX_UDP_PAYLOAD];
        let mut group = c.benchmark_group(format!("{name}_puzzle_client_solve"));
        if difficulty >= LONG_SOLVE_DIFFICULTY {
            group.sample_size(LONG_SOLVE_SAMPLES);
        }
        group.bench_function(format!("d{difficulty}"), |b| {
            b.iter_batched(
                || {
                    let len = server.handle_packet(PEER, &plain, &mut out).unwrap();
                    out[..len].to_vec()
                },
                |challenge| {
                    client
                        .solve_challenge(black_box(&challenge), MAX_CLIENT_DIFFICULTY)
                        .unwrap()
                },
                BatchSize::SmallInput,
            )
        });
        group.finish();
    }
}

fn bench_sessions<S: HqcScheme>(c: &mut Criterion, name: &str) {
    let clock = Arc::new(SettableClock(AtomicU32::new(FIRST_SECOND)));
    let keys = shared_keypair::<S>();
    for difficulty in SESSION_DIFFICULTIES {
        let server = server_at::<S>(difficulty, &clock);
        c.bench_function(&format!("{name}_puzzle_session_d{difficulty}"), |b| {
            b.iter(|| run_in_process(&server, new_client::<S>(), &keys.public).unwrap())
        });
    }
}

fn bench_level<S: HqcScheme>(c: &mut Criterion, name: &str) {
    bench_server::<S>(c, name);
    bench_client_solve::<S>(c, name);
    bench_sessions::<S>(c, name);
}

fn bench_hqc1(c: &mut Criterion) {
    bench_level::<Hqc1>(c, "hqc1");
}
fn bench_hqc3(c: &mut Criterion) {
    bench_level::<Hqc3>(c, "hqc3");
}
fn bench_hqc5(c: &mut Criterion) {
    bench_level::<Hqc5>(c, "hqc5");
}

criterion_group!(benches, bench_hqc1, bench_hqc3, bench_hqc5);
criterion_main!(benches);
