//! Server cost of the Phase-1 replay filter.
//!
//! Names: `hqcN_replay_fingerprint`,
//! `hqcN_replay_admit_fresh`, `hqcN_replay_admit_duplicate`,
//! `hqcN_replay_admit_exhausted`, `hqcN_replay_step_accepted`
//! (fingerprint and fresh admission together),
//! `hqcN_replay_step_dropped` (the same for a replay beyond the budget),
//! `hqcN_{uchunk,vresidue}_{nofilter,filter}_accepted` (end to end, distinct
//! requests), `hqcN_{uchunk,vresidue}_replay_dropped` (end to end),
//! `hqcN_uchunk_expired_dropped` (end to end, cookie key retired).

use HQCLethe::auth::shared_keypair;
use HQCLethe::client::Client;
use HQCLethe::encoding::{Kind, MAX_UDP_PAYLOAD};
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::replay::{DEFAULT_DUPLICATES, Fingerprint, ReplayConfig, ReplayFilter};
use HQCLethe::server::Server;
use HQCLethe::traits::*;
use criterion::{Criterion, criterion_group, criterion_main};
use rand::{Rng, RngExt};
use std::hint::black_box;
use std::time::{Duration, Instant};

const PEER: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
const ROTATION: u32 = 0;
const SESSIONS_FOR_DISTINCT_REQUESTS: usize = 5;
const CHUNK: usize = 1000;
const FILL_FRACTION_DIVISOR: u64 = 2;
const COOKIE_NONCE: [u8; 24] = [0x42; 24];

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

fn random_fingerprint() -> Fingerprint {
    let mut rng = rand::rng();
    Fingerprint {
        probe_base: rng.random(),
        probe_step: rng.random::<u64>() | 1,
        counter_hash: rng.random(),
    }
}

fn half_full_filter<S: HqcScheme>() -> ReplayFilter {
    let config = ReplayConfig::for_scheme::<S>();
    let mut filter = ReplayFilter::new(config.sizing().unwrap(), [9; 32]);
    for _ in 0..config.expected_insertions() / FILL_FRACTION_DIVISOR {
        filter.admit(&random_fingerprint(), ROTATION);
    }
    filter
}

fn bench_filter<S: HqcScheme>(c: &mut Criterion, name: &str) {
    let filter = half_full_filter::<S>();
    c.bench_function(&format!("{name}_replay_fingerprint"), |b| {
        b.iter(|| filter.fingerprint(black_box(&COOKIE_NONCE), black_box(1), black_box(1)))
    });

    let fresh_chunk: Vec<Fingerprint> = (0..CHUNK).map(|_| random_fingerprint()).collect();
    c.bench_function(&format!("{name}_replay_admit_fresh"), |b| {
        b.iter_custom(|iterations| {
            let mut spent = Duration::ZERO;
            let mut done = 0u64;
            while done < iterations {
                let mut filter = half_full_filter::<S>();
                let started = Instant::now();
                for fingerprint in &fresh_chunk {
                    black_box(filter.admit(black_box(fingerprint), ROTATION));
                }
                spent += started.elapsed();
                done += CHUNK as u64;
            }
            spent.mul_f64(iterations as f64 / done as f64)
        })
    });

    c.bench_function(&format!("{name}_replay_admit_duplicate"), |b| {
        b.iter_custom(|iterations| {
            let mut spent = Duration::ZERO;
            let mut done = 0u64;
            while done < iterations {
                let mut filter = half_full_filter::<S>();
                for fingerprint in &fresh_chunk {
                    filter.admit(fingerprint, ROTATION);
                }
                let started = Instant::now();
                for fingerprint in &fresh_chunk {
                    black_box(filter.admit(black_box(fingerprint), ROTATION));
                }
                spent += started.elapsed();
                done += CHUNK as u64;
            }
            spent.mul_f64(iterations as f64 / done as f64)
        })
    });

    let mut exhausted_filter = half_full_filter::<S>();
    let replayed = random_fingerprint();
    for _ in 0..=DEFAULT_DUPLICATES {
        exhausted_filter.admit(&replayed, ROTATION);
    }
    c.bench_function(&format!("{name}_replay_admit_exhausted"), |b| {
        b.iter(|| exhausted_filter.admit(black_box(&replayed), ROTATION))
    });

    c.bench_function(&format!("{name}_replay_step_accepted"), |b| {
        b.iter_custom(|iterations| {
            let mut spent = Duration::ZERO;
            let mut done = 0u64;
            while done < iterations {
                let mut filter = half_full_filter::<S>();
                let started = Instant::now();
                for sequence in 0..CHUNK as u32 {
                    let mut cookie_nonce = COOKIE_NONCE;
                    cookie_nonce[..4].copy_from_slice(&sequence.to_le_bytes());
                    let fingerprint = filter.fingerprint(black_box(&cookie_nonce), 1, 1);
                    black_box(filter.admit(&fingerprint, ROTATION));
                }
                spent += started.elapsed();
                done += CHUNK as u64;
            }
            spent.mul_f64(iterations as f64 / done as f64)
        })
    });

    c.bench_function(&format!("{name}_replay_step_dropped"), |b| {
        let mut filter = half_full_filter::<S>();
        let fingerprint = filter.fingerprint(&COOKIE_NONCE, 1, 1);
        for _ in 0..=DEFAULT_DUPLICATES {
            filter.admit(&fingerprint, ROTATION);
        }
        b.iter(|| {
            let fingerprint = filter.fingerprint(black_box(&COOKIE_NONCE), 1, 1);
            black_box(filter.admit(&fingerprint, ROTATION))
        })
    });
}

type BenchServer<S> = Server<S, NullSessionStore, Entropy>;

struct Session<S: HqcScheme> {
    filtered: BenchServer<S>,
    unfiltered: BenchServer<S>,
    uchunk: Vec<Vec<u8>>,
    vresidue: Vec<Vec<u8>>,
}

fn distinct_requests<S: HqcScheme>() -> Session<S> {
    let keys = shared_keypair::<S>();
    let sizing = ReplayConfig::for_scheme::<S>().sizing().unwrap();
    let unfiltered: BenchServer<S> = Server::new(NullSessionStore, Entropy, keys.secret.clone());
    let filtered = unfiltered.clone().with_replay_filter(sizing);

    let mut uchunk = Vec::new();
    let mut vresidue = Vec::new();
    let mut out = [0u8; MAX_UDP_PAYLOAD];
    for _ in 0..SESSIONS_FOR_DISTINCT_REQUESTS {
        let (client, request) =
            Client::<S, _, _, _>::new(NullSessionStore, Entropy).initialize(&keys.public);
        let len = unfiltered.handle_packet(PEER, &request, &mut out).unwrap();
        let client = client.handle_handshake_response(&out[..len]).unwrap();
        for request in client.requests() {
            match request.kind {
                Kind::UChunk => uchunk.push(request.bytes.clone()),
                _ => vresidue.push(request.bytes.clone()),
            }
        }
    }
    Session {
        filtered,
        unfiltered,
        uchunk,
        vresidue,
    }
}

fn time_distinct<S: HqcScheme>(
    server: &BenchServer<S>,
    requests: &[Vec<u8>],
    iterations: u64,
) -> Duration {
    let mut out = [0u8; MAX_UDP_PAYLOAD];
    let mut spent = Duration::ZERO;
    let mut done = 0u64;
    while done < iterations {
        let round = server.clone();
        let started = Instant::now();
        for request in requests {
            black_box(
                round
                    .handle_packet(PEER, black_box(request), &mut out)
                    .unwrap(),
            );
        }
        spent += started.elapsed();
        done += requests.len() as u64;
    }
    spent.mul_f64(iterations as f64 / done as f64)
}

fn bench_server<S: HqcScheme>(c: &mut Criterion, name: &str) {
    let session = distinct_requests::<S>();
    let mut out = [0u8; MAX_UDP_PAYLOAD];

    for (kind_name, requests) in [("uchunk", &session.uchunk), ("vresidue", &session.vresidue)] {
        c.bench_function(&format!("{name}_{kind_name}_nofilter_accepted"), |b| {
            b.iter_custom(|iterations| time_distinct(&session.unfiltered, requests, iterations))
        });
        c.bench_function(&format!("{name}_{kind_name}_filter_accepted"), |b| {
            b.iter_custom(|iterations| time_distinct(&session.filtered, requests, iterations))
        });

        let replayed = &requests[requests.len() / 2];
        for _ in 0..=DEFAULT_DUPLICATES {
            session
                .filtered
                .handle_packet(PEER, replayed, &mut out)
                .unwrap();
        }
        c.bench_function(&format!("{name}_{kind_name}_replay_dropped"), |b| {
            b.iter(|| {
                session
                    .filtered
                    .handle_packet(PEER, black_box(replayed), &mut out)
                    .unwrap_err()
            })
        });
    }

    let expired = session.uchunk[0].clone();
    session.filtered.rotate();
    session.filtered.rotate();
    c.bench_function(&format!("{name}_uchunk_expired_dropped"), |b| {
        b.iter(|| {
            session
                .filtered
                .handle_packet(PEER, black_box(&expired), &mut out)
                .unwrap_err()
        })
    });
}

fn replay_benches(c: &mut Criterion) {
    bench_filter::<Hqc1>(c, "hqc1");
    bench_filter::<Hqc3>(c, "hqc3");
    bench_filter::<Hqc5>(c, "hqc5");
    bench_server::<Hqc1>(c, "hqc1");
    bench_server::<Hqc3>(c, "hqc3");
    bench_server::<Hqc5>(c, "hqc5");
}

criterion_group!(benches, replay_benches);
criterion_main!(benches);
