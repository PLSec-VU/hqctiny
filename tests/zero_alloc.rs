//! The server must not touch the heap while it answers packets, once the
//! one-time set-up of the first request is done.

use HQCLethe::auth::shared_keypair;
use HQCLethe::client::Client;
use HQCLethe::encoding::{Kind, MAX_UDP_PAYLOAD};
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::server::Server;
mod test_utils;
use HQCLethe::replay::ReplayConfig;
use HQCLethe::traits::SessionStore;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use test_utils::{MockEntropy, SharedSessionStore};

const PEER: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

struct DiscardingStore;
impl SessionStore for DiscardingStore {
    fn save_session(&self, _k_session: [u8; 32]) {}
}

struct CountingAllocator;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

fn record() {
    if COUNTING.load(Ordering::Relaxed) {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record();
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record();
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn allocations_during<F: FnOnce()>(work: F) -> usize {
    ALLOCATIONS.store(0, Ordering::SeqCst);
    COUNTING.store(true, Ordering::SeqCst);
    work();
    COUNTING.store(false, Ordering::SeqCst);
    ALLOCATIONS.load(Ordering::SeqCst)
}

fn server_allocations<S: HqcScheme>() -> Vec<(Kind, usize)> {
    let keys = shared_keypair::<S>();
    let server = Server::<S, _, _>::new(DiscardingStore, MockEntropy, keys.secret.clone());
    let client = Client::<S, _, _, _>::new(SharedSessionStore::new(), MockEntropy);
    allocations_for_kinds(&server, client, &[Kind::UChunk, Kind::VResidue])
}

fn allocations_for_kinds<S: HqcScheme>(
    server: &Server<S, DiscardingStore, MockEntropy>,
    client: Client<S, SharedSessionStore, MockEntropy, HQCLethe::client::Initial>,
    kinds: &[Kind],
) -> Vec<(Kind, usize)> {
    let keys = shared_keypair::<S>();
    let (client, handshake_request) = client.initialize(&keys.public);
    let mut out = [0u8; MAX_UDP_PAYLOAD];
    let len = server
        .handle_packet(PEER, &handshake_request, &mut out)
        .unwrap();
    let client = client.handle_handshake_response(&out[..len]).unwrap();

    let mut requests: Vec<(Kind, Vec<u8>)> = vec![(Kind::Handshake, handshake_request)];
    for &kind in kinds {
        let request = client.requests().iter().find(|r| r.kind == kind).unwrap();
        requests.push((kind, request.bytes.clone()));
    }

    for (_, request) in &requests {
        server.handle_packet(PEER, request, &mut out).unwrap();
    }
    requests
        .iter()
        .map(|(kind, request)| {
            let count = allocations_during(|| {
                for _ in 0..3 {
                    server.handle_packet(PEER, request, &mut out).unwrap();
                }
            });
            (*kind, count)
        })
        .collect()
}

#[test]
fn test_server_makes_no_heap_allocation_after_warm_up() {
    assert_session_paths_allocate_nothing();
    assert_puzzle_paths_allocate_nothing();
    assert_replay_paths_allocate_nothing();
}

fn assert_session_paths_allocate_nothing() {
    for (level, counts) in [
        ("HQC-1", server_allocations::<Hqc1>()),
        ("HQC-3", server_allocations::<Hqc3>()),
        ("HQC-5", server_allocations::<Hqc5>()),
    ] {
        for (kind, count) in counts {
            assert_eq!(count, 0, "{level} {kind:?} allocated {count} times");
        }
    }
}

const PUZZLE_TEST_DIFFICULTY: u8 = 6;

fn puzzle_server_allocations<S: HqcScheme>() -> Vec<(&'static str, usize)> {
    let keys = shared_keypair::<S>();
    let server = Server::<S, _, _>::new(DiscardingStore, MockEntropy, keys.secret.clone())
        .with_puzzle_difficulty(PUZZLE_TEST_DIFFICULTY);
    let client = Client::<S, _, _, _>::new(SharedSessionStore::new(), MockEntropy);
    let (client, plain) = client.initialize(&keys.public);
    let mut out = [0u8; MAX_UDP_PAYLOAD];
    let len = server.handle_packet(PEER, &plain, &mut out).unwrap();
    let solved = client
        .solve_challenge(&out[..len], PUZZLE_TEST_DIFFICULTY)
        .unwrap();
    let mut forged = solved.clone();
    let mac_byte = forged.len() - 1 - 8 - 1;
    forged[mac_byte] ^= 1;

    server.handle_packet(PEER, &solved, &mut out).unwrap();
    let measure = |label, request: &[u8], serving: &Server<S, DiscardingStore, MockEntropy>| {
        let mut out = [0u8; MAX_UDP_PAYLOAD];
        let count = allocations_during(|| {
            for _ in 0..3 {
                let _ = serving.handle_packet(PEER, request, &mut out);
            }
        });
        (label, count)
    };
    vec![
        measure("challenge", &plain, &server),
        measure("solved", &solved, &server),
        measure("forged", &forged, &server),
    ]
}

fn assert_puzzle_paths_allocate_nothing() {
    for (level, counts) in [
        ("HQC-1", puzzle_server_allocations::<Hqc1>()),
        ("HQC-3", puzzle_server_allocations::<Hqc3>()),
        ("HQC-5", puzzle_server_allocations::<Hqc5>()),
    ] {
        for (path, count) in counts {
            assert_eq!(count, 0, "{level} {path} allocated {count} times");
        }
    }
}

const REPLAY_TEST_RATE: u32 = 100_000;
const REPLAYS_PER_PATH: usize = 10;

fn replay_server_allocations<S: HqcScheme>() -> Vec<(Kind, &'static str, usize)> {
    let keys = shared_keypair::<S>();
    let config = ReplayConfig {
        max_rate: REPLAY_TEST_RATE,
        ..ReplayConfig::for_scheme::<S>()
    };
    let server = Server::<S, _, _>::new(DiscardingStore, MockEntropy, keys.secret.clone())
        .with_replay_filter(config.sizing().unwrap());
    let client = Client::<S, _, _, _>::new(SharedSessionStore::new(), MockEntropy);
    let (client, handshake_request) = client.initialize(&keys.public);
    let mut out = [0u8; MAX_UDP_PAYLOAD];
    let len = server
        .handle_packet(PEER, &handshake_request, &mut out)
        .unwrap();
    let client = client.handle_handshake_response(&out[..len]).unwrap();

    let mut counts = Vec::new();
    for kind in [Kind::UChunk, Kind::VResidue] {
        let request = client.requests().iter().find(|r| r.kind == kind).unwrap();
        let accepted = allocations_during(|| {
            server
                .handle_packet(PEER, &request.bytes, &mut out)
                .unwrap();
        });
        counts.push((kind, "accepted", accepted));
        let duplicates = allocations_during(|| {
            for _ in 0..3 {
                server
                    .handle_packet(PEER, &request.bytes, &mut out)
                    .unwrap();
            }
        });
        counts.push((kind, "duplicate", duplicates));
        let dropped = allocations_during(|| {
            for _ in 0..REPLAYS_PER_PATH {
                assert!(
                    server
                        .handle_packet(PEER, &request.bytes, &mut out)
                        .is_err()
                );
            }
        });
        counts.push((kind, "dropped", dropped));
    }
    server.rotate();
    let one_rotation = allocations_during(|| {
        let _ = server.handle_packet(PEER, &client.requests()[0].bytes, &mut out);
    });
    server.rotate();
    server.rotate();
    let two_rotations = allocations_during(|| {
        let _ = server.handle_packet(PEER, &client.requests()[0].bytes, &mut out);
    });
    counts.push((Kind::UChunk, "rotation", one_rotation + two_rotations));
    counts
}

fn assert_replay_paths_allocate_nothing() {
    for (level, counts) in [
        ("HQC-1", replay_server_allocations::<Hqc1>()),
        ("HQC-3", replay_server_allocations::<Hqc3>()),
        ("HQC-5", replay_server_allocations::<Hqc5>()),
    ] {
        for (kind, path, count) in counts {
            assert_eq!(count, 0, "{level} {kind:?} {path} allocated {count} times");
        }
    }
}
