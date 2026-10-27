use HQCLethe::auth::{ServerKeypair, ServerPublicKey, shared_keypair};
use HQCLethe::client::{Client, DEFAULT_MAX_PUZZLE_DIFFICULTY, HandshakeReply, Progress};
use HQCLethe::encoding::{self, Kind, MAX_UDP_PAYLOAD};
use HQCLethe::error::Error as ProtocolError;
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::limits::COOKIE_ROTATION_SECS;
use HQCLethe::replay::DEFAULT_DUPLICATES;
use HQCLethe::server::Server;
use HQCLethe::session::run_in_process;
use HQCLethe::traits::*;
use clap::{Parser, Subcommand, ValueEnum};
use rand::RngCore;
use serde_json::json;
use std::cell::{Cell, RefCell};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

// --- Retry tuning (UDP packet-loss recovery, see run_client) ---
// The base retransmission timeout is seeded from the measured handshake
// RTT (clamped into [RTO_MIN, RTO_MAX]); each stall doubles it up to
// RTO_MAX, and we give up after MAX_RETRIES consecutive stalls in a phase.
const RTO_MIN: Duration = Duration::from_millis(100);
const RTO_MAX: Duration = Duration::from_secs(2);
/// Base RTO used for the handshake, before any RTT sample exists.
const RTO_FALLBACK: Duration = Duration::from_millis(500);
/// Point-phase base RTO = this multiple of the measured handshake RTT.
const RTT_RTO_MULTIPLIER: u32 = 3;
const RTO_BACKOFF: u32 = 2;
const MAX_RETRIES: u32 = 6;
/// A challenge cannot be authenticated by the client, so a forged one must not
/// be able to make it solve puzzles without end.
const MAX_PUZZLES_PER_HANDSHAKE: u32 = 3;
const DEFAULT_FLOOD_COOKIE_REFRESH_SECS: u64 = (COOKIE_ROTATION_SECS / 2) as u64;

#[derive(Clone)]
struct OsEntropy;
impl EntropyProvider for OsEntropy {
    fn random_bytes(&self, out: &mut [u8]) {
        rand::rng().fill_bytes(out);
    }
}

#[derive(Clone)]
struct InMemorySessionStore {
    sessions: Arc<Mutex<Vec<[u8; 32]>>>,
}

impl InMemorySessionStore {
    fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl SessionStore for InMemorySessionStore {
    fn save_session(&self, k_session: [u8; 32]) {
        self.sessions.lock().unwrap().push(k_session);
    }
}

#[cfg(not(feature = "quiet"))]
fn print_shared_secret(key: &[u8]) {
    use std::fmt::Write;
    let mut hex = String::with_capacity(key.len() * 2);
    for b in key {
        let _ = write!(hex, "{b:02x}");
    }
    println!("session key: {hex}");
}

#[cfg(feature = "quiet")]
fn print_shared_secret(_key: &[u8]) {}

const ANY_LOCAL_IP: &str = "0.0.0.0";

fn client_bind_address(bind_ip: Ipv4Addr) -> SocketAddr {
    SocketAddr::from((bind_ip, 0))
}

async fn run_client<SCHEME: HqcScheme>(
    server_addr: &str,
    bind_ip: Ipv4Addr,
    server_pk: &ServerPublicKey<SCHEME>,
    max_puzzle_difficulty: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(client_bind_address(bind_ip)).await?;
    socket.connect(server_addr).await?;

    // Phase timestamps for RTT accounting under emulated/real WAN links
    // (see eval/scripts/wan_latency.py): t0/t1 bound the handshake RTT,
    // t2/t3 bound the point-request RTT. Printed to stderr so stdout stays
    // reserved for the shared-secret result.
    let t_start = Instant::now();
    let phase = |name: &str| eprintln!("[phase] {name} t={}", t_start.elapsed().as_secs_f64());

    let store = InMemorySessionStore::new();
    let client = Client::<SCHEME, _, _, _>::new(store, OsEntropy);

    let (client, handshake_request) = client.initialize(server_pk);
    let mut recv_buf = [0u8; 4096];

    // --- Handshake phase, with retransmit on loss ---
    // A lost request or a lost response both surface here as a recv timeout.
    // The request is idempotent (the server is stateless and simply issues a
    // fresh cookie), so the same bytes go out again. A packet that does not
    // authenticate is ignored and does not count as a stall.
    let mut rto = RTO_FALLBACK;
    let mut attempts = 0u32;
    let mut puzzles_solved = 0u32;
    let mut puzzle_refused = false;
    let mut current_request = handshake_request;
    let (reply, rtt_sample) = loop {
        let last_send = Instant::now();
        socket.send(&current_request).await?;
        if attempts == 0 && puzzles_solved == 0 {
            phase("handshake_request_sent");
        }
        let deadline = last_send + rto;
        let event = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, socket.recv(&mut recv_buf)).await {
                Ok(Ok(len)) => {
                    let packet = &recv_buf[..len];
                    if let Ok(reply) = client.verify_handshake_response(packet) {
                        break HandshakeEvent::Replied(reply);
                    }
                    if puzzles_solved < MAX_PUZZLES_PER_HANDSHAKE {
                        match client.solve_challenge(packet, max_puzzle_difficulty) {
                            Ok(solved) => break HandshakeEvent::Challenged(solved),
                            Err(ProtocolError::PuzzleTooHard) => puzzle_refused = true,
                            Err(_) => {}
                        }
                    }
                }
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break HandshakeEvent::TimedOut,
            }
        };
        match event {
            HandshakeEvent::Replied(reply) => {
                phase("handshake_response_received");
                break (reply, last_send.elapsed());
            }
            HandshakeEvent::Challenged(solved) => {
                puzzles_solved += 1;
                phase("puzzle_solved");
                current_request = solved;
            }
            HandshakeEvent::TimedOut => {
                attempts += 1;
                if attempts > MAX_RETRIES {
                    return Err(if puzzle_refused {
                        format!(
                            "handshake timed out: the server asked for a puzzle harder than {max_puzzle_difficulty} bits"
                        )
                        .into()
                    } else {
                        "handshake timed out".into()
                    });
                }
                rto = (rto * RTO_BACKOFF).min(RTO_MAX);
                eprintln!(
                    "[retry] handshake attempt={attempts} rto={:.3}",
                    rto.as_secs_f64()
                );
            }
        }
    };

    let mut client = client.start_collecting(reply)?;

    // Base RTO for the second phase, adapted from the handshake RTT.
    let base_rto = Duration::from_secs_f64(
        (rtt_sample.as_secs_f64() * RTT_RTO_MULTIPLIER as f64)
            .clamp(RTO_MIN.as_secs_f64(), RTO_MAX.as_secs_f64()),
    );

    // --- u-chunk and v-residue phase, with a no-progress timer + resend-outstanding ---
    // Responses may come in any order. On a stall the client sends again only
    // the requests that are still unanswered. Each request is idempotent and
    // yields an equal response, so one lost response never re-floods the server.
    for request in client.requests() {
        socket.send(&request.bytes).await?;
    }
    phase("point_requests_sent");

    let mut rto = base_rto;
    let mut stalls = 0u32;
    loop {
        match tokio::time::timeout(rto, socket.recv(&mut recv_buf)).await {
            Ok(Ok(len)) => match client.handle_response(&recv_buf[..len]) {
                Ok(Progress::Complete(key)) => {
                    phase("session_key_derived");
                    print_shared_secret(&key);
                    return Ok(());
                }
                Ok(Progress::Pending) => {
                    rto = base_rto;
                    stalls = 0;
                }
                Ok(Progress::Duplicate) => {}
                Err(e @ (ProtocolError::KeyConfirmationFailed | ProtocolError::DecodingFailed)) => {
                    return Err(e.into());
                }
                Err(_) => {}
            },
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                stalls += 1;
                if stalls > MAX_RETRIES {
                    return Err("response collection timed out".into());
                }
                let mut outstanding = 0usize;
                for request in client.outstanding_requests() {
                    socket.send(&request.bytes).await?;
                    outstanding += 1;
                }
                rto = (rto * RTO_BACKOFF).min(RTO_MAX);
                eprintln!(
                    "[retry] point outstanding={outstanding} attempt={stalls} rto={:.3}",
                    rto.as_secs_f64()
                );
            }
        }
    }
}

enum HandshakeEvent {
    Replied(HandshakeReply),
    Challenged(Vec<u8>),
    TimedOut,
}

/// Runs one full protocol session in-process (no network) and reports, per
/// packet kind, how many packets of that kind the session needs and how many
/// UDP payload bytes each way. The amplification ratio is the reply size
/// divided by the request size; the protocol keeps it at or below 1. The raw
/// baseline is what a plain KEM handshake would move: the client's public key
/// and the server's ciphertext. See eval/scripts/bandwidth.py.
fn bandwidth_report<SCHEME: HqcScheme>(variant_name: &str) -> serde_json::Value {
    let keys = shared_keypair::<SCHEME>();
    let server =
        Server::<SCHEME, _, _>::new(InMemorySessionStore::new(), OsEntropy, keys.secret.clone());
    let client = Client::<SCHEME, _, _, _>::new(InMemorySessionStore::new(), OsEntropy);
    let outcome = run_in_process(&server, client, &keys.public).unwrap();

    let mut kinds = Vec::new();
    for kind in Kind::SESSION {
        let packets: Vec<_> = outcome.packets.iter().filter(|p| p.kind == kind).collect();
        let request_total: usize = packets.iter().map(|p| p.request_bytes).sum();
        let response_total: usize = packets.iter().map(|p| p.response_bytes).sum();
        let request_max = packets.iter().map(|p| p.request_bytes).max().unwrap_or(0);
        let response_max = packets.iter().map(|p| p.response_bytes).max().unwrap_or(0);
        let worst_ratio = packets
            .iter()
            .map(|p| p.response_bytes as f64 / p.request_bytes as f64)
            .fold(0.0, f64::max);
        kinds.push(json!({
            "kind": kind.name(),
            "count": packets.len(),
            "request_bytes": request_max,
            "response_bytes": response_max,
            "request_bytes_total": request_total,
            "response_bytes_total": response_total,
            "amplification_ratio": worst_ratio,
            "amplification_ratio_total": response_total as f64 / request_total as f64,
        }));
    }

    let total_sent: usize = outcome.packets.iter().map(|p| p.request_bytes).sum();
    let total_received: usize = outcome.packets.iter().map(|p| p.response_bytes).sum();
    let max_packet = outcome
        .packets
        .iter()
        .map(|p| p.request_bytes.max(p.response_bytes))
        .max()
        .unwrap_or(0);
    let raw_baseline = SCHEME::PUBLIC_KEY_BYTES + SCHEME::CIPHERTEXT_BYTES;

    json!({
        "variant": variant_name,
        "packets": kinds,
        "round_trips": outcome.packets.len(),
        "total_sent_bytes": total_sent,
        "total_received_bytes": total_received,
        "total_bytes": total_sent + total_received,
        "raw_baseline_bytes": raw_baseline,
        "overhead_ratio": (total_sent + total_received) as f64 / raw_baseline as f64,
        "mtu_limit_bytes": MAX_UDP_PAYLOAD,
        "max_packet_bytes": max_packet,
        "mtu_ok": max_packet <= MAX_UDP_PAYLOAD,
    })
}

fn print_bandwidth_table(reports: &[serde_json::Value]) {
    println!(
        "{:<6} {:<10} {:>5} {:>9} {:>9} {:>14} {:>14} {:>8}",
        "level", "kind", "count", "req B", "resp B", "req total B", "resp total B", "resp/req"
    );
    for report in reports {
        for packet in report["packets"].as_array().into_iter().flatten() {
            println!(
                "{:<6} {:<10} {:>5} {:>9} {:>9} {:>14} {:>14} {:>8.3}",
                report["variant"].as_str().unwrap_or(""),
                packet["kind"].as_str().unwrap_or(""),
                packet["count"].as_u64().unwrap_or(0),
                packet["request_bytes"].as_u64().unwrap_or(0),
                packet["response_bytes"].as_u64().unwrap_or(0),
                packet["request_bytes_total"].as_u64().unwrap_or(0),
                packet["response_bytes_total"].as_u64().unwrap_or(0),
                packet["amplification_ratio"].as_f64().unwrap_or(0.0),
            );
        }
        println!(
            "{:<6} sent {} B, received {} B, total {} B, raw pk+ct baseline {} B, ratio {:.2}, largest packet {} B (limit {} B)",
            report["variant"].as_str().unwrap_or(""),
            report["total_sent_bytes"],
            report["total_received_bytes"],
            report["total_bytes"],
            report["raw_baseline_bytes"],
            report["overhead_ratio"].as_f64().unwrap_or(0.0),
            report["max_packet_bytes"],
            report["mtu_limit_bytes"],
        );
    }
}

/// Sends `request` until `verify` accepts a reply, backing off like the
/// session client. A flood already running from other processes can drop the
/// request or the reply, so one attempt is not enough.
async fn handshake_with_resends<T>(
    socket: &UdpSocket,
    request: &[u8],
    verify: impl Fn(&[u8]) -> Option<T>,
) -> Result<T, Box<dyn std::error::Error>> {
    let mut recv_buf = [0u8; 4096];
    let mut rto = RTO_FALLBACK;
    for _ in 0..=MAX_RETRIES {
        socket.send(request).await?;
        let deadline = tokio::time::Instant::now() + rto;
        while let Ok(received) = tokio::time::timeout_at(deadline, socket.recv(&mut recv_buf)).await
        {
            if let Some(reply) = verify(&recv_buf[..received?]) {
                return Ok(reply);
            }
        }
        rto = (rto * RTO_BACKOFF).min(RTO_MAX);
    }
    Err("handshake timed out".into())
}

enum Phase0Reply {
    Response(HandshakeReply),
    Challenge(Vec<u8>),
}

/// Performs one real handshake against `server_addr` and returns every
/// valid, server-issued request of `kind` (one per u-chunk/v-residue index).
/// The cookie inside each one is a genuine ciphertext the server can open,
/// so -- unlike the handshake flood payload -- these cannot be made without
/// talking to the server once.
async fn obtain_requests<SCHEME: HqcScheme>(
    socket: &UdpSocket,
    server_pk: &ServerPublicKey<SCHEME>,
    kind: Kind,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let client = Client::<SCHEME, _, _, _>::new(InMemorySessionStore::new(), OsEntropy);
    let (client, request) = client.initialize(server_pk);
    let first_reply = handshake_with_resends(socket, &request, |packet| {
        match client.verify_handshake_response(packet) {
            Ok(reply) => Some(Phase0Reply::Response(reply)),
            Err(_) => client
                .solve_challenge(packet, DEFAULT_MAX_PUZZLE_DIFFICULTY)
                .ok()
                .map(Phase0Reply::Challenge),
        }
    })
    .await?;
    let reply = match first_reply {
        Phase0Reply::Response(reply) => reply,
        Phase0Reply::Challenge(solved) => {
            handshake_with_resends(socket, &solved, |packet| {
                client.verify_handshake_response(packet).ok()
            })
            .await?
        }
    };
    let matching: Vec<Vec<u8>> = client
        .start_collecting(reply)?
        .requests()
        .iter()
        .filter(|r| r.kind == kind)
        .map(|r| r.bytes.clone())
        .collect();
    if matching.is_empty() {
        return Err("client built no request of this kind".into());
    }
    Ok(matching)
}

/// One cookie-harvesting handshake: like [`obtain_requests`], but times every
/// puzzle it solves (the server may issue up to `MAX_PUZZLES_PER_HANDSHAKE` of
/// them per handshake, same as the real session client) and refuses none up
/// to `max_puzzle_difficulty`, so a harvester under `--puzzle-difficulty`
/// solves every challenge it is given.
async fn harvest_cookie<SCHEME: HqcScheme>(
    socket: &UdpSocket,
    server_pk: &ServerPublicKey<SCHEME>,
    kind: Kind,
    max_puzzle_difficulty: u8,
) -> Result<(Vec<Vec<u8>>, Duration), Box<dyn std::error::Error>> {
    let client = Client::<SCHEME, _, _, _>::new(InMemorySessionStore::new(), OsEntropy);
    let (client, handshake_request) = client.initialize(server_pk);
    let mut recv_buf = [0u8; 4096];
    let mut rto = RTO_FALLBACK;
    let mut attempts = 0u32;
    let mut puzzles_solved = 0u32;
    let mut puzzle_time = Duration::ZERO;
    let mut current_request = handshake_request;
    let reply = loop {
        let last_send = Instant::now();
        socket.send(&current_request).await?;
        let deadline = last_send + rto;
        let event = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, socket.recv(&mut recv_buf)).await {
                Ok(Ok(len)) => {
                    let packet = &recv_buf[..len];
                    if let Ok(reply) = client.verify_handshake_response(packet) {
                        break HandshakeEvent::Replied(reply);
                    }
                    if puzzles_solved < MAX_PUZZLES_PER_HANDSHAKE {
                        let solve_start = Instant::now();
                        let solved = client.solve_challenge(packet, max_puzzle_difficulty);
                        puzzle_time += solve_start.elapsed();
                        if let Ok(solved) = solved {
                            break HandshakeEvent::Challenged(solved);
                        }
                    }
                }
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break HandshakeEvent::TimedOut,
            }
        };
        match event {
            HandshakeEvent::Replied(reply) => break reply,
            HandshakeEvent::Challenged(solved) => {
                puzzles_solved += 1;
                current_request = solved;
            }
            HandshakeEvent::TimedOut => {
                attempts += 1;
                if attempts > MAX_RETRIES {
                    return Err("handshake timed out".into());
                }
                rto = (rto * RTO_BACKOFF).min(RTO_MAX);
            }
        }
    };
    let matching: Vec<Vec<u8>> = client
        .start_collecting(reply)?
        .requests()
        .iter()
        .filter(|r| r.kind == kind)
        .map(|r| r.bytes.clone())
        .collect();
    Ok((matching, puzzle_time))
}

#[derive(Default)]
struct HarvestStats {
    packets_sent: AtomicU64,
    cookies_obtained: AtomicU64,
    handshake_failures: AtomicU64,
    puzzle_ns: AtomicU64,
}

/// One cookie-harvesting worker: harvests a fresh cookie, then spends its
/// whole per-index replay budget (`DEFAULT_DUPLICATES` + 1 answers per
/// `(cookie, kind, index)`, the filter's default) before harvesting again.
/// Models an attacker who holds nothing back: maximum handshake concurrency
/// (one worker per socket, every worker harvesting as fast as the network
/// allows) and every cookie's budget spent in full.
async fn harvest_worker<SCHEME: HqcScheme>(
    socket: UdpSocket,
    server_pk: &ServerPublicKey<SCHEME>,
    kind: Kind,
    max_puzzle_difficulty: u8,
    deadline: Instant,
    stats: &HarvestStats,
) {
    let per_index_budget = usize::from(DEFAULT_DUPLICATES) + 1;
    while Instant::now() < deadline {
        match harvest_cookie::<SCHEME>(&socket, server_pk, kind, max_puzzle_difficulty).await {
            Ok((requests, puzzle_time)) => {
                stats.cookies_obtained.fetch_add(1, Ordering::Relaxed);
                stats
                    .puzzle_ns
                    .fetch_add(puzzle_time.as_nanos() as u64, Ordering::Relaxed);
                let mut sent = 0u64;
                'budget: for request in &requests {
                    for _ in 0..per_index_budget {
                        if Instant::now() >= deadline {
                            break 'budget;
                        }
                        if socket.send(request).await.is_ok() {
                            sent += 1;
                        }
                    }
                }
                stats.packets_sent.fetch_add(sent, Ordering::Relaxed);
            }
            Err(_) => {
                stats.handshake_failures.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

const FLOOD_SOURCE_IP_BASE: [u8; 2] = [127, 1];
const FLOOD_SOURCE_BASE_ENV: &str = "FLOOD_SOURCE_BASE";

fn flood_source_base() -> [u8; 2] {
    std::env::var(FLOOD_SOURCE_BASE_ENV)
        .ok()
        .and_then(|value| {
            let (a, b) = value.split_once('.')?;
            Some([a.parse().ok()?, b.parse().ok()?])
        })
        .unwrap_or(FLOOD_SOURCE_IP_BASE)
}
const AUTH_FLOOD_POOL_SIZE: usize = 4096;

/// Source address for flood socket `index`. With one source IP the kernel
/// picks the address. With more, sockets share 127.1.x.y round robin, which
/// Linux accepts on loopback.
fn flood_source(index: usize, source_ips: usize) -> std::net::SocketAddr {
    use std::net::{Ipv4Addr, SocketAddr};
    if source_ips <= 1 {
        return SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
    }
    let host = (index % source_ips) as u16 + 1;
    let [hi, lo] = host.to_be_bytes();
    let [a, b] = flood_source_base();
    SocketAddr::from((Ipv4Addr::new(a, b, hi, lo), 0))
}

/// Well-formed handshake requests whose `ct_auth` is random bytes. The server
/// cannot tell before it decapsulates, so each one costs a full ML-KEM
/// decapsulation. Distinct packets keep every request different on the wire.
fn random_auth_requests<SCHEME: HqcScheme>() -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let ct_bytes = HQCLethe::auth::auth_ciphertext_bytes::<SCHEME>();
    let mut buf = [0u8; MAX_UDP_PAYLOAD];
    (0..AUTH_FLOOD_POOL_SIZE)
        .map(|_| {
            let mut hash_ek_kem = [0u8; 32];
            let mut h_seed = [0u8; 32];
            let mut auth_ct = vec![0u8; ct_bytes];
            OsEntropy.random_bytes(&mut hash_ek_kem);
            OsEntropy.random_bytes(&mut h_seed);
            OsEntropy.random_bytes(&mut auth_ct);
            let len = encoding::write_handshake_request::<SCHEME>(
                &mut buf,
                &hash_ek_kem,
                &h_seed,
                &auth_ct,
            )?;
            Ok(buf[..len].to_vec())
        })
        .collect()
}

struct FloodPackets {
    packets: RefCell<Vec<Vec<u8>>>,
    refreshes: Cell<u64>,
}

impl FloodPackets {
    fn new(packets: Vec<Vec<u8>>) -> Self {
        Self {
            packets: RefCell::new(packets),
            refreshes: Cell::new(0),
        }
    }

    fn replace(&self, packets: Vec<Vec<u8>>) {
        *self.packets.borrow_mut() = packets;
        self.refreshes.set(self.refreshes.get() + 1);
    }

    fn snapshot(&self) -> (Vec<Vec<u8>>, u64) {
        (self.packets.borrow().clone(), self.refreshes.get())
    }
}

async fn keep_cookie_fresh<SCHEME: HqcScheme>(
    socket: &UdpSocket,
    server_pk: &ServerPublicKey<SCHEME>,
    kind: Kind,
    every: Duration,
    flood: &FloodPackets,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        tokio::time::sleep(every).await;
        flood.replace(obtain_requests::<SCHEME>(socket, server_pk, kind).await?);
    }
}

async fn blast(sockets: &[UdpSocket], flood: &FloodPackets, deadline: Instant) -> u64 {
    let (mut packets, mut seen_refreshes) = flood.snapshot();
    let mut sent: u64 = 0;
    let mut i = 0usize;
    while Instant::now() < deadline {
        if flood.refreshes.get() != seen_refreshes {
            (packets, seen_refreshes) = flood.snapshot();
        }
        let socket = &sockets[i % sockets.len()];
        if socket.send(&packets[i % packets.len()]).await.is_ok() {
            sent += 1;
        }
        i += 1;
    }
    sent
}

/// Blasts real (but never-completed) protocol requests at a server from
/// many distinct local sockets/ports as fast as possible, to drive the
/// memory-flooding / CPU-overload DoS measurements in
/// eval/scripts/dos_flood.py. `FloodKind::Handshake` never advances past
/// the stateless handshake path. `FloodKind::UChunk` and `FloodKind::VResidue`
/// first complete one real handshake to obtain a valid cookie, then flood
/// the u-chunk or v-residue path with valid requests. An attacker who holds
/// a cookie and the session keys could do the same. Those two kinds take a
/// new cookie every `cookie_refresh` so that the requests stay valid.
/// Runs the cookie-harvesting attacker (`--kind uchunk-harvest` or
/// `vresidue-harvest`): one worker per socket, each harvesting cookies back
/// to back and spending every cookie's full replay budget, for
/// `duration_secs`. Prints the same style of JSON line as [`flood_client`],
/// plus `cookies_obtained`, `handshake_failures` and `puzzle_cpu_secs` (total
/// CPU time this process spent solving puzzles, summed over every worker).
async fn harvest_flood_client<SCHEME: HqcScheme>(
    server_addr: &str,
    server_pk: &ServerPublicKey<SCHEME>,
    duration_secs: u64,
    num_sockets: usize,
    source_ips: usize,
    (kind, kind_label): (Kind, &str),
    max_puzzle_difficulty: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let process_started = Instant::now();
    let stats = HarvestStats::default();
    let deadline = Instant::now() + Duration::from_secs(duration_secs);
    let attack_started_secs = process_started.elapsed().as_secs_f64();

    let mut sockets = Vec::with_capacity(num_sockets);
    for i in 0..num_sockets {
        let socket = UdpSocket::bind(flood_source(i, source_ips)).await?;
        socket.connect(server_addr).await?;
        sockets.push(socket);
    }
    // All workers run concurrently on this one task (same model as `blast`
    // for the other flood kinds): network waits interleave on the async
    // runtime's reactor without needing a worker thread per socket.
    let workers = sockets.into_iter().map(|socket| {
        harvest_worker::<SCHEME>(
            socket,
            server_pk,
            kind,
            max_puzzle_difficulty,
            deadline,
            &stats,
        )
    });
    futures::future::join_all(workers).await;

    println!(
        "{}",
        json!({
            "packets_sent": stats.packets_sent.load(Ordering::Relaxed),
            "sockets": num_sockets,
            "duration_secs": duration_secs,
            "source_ips": source_ips,
            "kind": kind_label,
            "cookies_obtained": stats.cookies_obtained.load(Ordering::Relaxed),
            "handshake_failures": stats.handshake_failures.load(Ordering::Relaxed),
            "puzzle_cpu_secs": stats.puzzle_ns.load(Ordering::Relaxed) as f64 / 1e9,
            "attack_started_secs": attack_started_secs,
        })
    );
    Ok(())
}

async fn flood_client<SCHEME: HqcScheme>(
    server_addr: &str,
    server_pk: &ServerPublicKey<SCHEME>,
    duration_secs: u64,
    num_sockets: usize,
    source_ips: usize,
    kind: FloodKind,
    cookie_refresh: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let process_started = Instant::now();
    let setup_socket = UdpSocket::bind("0.0.0.0:0").await?;
    setup_socket.connect(server_addr).await?;

    let (packets, kind_label): (Vec<Vec<u8>>, &str) = match kind {
        FloodKind::Handshake => {
            let store = InMemorySessionStore::new();
            let client = Client::<SCHEME, _, _, _>::new(store, OsEntropy);
            let (_client, request) = client.initialize(server_pk);
            (vec![request], "handshake")
        }
        FloodKind::Auth => (random_auth_requests::<SCHEME>()?, "auth"),
        FloodKind::UChunk => (
            obtain_requests::<SCHEME>(&setup_socket, server_pk, Kind::UChunk).await?,
            "uchunk",
        ),
        FloodKind::VResidue => (
            obtain_requests::<SCHEME>(&setup_socket, server_pk, Kind::VResidue).await?,
            "vresidue",
        ),
        FloodKind::UChunkHarvest | FloodKind::VResidueHarvest => {
            unreachable!("dispatched to harvest_flood_client before reaching flood_client")
        }
    };

    let mut sockets = Vec::with_capacity(num_sockets);
    for i in 0..num_sockets {
        let socket = UdpSocket::bind(flood_source(i, source_ips)).await?;
        socket.connect(server_addr).await?;
        sockets.push(socket);
    }

    let packet_bytes = packets[0].len();
    let flood = FloodPackets::new(packets);
    let cookie_kind = match kind {
        FloodKind::UChunk => Some(Kind::UChunk),
        FloodKind::VResidue => Some(Kind::VResidue),
        FloodKind::Handshake | FloodKind::Auth => None,
        FloodKind::UChunkHarvest | FloodKind::VResidueHarvest => {
            unreachable!("dispatched to harvest_flood_client before reaching flood_client")
        }
    };
    let attack_started_secs = process_started.elapsed().as_secs_f64();
    let deadline = Instant::now() + Duration::from_secs(duration_secs);
    let sent = match cookie_kind {
        Some(cookie_kind) => tokio::select! {
            sent = blast(&sockets, &flood, deadline) => sent,
            refresh = keep_cookie_fresh::<SCHEME>(&setup_socket, server_pk, cookie_kind, cookie_refresh, &flood) => {
                refresh?;
                unreachable!("the refresh loop only ends with an error")
            }
        },
        None => blast(&sockets, &flood, deadline).await,
    };

    println!(
        "{}",
        json!({
            "packets_sent": sent,
            "sockets": num_sockets,
            "duration_secs": duration_secs,
            "source_ips": source_ips,
            "packet_bytes": packet_bytes,
            "kind": kind_label,
            "cookie_refreshes": flood.refreshes.get(),
            "attack_started_secs": attack_started_secs,
        })
    );
    Ok(())
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as a UDP client
    Client {
        #[arg(short, long, default_value = "127.0.0.1:12345")]
        addr: String,
        #[arg(short, long, value_enum, default_value_t = Variant::Hqc1)]
        variant: Variant,
        /// Local IPv4 address of the client socket
        #[arg(long, default_value = ANY_LOCAL_IP)]
        bind_ip: Ipv4Addr,
        /// Pinned server public key file (default: server-<variant>.pk)
        #[arg(short = 'k', long)]
        server_key: Option<PathBuf>,
        /// Hardest client puzzle (leading zero bits) to solve for the server
        #[arg(long, default_value_t = DEFAULT_MAX_PUZZLE_DIFFICULTY)]
        max_puzzle_difficulty: u8,
    },
    /// Generate a long-term server keypair: writes <out>.pk and <out>.sk
    Keygen {
        #[arg(short, long, value_enum, default_value_t = Variant::Hqc1)]
        variant: Variant,
        /// Output path prefix (default: server-<variant>)
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Print packet/byte-count JSON for one in-process protocol session per variant
    BandwidthReport {
        /// Print a text table instead of JSON
        #[arg(long)]
        table: bool,
    },
    /// Blast never-completed protocol requests at a server (DoS/flood measurement)
    FloodClient {
        #[arg(short, long, default_value = "127.0.0.1:12345")]
        addr: String,
        #[arg(short, long, value_enum, default_value_t = Variant::Hqc1)]
        variant: Variant,
        /// Pinned server public key file (default: server-<variant>.pk)
        #[arg(short = 'k', long)]
        server_key: Option<PathBuf>,
        /// Seconds of attack after the setup (cookie collection) is done
        #[arg(short, long, default_value_t = 10)]
        duration: u64,
        #[arg(short, long, default_value_t = 64)]
        sockets: usize,
        /// Distinct 127.1.x.y source addresses to bind the sockets to
        /// (default 1: the kernel picks the address). Models a botnet.
        #[arg(long, default_value_t = 1)]
        source_ips: usize,
        /// Which request type to flood: the stateless handshake path, the
        /// handshake path with random ML-KEM ciphertexts, or the u-chunk
        /// or v-residue path (both need a valid cookie from one real handshake)
        #[arg(short, long, value_enum, default_value_t = FloodKind::Handshake)]
        kind: FloodKind,
        /// Seconds between new cookies for the u-chunk and v-residue floods.
        /// Must be shorter than the server's cookie-key rotation period.
        #[arg(long, default_value_t = DEFAULT_FLOOD_COOKIE_REFRESH_SECS)]
        cookie_refresh_secs: u64,
        /// Hardest server puzzle the harvest kinds will solve (they solve
        /// every challenge up to this difficulty; irrelevant to the other kinds)
        #[arg(long, default_value_t = DEFAULT_MAX_PUZZLE_DIFFICULTY)]
        max_puzzle_difficulty: u8,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Variant {
    Hqc1,
    Hqc3,
    Hqc5,
}

impl Variant {
    fn name(self) -> &'static str {
        match self {
            Variant::Hqc1 => "hqc1",
            Variant::Hqc3 => "hqc3",
            Variant::Hqc5 => "hqc5",
        }
    }
}

fn load_server_pk<SCHEME: HqcScheme>(
    variant: Variant,
    path: Option<PathBuf>,
) -> Result<ServerPublicKey<SCHEME>, Box<dyn std::error::Error>> {
    let path = path.unwrap_or_else(|| PathBuf::from(format!("server-{}.pk", variant.name())));
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    ServerPublicKey::from_bytes(bytes).map_err(|_| {
        format!(
            "{} is not a public key for {}",
            path.display(),
            variant.name()
        )
        .into()
    })
}

fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)?.write_all(bytes)
}

fn keygen<SCHEME: HqcScheme>(variant: Variant, out: Option<PathBuf>) -> std::io::Result<()> {
    let prefix = out.unwrap_or_else(|| PathBuf::from(format!("server-{}", variant.name())));
    let keys = ServerKeypair::<SCHEME>::generate();
    let with_suffix = |suffix: &str| {
        let mut path = prefix.clone().into_os_string();
        path.push(suffix);
        PathBuf::from(path)
    };
    let pk_path = with_suffix(".pk");
    let sk_path = with_suffix(".sk");
    std::fs::write(&pk_path, keys.public.as_bytes())?;
    write_secret_file(&sk_path, keys.secret.as_bytes())?;
    let fingerprint = blake3::hash(keys.public.as_bytes()).to_hex();
    println!("public key: {} (blake3 {fingerprint})", pk_path.display());
    println!("secret key: {}", sk_path.display());
    Ok(())
}
#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum FloodKind {
    Handshake,
    /// Valid-format handshake requests with random `ct_auth`
    Auth,
    /// Valid u-chunk requests with a valid cookie
    #[value(name = "uchunk")]
    UChunk,
    /// Valid v-residue requests with a valid cookie
    #[value(name = "vresidue")]
    VResidue,
    /// Cookie-harvesting attacker: handshakes continuously, every worker its
    /// own socket, and spends each cookie's full u-chunk replay budget
    #[value(name = "uchunk-harvest")]
    UChunkHarvest,
    /// Cookie-harvesting attacker: handshakes continuously, every worker its
    /// own socket, and spends each cookie's full v-residue replay budget
    #[value(name = "vresidue-harvest")]
    VResidueHarvest,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Commands::Client {
            addr,
            variant,
            bind_ip,
            server_key,
            max_puzzle_difficulty,
        } => match variant {
            Variant::Hqc1 => {
                run_client::<Hqc1>(
                    &addr,
                    bind_ip,
                    &load_server_pk(variant, server_key)?,
                    max_puzzle_difficulty,
                )
                .await?
            }
            Variant::Hqc3 => {
                run_client::<Hqc3>(
                    &addr,
                    bind_ip,
                    &load_server_pk(variant, server_key)?,
                    max_puzzle_difficulty,
                )
                .await?
            }
            Variant::Hqc5 => {
                run_client::<Hqc5>(
                    &addr,
                    bind_ip,
                    &load_server_pk(variant, server_key)?,
                    max_puzzle_difficulty,
                )
                .await?
            }
        },
        Commands::Keygen { variant, out } => match variant {
            Variant::Hqc1 => keygen::<Hqc1>(variant, out)?,
            Variant::Hqc3 => keygen::<Hqc3>(variant, out)?,
            Variant::Hqc5 => keygen::<Hqc5>(variant, out)?,
        },
        Commands::BandwidthReport { table } => {
            let reports = vec![
                bandwidth_report::<Hqc1>("hqc1"),
                bandwidth_report::<Hqc3>("hqc3"),
                bandwidth_report::<Hqc5>("hqc5"),
            ];
            if table {
                print_bandwidth_table(&reports);
            } else {
                println!("{}", serde_json::to_string_pretty(&reports)?);
            }
        }
        Commands::FloodClient {
            addr,
            variant,
            server_key,
            duration,
            sockets,
            source_ips,
            kind,
            cookie_refresh_secs,
            max_puzzle_difficulty,
        } => {
            let refresh = Duration::from_secs(cookie_refresh_secs);
            let harvest_kind = match kind {
                FloodKind::UChunkHarvest => Some((Kind::UChunk, "uchunk-harvest")),
                FloodKind::VResidueHarvest => Some((Kind::VResidue, "vresidue-harvest")),
                _ => None,
            };
            match (variant, harvest_kind) {
                (Variant::Hqc1, Some((kind, label))) => {
                    let pk = load_server_pk::<Hqc1>(variant, server_key)?;
                    harvest_flood_client::<Hqc1>(
                        &addr,
                        &pk,
                        duration,
                        sockets,
                        source_ips,
                        (kind, label),
                        max_puzzle_difficulty,
                    )
                    .await?
                }
                (Variant::Hqc3, Some((kind, label))) => {
                    let pk = load_server_pk::<Hqc3>(variant, server_key)?;
                    harvest_flood_client::<Hqc3>(
                        &addr,
                        &pk,
                        duration,
                        sockets,
                        source_ips,
                        (kind, label),
                        max_puzzle_difficulty,
                    )
                    .await?
                }
                (Variant::Hqc5, Some((kind, label))) => {
                    let pk = load_server_pk::<Hqc5>(variant, server_key)?;
                    harvest_flood_client::<Hqc5>(
                        &addr,
                        &pk,
                        duration,
                        sockets,
                        source_ips,
                        (kind, label),
                        max_puzzle_difficulty,
                    )
                    .await?
                }
                (Variant::Hqc1, None) => {
                    let pk = load_server_pk(variant, server_key)?;
                    flood_client::<Hqc1>(&addr, &pk, duration, sockets, source_ips, kind, refresh)
                        .await?
                }
                (Variant::Hqc3, None) => {
                    let pk = load_server_pk(variant, server_key)?;
                    flood_client::<Hqc3>(&addr, &pk, duration, sockets, source_ips, kind, refresh)
                        .await?
                }
                (Variant::Hqc5, None) => {
                    let pk = load_server_pk(variant, server_key)?;
                    flood_client::<Hqc5>(&addr, &pk, duration, sockets, source_ips, kind, refresh)
                        .await?
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGIT_IP: Ipv4Addr = Ipv4Addr::new(127, 2, 0, 1);

    fn parsed_bind_ip(extra: &[&str]) -> Ipv4Addr {
        let mut argv = vec!["hqclethe-client", "client"];
        argv.extend_from_slice(extra);
        match Args::try_parse_from(argv).unwrap().command {
            Commands::Client { bind_ip, .. } => bind_ip,
            _ => unreachable!(),
        }
    }

    #[test]
    fn client_binds_any_address_by_default() {
        assert_eq!(parsed_bind_ip(&[]), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn client_takes_bind_ip_option() {
        assert_eq!(parsed_bind_ip(&["--bind-ip", "127.2.0.1"]), LEGIT_IP);
    }

    #[test]
    fn bind_address_has_ephemeral_port() {
        let address = client_bind_address(LEGIT_IP);
        assert_eq!(
            (address.ip().to_string(), address.port()),
            ("127.2.0.1".to_string(), 0)
        );
    }
}
