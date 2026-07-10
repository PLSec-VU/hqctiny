use HQCTiny::client::{Client, PointResult};
use HQCTiny::encoding::{Packet, decode_packet, encode_packet};
use HQCTiny::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCTiny::protocol::{PointRequest, PointType};
use HQCTiny::server::Server;
use HQCTiny::traits::*;
use clap::{Parser, Subcommand, ValueEnum};
use rand::RngCore;
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

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

async fn run_client<SCHEME: HqcScheme>(
    server_addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(server_addr).await?;

    // Phase timestamps for RTT accounting under emulated/real WAN links
    // (see eval/scripts/wan_latency.py): t0/t1 bound the handshake RTT,
    // t2/t3 bound the point-request RTT. Printed to stderr so stdout stays
    // reserved for the shared-secret result.
    let t_start = Instant::now();
    let phase = |name: &str| eprintln!("[phase] {name} t={}", t_start.elapsed().as_secs_f64());

    let store = InMemorySessionStore::new();
    let client = Client::<SCHEME, _, _, _>::new(store, OsEntropy);

    let (client, handshake_req) = client.initialize();
    let mut buf = [0u8; 2048];
    let encoded = encode_packet::<SCHEME>(&Packet::HandshakeRequest(handshake_req), &mut buf)?;
    socket.send(encoded).await?;
    phase("handshake_request_sent");

    let mut recv_buf = [0u8; 4096];
    let len = socket.recv(&mut recv_buf).await?;
    phase("handshake_response_received");
    let packet = decode_packet::<SCHEME>(&recv_buf[..len])?;

    let handshake_res = match packet {
        Packet::HandshakeResponse(res) => res,
        _ => return Err("Expected HandshakeResponse".into()),
    };

    let (client, point_reqs) = client.handle_handshake_response(handshake_res)?;
    let mut client = client;

    // Send all point requests
    for req in point_reqs {
        let mut buf = [0u8; 2048];
        let encoded = encode_packet::<SCHEME>(&Packet::PointRequest(req), &mut buf)?;
        socket.send(encoded).await?;
    }
    phase("point_requests_sent");

    // Collect responses
    loop {
        let len = socket.recv(&mut recv_buf).await?;
        let packet = decode_packet::<SCHEME>(&recv_buf[..len])?;
        let point_res = match packet {
            Packet::PointResponse(res) => res,
            _ => continue,
        };

        match client.handle_point_response(point_res)? {
            PointResult::Collecting(c) => client = *c,
            PointResult::Completed(_, key) => {
                phase("session_key_derived");
                print_shared_secret(&key);
                return Ok(());
            }
        }
    }
}

/// Runs one full protocol session in-process (no network) and reports the
/// exact wire size of every packet type, round-trip counts, and how that
/// compares to the raw key/ciphertext bytes a non-segmented KEM handshake
/// would move. See eval/scripts/bandwidth.py.
fn bandwidth_report<SCHEME: HqcScheme>(variant_name: &str) -> serde_json::Value {
    const MTU_LIMIT: usize = 1280;

    let store = InMemorySessionStore::new();
    let server = Server::<SCHEME, _, _>::new(store.clone(), OsEntropy);
    let client = Client::<SCHEME, _, _, _>::new(store, OsEntropy);

    let (client, req) = client.initialize();
    let mut buf = vec![0u8; 4096];
    let handshake_req_bytes =
        encode_packet::<SCHEME>(&Packet::HandshakeRequest(req.clone()), &mut buf)
            .unwrap()
            .len();

    let res = server.handle_handshake(req).unwrap();
    let mut buf = vec![0u8; 4096];
    let handshake_res_bytes = encode_packet::<SCHEME>(&Packet::HandshakeResponse(res), &mut buf)
        .unwrap()
        .len();

    let (mut client, point_reqs) = client.handle_handshake_response(res).unwrap();
    let mut max_point_req_bytes = 0usize;
    let mut max_point_res_bytes = 0usize;
    let mut max_packet_bytes = handshake_req_bytes.max(handshake_res_bytes);

    for req in point_reqs {
        let mut buf = vec![0u8; 8192];
        let encoded = encode_packet::<SCHEME>(&Packet::PointRequest(req), &mut buf)
            .unwrap()
            .len();
        max_point_req_bytes = max_point_req_bytes.max(encoded);
        max_packet_bytes = max_packet_bytes.max(encoded);

        let point_res = server.handle_point_request(req).unwrap();
        let mut buf = vec![0u8; 8192];
        let encoded = encode_packet::<SCHEME>(&Packet::PointResponse(point_res.clone()), &mut buf)
            .unwrap()
            .len();
        max_point_res_bytes = max_point_res_bytes.max(encoded);
        max_packet_bytes = max_packet_bytes.max(encoded);

        match client.handle_point_response(point_res).unwrap() {
            PointResult::Collecting(c) => client = *c,
            PointResult::Completed(_, _) => break,
        }
    }

    let points_num = SCHEME::POINTS_NUM;
    let round_trips = 1 + points_num * 2;
    let total_sent = handshake_req_bytes + points_num * 2 * max_point_req_bytes;
    let total_received = handshake_res_bytes + points_num * 2 * max_point_res_bytes;
    // What a naive (non-McTiny-style) KEM handshake would move: the
    // client's ephemeral public key and the server's ciphertext, sent
    // whole instead of as segmented evaluation points.
    let raw_baseline = SCHEME::PUBLIC_KEY_BYTES + SCHEME::CIPHERTEXT_BYTES;

    json!({
        "variant": variant_name,
        "packet_bytes": {
            "handshake_request": handshake_req_bytes,
            "handshake_response": handshake_res_bytes,
            "point_request_max": max_point_req_bytes,
            "point_response_max": max_point_res_bytes,
        },
        "round_trips": round_trips,
        "total_sent_bytes": total_sent,
        "total_received_bytes": total_received,
        "total_bytes": total_sent + total_received,
        "raw_baseline_bytes": raw_baseline,
        "overhead_ratio": (total_sent + total_received) as f64 / raw_baseline as f64,
        "mtu_limit_bytes": MTU_LIMIT,
        "max_packet_bytes": max_packet_bytes,
        "mtu_ok": max_packet_bytes <= MTU_LIMIT,
    })
}

/// Performs one real handshake round trip against `server_addr` and
/// returns a valid, server-issued PointRequest (point_index=1, type U).
/// The cookie inside it is a genuine AEAD ciphertext the server produced
/// and can decrypt, so -- unlike the HandshakeRequest flood payload --
/// this can't be synthesized without actually talking to the server once.
async fn obtain_point_request<SCHEME: HqcScheme>(
    socket: &UdpSocket,
) -> Result<PointRequest, Box<dyn std::error::Error>> {
    let store = InMemorySessionStore::new();
    let client = Client::<SCHEME, _, _, _>::new(store, OsEntropy);
    let (client, req) = client.initialize();
    let mut buf = [0u8; 2048];
    let encoded = encode_packet::<SCHEME>(&Packet::HandshakeRequest(req), &mut buf)?;
    socket.send(encoded).await?;

    let mut recv_buf = [0u8; 4096];
    let len = socket.recv(&mut recv_buf).await?;
    let packet = decode_packet::<SCHEME>(&recv_buf[..len])?;
    let handshake_res = match packet {
        Packet::HandshakeResponse(res) => res,
        _ => return Err("Expected HandshakeResponse".into()),
    };

    let (_client, point_reqs) = client.handle_handshake_response(handshake_res)?;
    point_reqs
        .into_iter()
        .find(|r| r.point_index == 1 && r.point_type == PointType::U)
        .ok_or_else(|| "server returned no point_index=1 U request".into())
}

/// Blasts real (but never-completed) protocol requests at a server from
/// many distinct local sockets/ports as fast as possible, to drive the
/// memory-flooding / CPU-overload DoS measurements in
/// eval/scripts/dos_flood.py. `FloodKind::Handshake` never advances past
/// the stateless handshake path; `FloodKind::Point` first completes one
/// real handshake to obtain a valid cookie, then floods the (more
/// expensive to handle) point-request path an attacker who already has --
/// or has intercepted -- a cookie could exercise.
async fn flood_client<SCHEME: HqcScheme>(
    server_addr: &str,
    duration_secs: u64,
    num_sockets: usize,
    kind: FloodKind,
) -> Result<(), Box<dyn std::error::Error>> {
    let setup_socket = UdpSocket::bind("0.0.0.0:0").await?;
    setup_socket.connect(server_addr).await?;

    let mut buf = [0u8; 2048];
    let (encoded, kind_label): (Vec<u8>, &str) = match kind {
        FloodKind::Handshake => {
            let store = InMemorySessionStore::new();
            let client = Client::<SCHEME, _, _, _>::new(store, OsEntropy);
            let (_client, req) = client.initialize();
            (
                encode_packet::<SCHEME>(&Packet::HandshakeRequest(req), &mut buf)?.to_vec(),
                "handshake",
            )
        }
        FloodKind::Point => {
            let point_req = obtain_point_request::<SCHEME>(&setup_socket).await?;
            (
                encode_packet::<SCHEME>(&Packet::PointRequest(point_req), &mut buf)?.to_vec(),
                "point",
            )
        }
    };

    let mut sockets = Vec::with_capacity(num_sockets);
    for _ in 0..num_sockets {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(server_addr).await?;
        sockets.push(socket);
    }

    let deadline = Instant::now() + Duration::from_secs(duration_secs);
    let mut sent: u64 = 0;
    let mut i = 0usize;
    while Instant::now() < deadline {
        let socket = &sockets[i % sockets.len()];
        if socket.send(&encoded).await.is_ok() {
            sent += 1;
        }
        i += 1;
    }

    println!(
        "{}",
        json!({
            "packets_sent": sent,
            "sockets": num_sockets,
            "duration_secs": duration_secs,
            "packet_bytes": encoded.len(),
            "kind": kind_label,
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
    },
    /// Print packet/byte-count JSON for one in-process protocol session per variant
    BandwidthReport,
    /// Blast never-completed protocol requests at a server (DoS/flood measurement)
    FloodClient {
        #[arg(short, long, default_value = "127.0.0.1:12345")]
        addr: String,
        #[arg(short, long, value_enum, default_value_t = Variant::Hqc1)]
        variant: Variant,
        #[arg(short, long, default_value_t = 10)]
        duration: u64,
        #[arg(short, long, default_value_t = 64)]
        sockets: usize,
        /// Which request type to flood: the cheap-to-reject stateless
        /// handshake path, or the point-request path (more expensive per
        /// request), reachable only after completing one real handshake
        /// to obtain a valid cookie
        #[arg(short, long, value_enum, default_value_t = FloodKind::Handshake)]
        kind: FloodKind,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Variant {
    Hqc1,
    Hqc3,
    Hqc5,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum FloodKind {
    Handshake,
    Point,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Commands::Client { addr, variant } => match variant {
            Variant::Hqc1 => run_client::<Hqc1>(&addr).await?,
            Variant::Hqc3 => run_client::<Hqc3>(&addr).await?,
            Variant::Hqc5 => run_client::<Hqc5>(&addr).await?,
        },
        Commands::BandwidthReport => {
            let reports = vec![
                bandwidth_report::<Hqc1>("hqc1"),
                bandwidth_report::<Hqc3>("hqc3"),
                bandwidth_report::<Hqc5>("hqc5"),
            ];
            println!("{}", serde_json::to_string_pretty(&reports)?);
        }
        Commands::FloodClient {
            addr,
            variant,
            duration,
            sockets,
            kind,
        } => match variant {
            Variant::Hqc1 => flood_client::<Hqc1>(&addr, duration, sockets, kind).await?,
            Variant::Hqc3 => flood_client::<Hqc3>(&addr, duration, sockets, kind).await?,
            Variant::Hqc5 => flood_client::<Hqc5>(&addr, duration, sockets, kind).await?,
        },
    }

    Ok(())
}
