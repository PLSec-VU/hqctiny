use HQCLethe::auth::{AuthLevel, ServerPublicKey};
use HQCLethe::stateful::auth::{ClientAuth, MlKemClientAuth, MlKemServerAuth, RandomRequestAuth};
use HQCLethe::stateful::client::StatefulClient;
use HQCLethe::stateful::config::ServerConfig;
use HQCLethe::stateful::entropy::OsEntropy;
use HQCLethe::stateful::kem::StatefulKem;
use HQCLethe::stateful::server::StatefulServer;
use HQCLethe::stateful::stats::{STATS_QUERY, StatsSnapshot};
use HQCLethe::stateful::transport::run_session;
use clap::{Parser, Subcommand, ValueEnum};
use hqclethe_stateful::{Variant, dispatch_variant};
use serde_json::json;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

const COOKIE_COLLECT_TOTAL: Duration = Duration::from_secs(2);
const MIN_RECV_TIMEOUT: Duration = Duration::from_millis(1);
const COOKIE_REFRESH_INTERVAL: Duration = Duration::from_secs(20);
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
const RECV_BYTES: usize = 4096;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Client {
        #[arg(short, long, default_value = "127.0.0.1:12346")]
        addr: String,
        #[arg(short, long, value_enum, default_value_t = Variant::Hqc1)]
        variant: Variant,
        #[arg(long, default_value = "0.0.0.0")]
        bind_ip: Ipv4Addr,
        /// Pinned server public key file (default: server-<variant>.pk)
        #[arg(short = 'k', long)]
        server_key: Option<PathBuf>,
    },
    FloodClient {
        #[arg(short, long, default_value = "127.0.0.1:12346")]
        addr: String,
        #[arg(short, long, value_enum, default_value_t = Variant::Hqc1)]
        variant: Variant,
        /// Seconds of attack after the setup (cookie collection) is done
        #[arg(short, long, default_value_t = 10)]
        duration: u64,
        #[arg(short, long, default_value_t = 64)]
        sockets: usize,
        #[arg(long, default_value_t = 1)]
        source_ips: usize,
        #[arg(short, long, value_enum, default_value_t = FloodKind::Hello)]
        kind: FloodKind,
        /// Pinned server public key file (default: server-<variant>.pk)
        #[arg(short = 'k', long)]
        server_key: Option<PathBuf>,
    },
    Stats {
        #[arg(short, long, default_value = "127.0.0.1:12346")]
        addr: String,
    },
    /// Print packet counts and bytes of one in-process authenticated session per variant
    BandwidthReport {
        /// Print a table instead of JSON
        #[arg(long)]
        table: bool,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum FloodKind {
    Hello,
    Partial,
    Fullkey,
    Auth,
    /// Each source repeatedly obtains a fresh cookie and opens a new
    /// reassembly entry as fast as its per-source limit allows, for the
    /// whole flood duration (T3). Unlike `Partial`/`Fullkey`/`Auth`, which
    /// collect one cookie and then resend the same fragment(s) under that
    /// one cookie for up to COOKIE_REFRESH_INTERVAL, `Churn` re-collects a
    /// fresh cookie on every round, so every round's upload lands in a
    /// distinct table entry (EntryKey is keyed on (addr, cookie)) instead
    /// of hitting the same one as a duplicate.
    Churn,
    /// T3 round 3: `Churn` turned out not to be sustained -- it alternates
    /// a sequential cookie-collection pass (during which no uploads are
    /// sent at all) with uploading complete key sets (which the server
    /// finishes and removes immediately). `Churn2` fixes both: many
    /// worker threads each run their own sockets' hello/cookie/upload
    /// cycle concurrently (so uploads never stop while other sockets are
    /// mid-handshake), and every upload sends all key fragments except
    /// the last one, so the entry can never reach `Accepted::Complete`
    /// and stays in the table until the server evicts or times it out.
    Churn2,
}

impl FloodKind {
    fn label(self) -> &'static str {
        match self {
            Self::Hello => "hello",
            Self::Partial => "partial",
            Self::Fullkey => "fullkey",
            Self::Auth => "auth",
            Self::Churn => "churn",
            Self::Churn2 => "churn2",
        }
    }
}

#[cfg(not(feature = "quiet"))]
fn report_shared_secret(secret: &[u8]) {
    println!("session key: {}", hqclethe_stateful::hex(secret));
}

#[cfg(feature = "quiet")]
fn report_shared_secret(_secret: &[u8]) {}

fn load_server_key<K: AuthLevel>(
    variant: Variant,
    path: Option<PathBuf>,
) -> Result<Arc<ServerPublicKey<K>>, Box<dyn std::error::Error>> {
    let path = path.unwrap_or_else(|| PathBuf::from(format!("server-{}.pk", variant.name())));
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let key = ServerPublicKey::from_bytes(bytes).map_err(|_| {
        format!(
            "{} is not a public key for {}",
            path.display(),
            variant.name()
        )
    })?;
    Ok(Arc::new(key))
}

fn run_client<K: StatefulKem + AuthLevel>(
    addr: &str,
    bind_ip: Ipv4Addr,
    server_key: Arc<ServerPublicKey<K>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind((bind_ip, 0))?;
    socket.connect(addr)?;
    let started = Instant::now();
    let mut client = StatefulClient::<K, _>::new(MlKemClientAuth::new(server_key), &OsEntropy);
    started_phase(&started, "keypair_generated");
    let secret = run_session(&socket, &mut client, |name| started_phase(&started, name))?;
    report_shared_secret(&secret);
    Ok(())
}

fn started_phase(started: &Instant, name: &str) {
    eprintln!("[phase] {name} t={}", started.elapsed().as_secs_f64());
}

fn flood_source(index: usize, source_ips: usize) -> SocketAddr {
    if source_ips <= 1 {
        return (Ipv4Addr::UNSPECIFIED, 0).into();
    }
    let host = (index % source_ips) as u16 + 1;
    let [hi, lo] = host.to_be_bytes();
    let [a, b] = flood_source_base();
    (Ipv4Addr::new(a, b, hi, lo), 0).into()
}

fn open_flood_sockets(
    server: SocketAddr,
    count: usize,
    source_ips: usize,
) -> std::io::Result<Vec<UdpSocket>> {
    (0..count)
        .map(|i| {
            let socket = UdpSocket::bind(flood_source(i, source_ips))?;
            socket.connect(server)?;
            Ok(socket)
        })
        .collect()
}

type AuthFactory<'a> = &'a dyn Fn() -> Box<dyn ClientAuth>;

fn collect_key_fragments<K: StatefulKem>(
    sockets: &[UdpSocket],
    public_key: &[u8],
    make_auth: AuthFactory<'_>,
) -> Vec<Option<Vec<Vec<u8>>>> {
    let mut clients: Vec<StatefulClient<K, Box<dyn ClientAuth>>> = sockets
        .iter()
        .map(|_| {
            StatefulClient::with_keypair(make_auth(), &OsEntropy, public_key.to_vec(), Vec::new())
        })
        .collect();
    for (socket, client) in sockets.iter().zip(&clients) {
        let _ = socket.send(client.hello());
    }
    let mut buf = [0u8; RECV_BYTES];
    let collect_deadline = Instant::now() + COOKIE_COLLECT_TOTAL;
    sockets
        .iter()
        .zip(clients.iter_mut())
        .map(|(socket, client)| {
            let remaining = collect_deadline
                .saturating_duration_since(Instant::now())
                .max(MIN_RECV_TIMEOUT);
            let _ = socket.set_read_timeout(Some(remaining));
            let len = socket.recv(&mut buf).ok()?;
            client.on_server_hello(&buf[..len]).ok().map(|f| f.to_vec())
        })
        .collect()
}

/// `FloodKind::Churn`: every round, collect a fresh cookie per socket and
/// send the complete key upload once under it, then immediately collect
/// again -- no resend-same-cookie phase, so each round opens new table
/// entries (one per socket that gets a cookie and is not source-limited)
/// rather than retransmitting into the entries the last round opened.
fn churn_flood<K: StatefulKem>(
    sockets: &[UdpSocket],
    public_key: &[u8],
    make_auth: AuthFactory<'_>,
    deadline: Instant,
    duration: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut sent = 0u64;
    let mut cookies_obtained = 0usize;
    let mut packet_bytes = 0usize;
    let mut rounds = 0u64;
    while Instant::now() < deadline {
        let per_socket = collect_key_fragments::<K>(sockets, public_key, make_auth);
        cookies_obtained = per_socket.iter().flatten().count();
        rounds += 1;
        for (socket, fragments) in sockets.iter().zip(&per_socket) {
            let Some(fragments) = fragments else { continue };
            for fragment in fragments {
                packet_bytes = fragment.len();
                if socket.send(fragment).is_ok() {
                    sent += 1;
                }
            }
        }
    }
    println!(
        "{}",
        json!({
            "packets_sent": sent,
            "sockets": sockets.len(),
            "duration_secs": duration,
            "packet_bytes": packet_bytes,
            "kind": FloodKind::Churn.label(),
            "cookies_obtained": cookies_obtained,
            "rounds": rounds,
        })
    );
    Ok(())
}

/// `FloodKind::Churn2` (T3 round 3): CHURN2_WORKERS threads, each owning a
/// contiguous slice of the socket pool, loop independently: send hello,
/// wait briefly for the cookie, then send every key fragment except the
/// last one (so `ReassemblyTable::accept` never reaches `Accepted::Complete`
/// and the entry sits in the table until the server evicts or times it
/// out), then immediately start the next cycle on that same socket with a
/// fresh cookie. Because the threads run independently, some sockets are
/// always mid-upload while others are mid-handshake -- unlike `Churn`,
/// there is no global phase where every socket is simultaneously waiting
/// on cookies and nothing is being uploaded.
const CHURN2_WORKERS: usize = 64;
const CHURN2_RECV_TIMEOUT: Duration = Duration::from_millis(5);

fn churn2_flood<K: StatefulKem>(
    sockets: &[UdpSocket],
    public_key: &[u8],
    server_key: Arc<ServerPublicKey<K>>,
    deadline: Instant,
    duration: u64,
    attack_started_secs: f64,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::atomic::{AtomicU64, Ordering};

    let packets_sent = AtomicU64::new(0);
    let cookies_obtained = AtomicU64::new(0);
    let entries_attempted = AtomicU64::new(0);
    let workers = CHURN2_WORKERS.min(sockets.len().max(1));
    let chunk_size = sockets.len().div_ceil(workers).max(1);

    std::thread::scope(|scope| {
        for chunk in sockets.chunks(chunk_size) {
            let server_key = server_key.clone();
            let packets_sent = &packets_sent;
            let cookies_obtained = &cookies_obtained;
            let entries_attempted = &entries_attempted;
            scope.spawn(move || {
                let mut buf = [0u8; RECV_BYTES];
                while Instant::now() < deadline {
                    for socket in chunk {
                        let auth = MlKemClientAuth::new(server_key.clone());
                        let mut client = StatefulClient::<K, _>::with_keypair(
                            auth,
                            &OsEntropy,
                            public_key.to_vec(),
                            Vec::new(),
                        );
                        if socket.send(client.hello()).is_err() {
                            continue;
                        }
                        packets_sent.fetch_add(1, Ordering::Relaxed);
                        let _ = socket.set_read_timeout(Some(CHURN2_RECV_TIMEOUT));
                        let Ok(len) = socket.recv(&mut buf) else {
                            continue;
                        };
                        if client.on_server_hello(&buf[..len]).is_err() {
                            continue;
                        }
                        cookies_obtained.fetch_add(1, Ordering::Relaxed);
                        let fragments = client.key_fragments();
                        if fragments.len() < 2 {
                            // Can't withhold a fragment and still send at
                            // least one; skip rather than accidentally
                            // completing the upload. Not hit by HQC-1/3/5
                            // (2/4/7 fragments each, confirmed via
                            // bandwidth-report), kept as a safety net.
                            continue;
                        }
                        let incomplete = &fragments[..fragments.len() - 1];
                        for fragment in incomplete {
                            if socket.send(fragment).is_ok() {
                                packets_sent.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        entries_attempted.fetch_add(1, Ordering::Relaxed);
                        if Instant::now() >= deadline {
                            break;
                        }
                    }
                }
            });
        }
    });

    println!(
        "{}",
        json!({
            "packets_sent": packets_sent.load(Ordering::Relaxed),
            "sockets": sockets.len(),
            "duration_secs": duration,
            "kind": FloodKind::Churn2.label(),
            "attack_started_secs": attack_started_secs,
            "cookies_obtained": cookies_obtained.load(Ordering::Relaxed),
            "entries_attempted": entries_attempted.load(Ordering::Relaxed),
            "workers": workers,
        })
    );
    Ok(())
}

const AUTH_FLOOD_POOL_SIZE: usize = 4096;

fn hello_pool<K: StatefulKem>(
    kind: FloodKind,
    public_key: &[u8],
    make_auth: AuthFactory<'_>,
    honest_hello: &[u8],
) -> Vec<Vec<u8>> {
    if kind != FloodKind::Auth {
        return vec![honest_hello.to_vec()];
    }
    (0..AUTH_FLOOD_POOL_SIZE)
        .map(|_| {
            StatefulClient::<K, _>::with_keypair(
                make_auth(),
                &OsEntropy,
                public_key.to_vec(),
                Vec::new(),
            )
            .hello()
            .to_vec()
        })
        .collect()
}

fn flood_client<K: StatefulKem + AuthLevel>(
    addr: &str,
    duration: u64,
    socket_count: usize,
    source_ips: usize,
    kind: FloodKind,
    server_key: Arc<ServerPublicKey<K>>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::net::ToSocketAddrs;
    let process_started = Instant::now();
    let server = addr.to_socket_addrs()?.next().ok_or("no address")?;
    let sockets = open_flood_sockets(server, socket_count, source_ips)?;
    let churn2_server_key = server_key.clone();
    let honest_auth =
        move || -> Box<dyn ClientAuth> { Box::new(MlKemClientAuth::new(server_key.clone())) };
    let request_bytes = HQCLethe::auth::auth_ciphertext_bytes::<K>();
    let random_auth = move || -> Box<dyn ClientAuth> {
        Box::new(RandomRequestAuth::new(request_bytes, OsEntropy))
    };
    let make_auth: AuthFactory<'_> = match kind {
        FloodKind::Auth => &random_auth,
        _ => &honest_auth,
    };
    let template = StatefulClient::<K, _>::new(make_auth(), &OsEntropy);
    let hello = template.hello().to_vec();
    let hellos = hello_pool::<K>(kind, template.public_key(), make_auth, &hello);
    let attack_duration = Duration::from_secs(duration);
    let mut deadline = Instant::now() + attack_duration;
    if kind == FloodKind::Churn {
        return churn_flood::<K>(
            &sockets,
            template.public_key(),
            make_auth,
            deadline,
            duration,
        );
    }
    if kind == FloodKind::Churn2 {
        return churn2_flood::<K>(
            &sockets,
            template.public_key(),
            churn2_server_key,
            deadline,
            duration,
            process_started.elapsed().as_secs_f64(),
        );
    }
    let mut attack_started_secs = process_started.elapsed().as_secs_f64();
    let mut sent = 0u64;
    let mut cookies_obtained = 0usize;
    let mut packet_bytes = hello.len();

    if matches!(kind, FloodKind::Hello | FloodKind::Auth) {
        let mut i = 0usize;
        while Instant::now() < deadline {
            if sockets[i % sockets.len()]
                .send(&hellos[i % hellos.len()])
                .is_ok()
            {
                sent += 1;
            }
            i += 1;
        }
    } else {
        while Instant::now() < deadline {
            let per_socket = collect_key_fragments::<K>(&sockets, template.public_key(), make_auth);
            if cookies_obtained == 0 {
                attack_started_secs = process_started.elapsed().as_secs_f64();
                deadline = Instant::now() + attack_duration;
            }
            cookies_obtained = per_socket.iter().flatten().count();
            let armed: Vec<(&UdpSocket, &[Vec<u8>])> = sockets
                .iter()
                .zip(&per_socket)
                .filter_map(|(s, f)| f.as_deref().map(|f| (s, f)))
                .collect();
            if armed.is_empty() {
                return Err("server issued no cookies".into());
            }
            let payloads: Vec<&[Vec<u8>]> = armed
                .iter()
                .map(|(_, f)| match kind {
                    FloodKind::Partial => &f[..1],
                    _ => *f,
                })
                .collect();
            packet_bytes = payloads[0][0].len();
            let round_end = (Instant::now() + COOKIE_REFRESH_INTERVAL).min(deadline);
            while Instant::now() < round_end {
                for ((socket, _), fragments) in armed.iter().zip(&payloads) {
                    for fragment in *fragments {
                        if socket.send(fragment).is_ok() {
                            sent += 1;
                        }
                    }
                }
            }
        }
    }

    println!(
        "{}",
        json!({
            "packets_sent": sent,
            "sockets": socket_count,
            "source_ips": source_ips,
            "duration_secs": duration,
            "packet_bytes": packet_bytes,
            "kind": kind.label(),
            "attack_started_secs": attack_started_secs,
            "cookies_obtained": cookies_obtained,
        })
    );
    Ok(())
}

fn print_stats(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    socket.send(STATS_QUERY)?;
    let mut buf = [0u8; RECV_BYTES];
    let len = socket.recv(&mut buf)?;
    let fields: serde_json::Map<String, serde_json::Value> = StatsSnapshot::FIELD_NAMES
        .iter()
        .zip(buf[..len].chunks_exact(8))
        .map(|(name, chunk)| {
            let value = u64::from_le_bytes(chunk.try_into().unwrap());
            (name.to_string(), json!(value))
        })
        .collect();
    println!("{}", serde_json::Value::Object(fields));
    Ok(())
}

const MTU_LIMIT_BYTES: usize = HQCLethe::stateful::wire::MAX_DATAGRAM_BYTES;

struct PacketCost {
    kind: &'static str,
    request_bytes: usize,
    response_bytes: usize,
    response_packets: usize,
}

fn kind_report(kind: &'static str, packets: &[&PacketCost]) -> serde_json::Value {
    let request_total: usize = packets.iter().map(|p| p.request_bytes).sum();
    let response_total: usize = packets.iter().map(|p| p.response_bytes).sum();
    let worst_ratio = packets
        .iter()
        .map(|p| p.response_bytes as f64 / p.request_bytes as f64)
        .fold(0.0, f64::max);
    json!({
        "kind": kind,
        "count": packets.len(),
        "request_bytes": packets.iter().map(|p| p.request_bytes).max().unwrap_or(0),
        "response_bytes": packets.iter().map(|p| p.response_bytes).max().unwrap_or(0),
        "response_packets": packets.iter().map(|p| p.response_packets).sum::<usize>(),
        "request_bytes_total": request_total,
        "response_bytes_total": response_total,
        "amplification_ratio": worst_ratio,
        "amplification_ratio_total": response_total as f64 / request_total as f64,
    })
}

fn deliver_counting<K, A>(
    server: &mut StatefulServer<K, A, OsEntropy>,
    src: SocketAddr,
    datagram: &[u8],
    kind: &'static str,
    replies: &mut Vec<Vec<u8>>,
) -> PacketCost
where
    K: StatefulKem,
    A: HQCLethe::stateful::auth::ServerAuth,
{
    let before = replies.len();
    server.handle(src, datagram, 0, &mut |d: &[u8]| {
        replies.push(d.to_vec());
        true
    });
    let new_replies = &replies[before..];
    PacketCost {
        kind,
        request_bytes: datagram.len(),
        response_bytes: new_replies.iter().map(Vec::len).sum(),
        response_packets: new_replies.len(),
    }
}

fn bandwidth_report<K: StatefulKem + AuthLevel>(name: &str) -> serde_json::Value {
    let keys = HQCLethe::auth::shared_keypair::<K>();
    let pinned = ServerPublicKey::<K>::from_bytes(keys.public.as_bytes().to_vec()).unwrap();
    let auth = MlKemServerAuth::new(keys.secret.clone());
    let mut server = StatefulServer::<K, _, _>::new(ServerConfig::default(), auth, OsEntropy, 0);
    let mut client =
        StatefulClient::<K, _>::new(MlKemClientAuth::new(Arc::new(pinned)), &OsEntropy);
    let src: SocketAddr = "192.0.2.1:40000".parse().unwrap();

    let mut replies = Vec::new();
    let hello = client.hello().to_vec();
    let mut costs = vec![deliver_counting(
        &mut server,
        src,
        &hello,
        "hello",
        &mut replies,
    )];
    let key_datagrams = client.on_server_hello(&replies[0]).unwrap().to_vec();
    replies.clear();
    for datagram in &key_datagrams {
        costs.push(deliver_counting(
            &mut server,
            src,
            datagram,
            "key_fragment",
            &mut replies,
        ));
    }

    let kinds: Vec<_> = ["hello", "key_fragment"]
        .into_iter()
        .map(|kind| {
            let packets: Vec<_> = costs.iter().filter(|c| c.kind == kind).collect();
            kind_report(kind, &packets)
        })
        .collect();
    let packets_sent = costs.len();
    let packets_received = costs.iter().map(|c| c.response_packets).sum::<usize>();
    let total_sent: usize = costs.iter().map(|c| c.request_bytes).sum();
    let total_received: usize = costs.iter().map(|c| c.response_bytes).sum();
    let max_packet = costs
        .iter()
        .map(|c| c.request_bytes)
        .chain(replies.iter().map(Vec::len))
        .max()
        .unwrap_or(0);
    let raw_baseline = K::PUBLIC_KEY_BYTES + K::CIPHERTEXT_BYTES;
    json!({
        "variant": name,
        "packets": kinds,
        "packets_sent": packets_sent,
        "packets_received": packets_received,
        "packets_total": packets_sent + packets_received,
        "total_sent_bytes": total_sent,
        "total_received_bytes": total_received,
        "total_bytes": total_sent + total_received,
        "amplification_ratio_total": total_received as f64 / total_sent as f64,
        "raw_baseline_bytes": raw_baseline,
        "overhead_ratio": (total_sent + total_received) as f64 / raw_baseline as f64,
        "mtu_limit_bytes": MTU_LIMIT_BYTES,
        "max_packet_bytes": max_packet,
        "mtu_ok": max_packet <= MTU_LIMIT_BYTES,
    })
}

fn print_bandwidth_table(reports: &[serde_json::Value]) {
    println!(
        "{:<6} {:<13} {:>5} {:>9} {:>9} {:>6} {:>14} {:>14} {:>8}",
        "level",
        "kind",
        "count",
        "req B",
        "resp B",
        "resp#",
        "req total B",
        "resp total B",
        "resp/req"
    );
    for report in reports {
        for packet in report["packets"].as_array().into_iter().flatten() {
            println!(
                "{:<6} {:<13} {:>5} {:>9} {:>9} {:>6} {:>14} {:>14} {:>8.3}",
                report["variant"].as_str().unwrap_or(""),
                packet["kind"].as_str().unwrap_or(""),
                packet["count"].as_u64().unwrap_or(0),
                packet["request_bytes"].as_u64().unwrap_or(0),
                packet["response_bytes"].as_u64().unwrap_or(0),
                packet["response_packets"].as_u64().unwrap_or(0),
                packet["request_bytes_total"].as_u64().unwrap_or(0),
                packet["response_bytes_total"].as_u64().unwrap_or(0),
                packet["amplification_ratio"].as_f64().unwrap_or(0.0),
            );
        }
        println!(
            "{:<6} packets {} sent + {} received = {}, bytes {} sent + {} received = {}, resp/req {:.3}, raw pk+ct baseline {} B, ratio {:.2}, largest packet {} B (limit {} B)",
            report["variant"].as_str().unwrap_or(""),
            report["packets_sent"],
            report["packets_received"],
            report["packets_total"],
            report["total_sent_bytes"],
            report["total_received_bytes"],
            report["total_bytes"],
            report["amplification_ratio_total"].as_f64().unwrap_or(0.0),
            report["raw_baseline_bytes"],
            report["overhead_ratio"].as_f64().unwrap_or(0.0),
            report["max_packet_bytes"],
            report["mtu_limit_bytes"],
        );
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Args::parse().command {
        Commands::Client {
            addr,
            variant,
            bind_ip,
            server_key,
        } => dispatch_variant!(variant, Scheme =>
            run_client::<Scheme>(&addr, bind_ip, load_server_key(variant, server_key)?)),
        Commands::FloodClient {
            addr,
            variant,
            duration,
            sockets,
            source_ips,
            kind,
            server_key,
        } => dispatch_variant!(variant, Scheme => flood_client::<Scheme>(
            &addr,
            duration,
            sockets,
            source_ips,
            kind,
            load_server_key(variant, server_key)?
        )),
        Commands::Stats { addr } => print_stats(&addr),
        Commands::BandwidthReport { table } => {
            let reports = vec![
                bandwidth_report::<HQCLethe::Hqc1>("hqc1"),
                bandwidth_report::<HQCLethe::Hqc3>("hqc3"),
                bandwidth_report::<HQCLethe::Hqc5>("hqc5"),
            ];
            if table {
                print_bandwidth_table(&reports);
            } else {
                println!("{}", serde_json::to_string_pretty(&reports)?);
            }
            Ok(())
        }
    }
}
