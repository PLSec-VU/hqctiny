use HQCLethe::auth::ServerSecretKey;
use HQCLethe::encoding::MAX_UDP_PAYLOAD;
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::limits::COOKIE_ROTATION_SECS;
use HQCLethe::replay::{ReplayConfig, ReplaySizing};
use HQCLethe::server::Server;
use HQCLethe::sockets::{bind_udp_workers, runs_on_calling_thread, worker_thread};
use HQCLethe::traits::*;
use rand::Rng;
use std::net::{SocketAddr, UdpSocket};
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::mpsc;
use std::time::Duration;

/// Answers a magic-byte probe (see FLOOD_STATS_QUERY below) with the
/// current successfully-sent-response count instead of attempting to
/// decode it as a protocol packet. Distinguishing it from real traffic by
/// exact byte match rather than length or a header bit is deliberate: it
/// costs nothing extra here, and means this can never collide with a
/// legitimate encoded packet regardless of future wire-format changes.
#[cfg(feature = "flood-stats")]
static RESPONSES_SENT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(feature = "flood-stats")]
const FLOOD_STATS_QUERY: &[u8] = b"HQCLETHE_FLOOD_STATS_QUERY_V1";

#[cfg(feature = "flood-stats")]
fn record_response_sent() {
    RESPONSES_SENT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}
#[cfg(not(feature = "flood-stats"))]
fn record_response_sent() {}

#[derive(Clone)]
struct OsEntropy;
impl EntropyProvider for OsEntropy {
    fn random_bytes(&self, out: &mut [u8]) {
        rand::rng().fill_bytes(out);
    }
}

/// The derived session key is a hand-off point to whatever the deployment
/// does next (forward to an application, log, etc). Holding it in server
/// RAM would reintroduce the per-client state this protocol is designed to
/// avoid, so this implementation intentionally discards it after a single
/// transient print (not stored anywhere, so statelessness holds). Build
/// with `--features quiet` to compile that print out entirely (a true
/// nop, not just a suppressed print) for benchmarking, where the extra
/// write syscall and formatting would otherwise skew CPU/RSS/syscall
/// measurements (see eval/scripts/dos_flood.py).
#[derive(Clone, Default)]
struct StatelessSessionStore;
impl SessionStore for StatelessSessionStore {
    fn save_session(&self, k_session: [u8; 32]) {
        print_session_key(&k_session);
    }
}

#[cfg(not(feature = "quiet"))]
fn print_session_key(k_session: &[u8; 32]) {
    use std::fmt::Write;
    let mut hex = String::with_capacity(k_session.len() * 2);
    for b in k_session {
        let _ = write!(hex, "{b:02x}");
    }
    eprintln!("session key: {hex}");
}

#[cfg(feature = "quiet")]
fn print_session_key(_k_session: &[u8; 32]) {}

type StatelessServer<SCHEME> = Server<SCHEME, StatelessSessionStore, OsEntropy>;

#[derive(Default)]
struct ReplayOptions {
    disabled: bool,
    false_positive_rate: Option<f64>,
    max_rate: Option<u32>,
    duplicates: Option<u8>,
}

impl ReplayOptions {
    fn sizing<SCHEME: HqcScheme>(
        &self,
        cookie_rotation_secs: u32,
    ) -> std::io::Result<Option<ReplaySizing>> {
        if self.disabled {
            return Ok(None);
        }
        let defaults = ReplayConfig::for_scheme::<SCHEME>();
        let config = ReplayConfig {
            rotation_secs: cookie_rotation_secs,
            false_positive_rate: self
                .false_positive_rate
                .unwrap_or(defaults.false_positive_rate),
            max_rate: self.max_rate.unwrap_or(defaults.max_rate),
            duplicates: self.duplicates.unwrap_or(defaults.duplicates),
        };
        config
            .sizing()
            .map(Some)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))
    }
}

struct Options {
    port: u16,
    variant: String,
    key_path: Option<String>,
    workers: NonZeroUsize,
    worker_stack_kib: Option<NonZeroUsize>,
    puzzle_difficulty: u8,
    cookie_rotation_secs: NonZeroU32,
    replay: ReplayOptions,
}

fn announce_replay_filter(sizing: &Option<ReplaySizing>, workers: NonZeroUsize) {
    match sizing {
        Some(sizing) => eprintln!(
            "{}; {} workers use {:.1} KiB in total",
            sizing.describe(),
            workers,
            (sizing.memory_bytes() * workers.get()) as f64 / 1024.0
        ),
        None => eprintln!("replay filter off"),
    }
}

fn with_replay_filter<SCHEME: HqcScheme>(
    server: StatelessServer<SCHEME>,
    sizing: Option<ReplaySizing>,
) -> StatelessServer<SCHEME> {
    match sizing {
        Some(sizing) => server.with_replay_filter(sizing),
        None => server,
    }
}

fn run_server<SCHEME: HqcScheme + 'static>(options: Options) -> std::io::Result<()> {
    let key_path = options
        .key_path
        .unwrap_or_else(|| format!("server-{}.sk", options.variant));
    let auth_key =
        ServerSecretKey::<SCHEME>::from_bytes(std::fs::read(&key_path)?).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{key_path} is not a secret key for this variant"),
            )
        })?;
    let rotation_secs = options.cookie_rotation_secs.get();
    let replay_sizing = options.replay.sizing::<SCHEME>(rotation_secs)?;

    let sockets = bind_udp_workers(
        SocketAddr::from(([0, 0, 0, 0], options.port)),
        options.workers,
    )?;
    eprintln!(
        "hqclethe-server listening on 0.0.0.0:{} with {} workers",
        options.port, options.workers
    );
    eprintln!("cookie key rotates every {rotation_secs} s");
    announce_replay_filter(&replay_sizing, options.workers);

    let server = StatelessServer::<SCHEME>::new(StatelessSessionStore, OsEntropy, auth_key)
        .with_puzzle_difficulty(options.puzzle_difficulty)
        .with_puzzle_max_age_secs(rotation_secs);

    {
        let server = server.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(rotation_secs.into()));
                let new_idx = server.rotate();
                eprintln!("cookie key rotated, new active index: {new_idx}");
            }
        });
    }

    if runs_on_calling_thread(sockets.len(), options.worker_stack_kib) {
        let server = with_replay_filter(server, replay_sizing);
        return Err(serve_socket(&sockets[0], &server));
    }
    let (failed, first_failure) = mpsc::channel();
    for socket in sockets {
        let server = with_replay_filter(server.clone(), replay_sizing);
        let failed = failed.clone();
        worker_thread(options.worker_stack_kib).spawn(move || {
            let _ = failed.send(serve_socket(&socket, &server));
        })?;
    }
    Err(first_failure
        .recv()
        .expect("a worker reports before it exits"))
}

/// Answers datagrams on `socket` until receiving fails for good.
fn serve_socket<SCHEME: HqcScheme>(
    socket: &UdpSocket,
    server: &StatelessServer<SCHEME>,
) -> std::io::Error {
    // recv_from can fail transiently (EINTR, or a queued ICMP error from an
    // earlier send_to), and one unreachable peer shouldn't take the server
    // down. The cap stops a permanently broken socket spinning here instead.
    const MAX_CONSECUTIVE_RECV_ERRORS: u32 = 64;
    let mut consecutive_errors: u32 = 0;

    let mut buf = [0u8; 4096];
    loop {
        let (len, addr) = match socket.recv_from(&mut buf) {
            Ok(v) => {
                consecutive_errors = 0;
                v
            }
            Err(e) => {
                consecutive_errors += 1;
                if consecutive_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                    eprintln!("recv_from failed {consecutive_errors} times in a row, giving up");
                    return e;
                }
                if e.kind() != std::io::ErrorKind::Interrupted {
                    eprintln!("recv_from error (skipping datagram): {e}");
                }
                continue;
            }
        };

        #[cfg(feature = "flood-stats")]
        if buf[..len] == *FLOOD_STATS_QUERY {
            let count = RESPONSES_SENT.load(std::sync::atomic::Ordering::Relaxed);
            let _ = socket.send_to(&count.to_le_bytes(), addr);
            continue;
        }

        let mut response = [0u8; MAX_UDP_PAYLOAD];
        if let Ok(response_len) = server.handle_packet(addr.ip(), &buf[..len], &mut response)
            && socket.send_to(&response[..response_len], addr).is_ok()
        {
            record_response_sent();
        }
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: hqclethe-server [--port PORT] [--variant hqc1|hqc3|hqc5] [--key SECRET_KEY_FILE] [--workers N] [--worker-stack-kib KIB] [--puzzle-difficulty BITS] [--cookie-rotation SECS] [--replay-fp RATE] [--replay-rate PER_SECOND] [--replay-duplicates N] [--no-replay-filter]"
    );
    std::process::exit(2);
}

fn parsed_value<T: std::str::FromStr>(args: &mut impl Iterator<Item = String>) -> T {
    args.next()
        .unwrap_or_else(|| usage())
        .parse()
        .unwrap_or_else(|_| usage())
}

fn main() -> std::io::Result<()> {
    let mut options = Options {
        port: 12345,
        variant: "hqc1".to_string(),
        key_path: None,
        workers: NonZeroUsize::MIN,
        worker_stack_kib: None,
        puzzle_difficulty: 0,
        cookie_rotation_secs: NonZeroU32::new(COOKIE_ROTATION_SECS)
            .expect("the default rotation period is not zero"),
        replay: ReplayOptions::default(),
    };

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => options.port = parsed_value(&mut args),
            "--variant" => options.variant = args.next().unwrap_or_else(|| usage()),
            "--key" => options.key_path = Some(args.next().unwrap_or_else(|| usage())),
            "--workers" => options.workers = parsed_value(&mut args),
            "--worker-stack-kib" => options.worker_stack_kib = Some(parsed_value(&mut args)),
            "--puzzle-difficulty" => options.puzzle_difficulty = parsed_value(&mut args),
            "--cookie-rotation" => options.cookie_rotation_secs = parsed_value(&mut args),
            "--replay-fp" => options.replay.false_positive_rate = Some(parsed_value(&mut args)),
            "--replay-rate" => options.replay.max_rate = Some(parsed_value(&mut args)),
            "--replay-duplicates" => options.replay.duplicates = Some(parsed_value(&mut args)),
            "--no-replay-filter" => options.replay.disabled = true,
            _ => usage(),
        }
    }

    match options.variant.as_str() {
        "hqc1" => run_server::<Hqc1>(options),
        "hqc3" => run_server::<Hqc3>(options),
        "hqc5" => run_server::<Hqc5>(options),
        _ => usage(),
    }
}
