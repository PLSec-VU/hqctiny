use HQCLethe::encoding::{Packet, decode_packet, encode_packet};
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::server::Server;
use HQCLethe::traits::*;
use rand::Rng;
use std::net::UdpSocket;
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

fn run_server<SCHEME: HqcScheme + 'static>(port: u16) -> std::io::Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", port))?;
    eprintln!("hqclethe-server listening on 0.0.0.0:{port}");

    let server = Server::<SCHEME, _, _>::new(StatelessSessionStore, OsEntropy);

    {
        let server = server.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(90));
                let new_idx = server.rotate();
                eprintln!("cookie key rotated, new active index: {new_idx}");
            }
        });
    }

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
                    return Err(e);
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

        let packet = match decode_packet::<SCHEME>(&buf[..len]) {
            Ok(p) => p,
            Err(_) => continue,
        };

        match packet {
            Packet::HandshakeRequest(req) => {
                if let Ok(res) = server.handle_handshake(req) {
                    let mut resp_buf = [0u8; 2048];
                    if let Ok(encoded) =
                        encode_packet::<SCHEME>(&Packet::HandshakeResponse(res), &mut resp_buf)
                        && socket.send_to(encoded, addr).is_ok()
                    {
                        record_response_sent();
                    }
                }
            }
            Packet::PointRequest(req) => {
                if let Ok(res) = server.handle_point_request(req) {
                    let mut resp_buf = [0u8; 2048];
                    if let Ok(encoded) =
                        encode_packet::<SCHEME>(&Packet::PointResponse(res), &mut resp_buf)
                        && socket.send_to(encoded, addr).is_ok()
                    {
                        record_response_sent();
                    }
                }
            }
            _ => {}
        }
    }
}

fn usage() -> ! {
    eprintln!("usage: hqclethe-server [--port PORT] [--variant hqc1|hqc3|hqc5]");
    std::process::exit(2);
}

fn main() -> std::io::Result<()> {
    let mut port: u16 = 12345;
    let mut variant = "hqc1".to_string();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => {
                port = args
                    .next()
                    .unwrap_or_else(|| usage())
                    .parse()
                    .unwrap_or_else(|_| usage())
            }
            "--variant" => variant = args.next().unwrap_or_else(|| usage()),
            _ => usage(),
        }
    }

    match variant.as_str() {
        "hqc1" => run_server::<Hqc1>(port),
        "hqc3" => run_server::<Hqc3>(port),
        "hqc5" => run_server::<Hqc5>(port),
        _ => usage(),
    }
}
