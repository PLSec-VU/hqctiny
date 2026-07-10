use HQCTiny::encoding::{Packet, decode_packet, encode_packet};
use HQCTiny::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCTiny::server::Server;
use HQCTiny::traits::*;
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
const FLOOD_STATS_QUERY: &[u8] = b"HQCTINY_FLOOD_STATS_QUERY_V1";

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
    eprintln!("hqctiny-server listening on 0.0.0.0:{port}");

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

    let mut buf = [0u8; 4096];
    loop {
        let (len, addr) = socket.recv_from(&mut buf)?;

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
                    {
                        if socket.send_to(encoded, addr).is_ok() {
                            record_response_sent();
                        }
                    }
                }
            }
            Packet::PointRequest(req) => {
                if let Ok(res) = server.handle_point_request(req) {
                    let mut resp_buf = [0u8; 2048];
                    if let Ok(encoded) =
                        encode_packet::<SCHEME>(&Packet::PointResponse(res), &mut resp_buf)
                    {
                        if socket.send_to(encoded, addr).is_ok() {
                            record_response_sent();
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn usage() -> ! {
    eprintln!("usage: hqctiny-server [--port PORT] [--variant hqc1|hqc3|hqc5]");
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
