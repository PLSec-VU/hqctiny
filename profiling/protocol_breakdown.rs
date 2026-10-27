//! One-off diagnostic: splits the "ours" (non-FFI) share of the round trip
//! reported by timing-breakdown into its constituent phases, so we can see
//! which part of the protocol layer (s residues, server u and v
//! computation, client reconstruction) actually dominates.

use HQCLethe::auth::shared_keypair;
use HQCLethe::client::{Client, Progress};
use HQCLethe::encoding::{Kind, MAX_UDP_PAYLOAD};
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::server::Server;
use HQCLethe::traits::*;
use rand::Rng;
use std::time::{Duration, Instant};

const PEER: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

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

#[derive(Default)]
struct Buckets {
    client_init: Duration,
    server_handshake: Duration,
    client_handshake_response: Duration,
    server_uchunk: Duration,
    server_vresidue: Duration,
    client_collect: Duration,
    client_complete: Duration,
}

fn run_once<SCHEME: HqcScheme>(b: &mut Buckets) {
    let keys = shared_keypair::<SCHEME>();
    let server = Server::<SCHEME, _, _>::new(NullSessionStore, Entropy, keys.secret.clone());
    let client = Client::<SCHEME, _, _, _>::new(NullSessionStore, Entropy);
    let mut out = [0u8; MAX_UDP_PAYLOAD];

    let t = Instant::now();
    let (client, request) = client.initialize(&keys.public);
    b.client_init += t.elapsed();

    let t = Instant::now();
    let len = server.handle_packet(PEER, &request, &mut out).unwrap();
    b.server_handshake += t.elapsed();

    let t = Instant::now();
    let mut client = client.handle_handshake_response(&out[..len]).unwrap();
    b.client_handshake_response += t.elapsed();

    let requests = client.requests().to_vec();
    for request in requests {
        let t = Instant::now();
        let len = server
            .handle_packet(PEER, &request.bytes, &mut out)
            .unwrap();
        let elapsed = t.elapsed();
        match request.kind {
            Kind::UChunk => b.server_uchunk += elapsed,
            _ => b.server_vresidue += elapsed,
        }

        let t = Instant::now();
        let progress = client.handle_response(&out[..len]).unwrap();
        let elapsed = t.elapsed();
        match progress {
            Progress::Complete(_) => {
                b.client_complete += elapsed;
                break;
            }
            _ => b.client_collect += elapsed,
        }
    }
}

fn measure<SCHEME: HqcScheme>(name: &str, iters: u32) {
    // Isolate the FFI-only costs the same way timing-breakdown.rs does, so
    // client_init and client_complete can be split into "FFI" vs "ours".
    let entropy = Entropy;
    let mut pk = vec![0u8; SCHEME::PUBLIC_KEY_BYTES];
    let mut sk = vec![0u8; SCHEME::SECRET_KEY_BYTES];
    let mut ent = [0u8; 48];
    let t0 = Instant::now();
    for _ in 0..iters {
        entropy.random_bytes(&mut ent);
        unsafe {
            SCHEME::keypair(&ent, &mut pk, &mut sk);
        }
    }
    let keypair_time = t0.elapsed() / iters;

    let ct = vec![0u8; SCHEME::CIPHERTEXT_BYTES];
    let mut ss_dec = vec![0u8; SCHEME::SHARED_SECRET_BYTES];
    let t1 = Instant::now();
    for _ in 0..iters {
        SCHEME::dec(&mut ss_dec, &ct, &sk);
    }
    let dec_time = t1.elapsed() / iters;

    let mut b = Buckets::default();
    for _ in 0..iters {
        run_once::<SCHEME>(&mut b);
    }

    let per = |d: Duration| d / iters;
    let total = b.client_init
        + b.server_handshake
        + b.client_handshake_response
        + b.server_uchunk
        + b.server_vresidue
        + b.client_collect
        + b.client_complete;

    let client_init_protocol = per(b.client_init).saturating_sub(keypair_time);
    let client_complete_protocol = per(b.client_complete).saturating_sub(dec_time);

    println!(
        "=== {name} (iters={iters}, round trip total={:.2?}) ===",
        per(total)
    );
    println!(
        "  client_init (total)            {:>9.2?}  [of which keypair FFI {:>9.2?}, s evals/setup {:>9.2?}]",
        per(b.client_init),
        keypair_time,
        client_init_protocol
    );
    println!(
        "  server handle_handshake         {:>9.2?}",
        per(b.server_handshake)
    );
    println!(
        "  client verify + build requests  {:>9.2?}",
        per(b.client_handshake_response)
    );
    println!(
        "  server u-chunk requests         {:>9.2?}  (summed over all chunks)",
        per(b.server_uchunk)
    );
    println!(
        "  server v-residue requests         {:>9.2?}  (summed over all points)",
        per(b.server_vresidue)
    );
    println!(
        "  client collect (non-final)      {:>9.2?}  (summed over all but last response)",
        per(b.client_collect)
    );
    println!(
        "  client complete (final)         {:>9.2?}  [of which dec FFI {:>9.2?}, reconstruct/serialize {:>9.2?}]",
        per(b.client_complete),
        dec_time,
        client_complete_protocol
    );
    println!();
}

fn main() {
    let iters: u32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2000);
    measure::<Hqc1>("HQC-1", iters);
    measure::<Hqc3>("HQC-3", (iters / 4).max(1));
    measure::<Hqc5>("HQC-5", (iters / 12).max(1));
}
