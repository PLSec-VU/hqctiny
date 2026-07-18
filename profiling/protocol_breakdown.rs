//! One-off diagnostic: splits the "ours" (non-FFI) share of the round trip
//! reported by timing-breakdown into its constituent phases, so we can see
//! which part of the protocol layer (wire encode/decode, Merkle tree/proof
//! work, server point evaluation, client interpolation) actually dominates.

use HQCLethe::client::{Client, PointResult};
use HQCLethe::encoding::{Packet, decode_packet, encode_packet};
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::server::Server;
use HQCLethe::traits::*;
use rand::Rng;
use std::time::{Duration, Instant};

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
    hreq_wire: Duration,
    server_handshake: Duration,
    hres_wire: Duration,
    client_handshake_response: Duration,
    preq_wire: Duration,
    server_point_eval: Duration,
    pres_wire: Duration,
    client_collect: Duration,
    client_complete: Duration,
}

fn run_once<SCHEME: HqcScheme>(b: &mut Buckets) {
    let server = Server::<SCHEME, _, _>::new(NullSessionStore, Entropy);
    let client = Client::<SCHEME, _, _, _>::new(NullSessionStore, Entropy);

    let t = Instant::now();
    let (client, req) = client.initialize();
    b.client_init += t.elapsed();

    let t = Instant::now();
    let mut buf = vec![0u8; 4096];
    let encoded = encode_packet::<SCHEME>(&Packet::HandshakeRequest(req), &mut buf).unwrap();
    let decoded_req = match decode_packet::<SCHEME>(encoded).unwrap() {
        Packet::HandshakeRequest(r) => r,
        _ => unreachable!(),
    };
    b.hreq_wire += t.elapsed();

    let t = Instant::now();
    let res = server.handle_handshake(decoded_req).unwrap();
    b.server_handshake += t.elapsed();

    let t = Instant::now();
    let mut buf = vec![0u8; 4096];
    let encoded = encode_packet::<SCHEME>(&Packet::HandshakeResponse(res), &mut buf).unwrap();
    let decoded_res = match decode_packet::<SCHEME>(encoded).unwrap() {
        Packet::HandshakeResponse(r) => r,
        _ => unreachable!(),
    };
    b.hres_wire += t.elapsed();

    let t = Instant::now();
    let (mut client, point_reqs) = client.handle_handshake_response(decoded_res).unwrap();
    b.client_handshake_response += t.elapsed();

    for req in point_reqs {
        let t = Instant::now();
        let mut buf = vec![0u8; 8192];
        let encoded = encode_packet::<SCHEME>(&Packet::PointRequest(req), &mut buf).unwrap();
        let decoded_preq = match decode_packet::<SCHEME>(encoded).unwrap() {
            Packet::PointRequest(r) => r,
            _ => unreachable!(),
        };
        b.preq_wire += t.elapsed();

        let t = Instant::now();
        let point_res = server.handle_point_request(decoded_preq).unwrap();
        b.server_point_eval += t.elapsed();

        let t = Instant::now();
        let mut buf = vec![0u8; 8192];
        let encoded = encode_packet::<SCHEME>(&Packet::PointResponse(point_res), &mut buf).unwrap();
        let decoded_pres = match decode_packet::<SCHEME>(encoded).unwrap() {
            Packet::PointResponse(r) => r,
            _ => unreachable!(),
        };
        b.pres_wire += t.elapsed();

        let t = Instant::now();
        let result = client.handle_point_response(decoded_pres).unwrap();
        let elapsed = t.elapsed();
        match result {
            PointResult::Collecting(c) => {
                client = *c;
                b.client_collect += elapsed;
            }
            PointResult::Completed(_, _) => {
                b.client_complete += elapsed;
                break;
            }
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
        + b.hreq_wire
        + b.server_handshake
        + b.hres_wire
        + b.client_handshake_response
        + b.preq_wire
        + b.server_point_eval
        + b.pres_wire
        + b.client_collect
        + b.client_complete;

    let client_init_protocol = per(b.client_init).saturating_sub(keypair_time);
    let client_complete_protocol = per(b.client_complete).saturating_sub(dec_time);

    println!(
        "=== {name} (iters={iters}, round trip total={:.2?}) ===",
        per(total)
    );
    println!(
        "  client_init (total)            {:>9.2?}  [of which keypair FFI {:>9.2?}, merkle/setup {:>9.2?}]",
        per(b.client_init),
        keypair_time,
        client_init_protocol
    );
    println!(
        "  handshake_req wire encode/decode{:>9.2?}",
        per(b.hreq_wire)
    );
    println!(
        "  server handle_handshake         {:>9.2?}",
        per(b.server_handshake)
    );
    println!(
        "  handshake_res wire encode/decode{:>9.2?}",
        per(b.hres_wire)
    );
    println!(
        "  client build point requests     {:>9.2?}",
        per(b.client_handshake_response)
    );
    println!(
        "  point_req wire encode/decode    {:>9.2?}  (summed over all points)",
        per(b.preq_wire)
    );
    println!(
        "  server handle_point_request     {:>9.2?}  (summed over all points)",
        per(b.server_point_eval)
    );
    println!(
        "  point_res wire encode/decode    {:>9.2?}  (summed over all points)",
        per(b.pres_wire)
    );
    println!(
        "  client collect (non-final)      {:>9.2?}  (summed over all but last point)",
        per(b.client_collect)
    );
    println!(
        "  client complete (final)         {:>9.2?}  [of which dec FFI {:>9.2?}, interpolate/combine/serialize {:>9.2?}]",
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
