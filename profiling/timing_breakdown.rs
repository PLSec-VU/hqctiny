#[path = "workload.rs"]
mod workload;

use HQCTiny::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCTiny::traits::EntropyProvider;
use rand::Rng;
use std::time::Instant;

#[derive(Clone)]
struct Entropy;
impl EntropyProvider for Entropy {
    fn random_bytes(&self, out: &mut [u8]) {
        rand::rng().fill_bytes(out);
    }
}

fn measure<SCHEME: HqcScheme>(name: &str, iters: u32) {
    let entropy = Entropy;

    // keypair() alone: pure FFI (c_crypto_kem_keypair), no protocol-layer
    // code around it.
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
    let keypair_time = t0.elapsed();

    // dec() alone: pure FFI (c_crypto_kem_dec). The ciphertext is garbage —
    // `enc` is cfg(test)-gated inside the library and unreachable from this
    // external binary — but HQC's decode path isn't structured to fast-path
    // on validity, so this doesn't skew the timing.
    let ct = vec![0u8; SCHEME::CIPHERTEXT_BYTES];
    let mut ss_dec = vec![0u8; SCHEME::SHARED_SECRET_BYTES];
    let t1 = Instant::now();
    for _ in 0..iters {
        SCHEME::dec(&mut ss_dec, &ct, &sk);
    }
    let dec_time = t1.elapsed();

    // Full in-process round trip: both sides, every Rust protocol-layer
    // operation, plus the same keypair/dec FFI calls measured above.
    let t2 = Instant::now();
    for _ in 0..iters {
        workload::run_round_trip::<SCHEME>();
    }
    let total_time = t2.elapsed();

    let ffi_time = keypair_time + dec_time;
    println!(
        "{name:6} total={:>8.1?}/rt   keypair={:>8.1?}   dec={:>8.1?}   \
         ffi(keypair+dec)={:>5.1}% of round trip   ours={:>5.1}%",
        total_time / iters,
        keypair_time / iters,
        dec_time / iters,
        100.0 * ffi_time.as_secs_f64() / total_time.as_secs_f64(),
        100.0 * (1.0 - ffi_time.as_secs_f64() / total_time.as_secs_f64()),
    );
}

fn main() {
    let iters: u32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);

    measure::<Hqc1>("HQC-1", iters);
    measure::<Hqc3>("HQC-3", iters);
    measure::<Hqc5>("HQC-5", iters);
}
