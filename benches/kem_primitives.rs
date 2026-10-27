//! Microbenchmarks for the raw HQC FFI primitives: keypair generation,
//! monolithic encapsulation, decapsulation and the polynomial multiply. The
//! protocol itself never calls monolithic encapsulation; see
//! benches/protocol_phases.rs for the phased work it performs instead.

use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::traits::EntropyProvider;
use criterion::{Criterion, criterion_group, criterion_main};
use rand::Rng;

#[derive(Clone)]
struct Entropy;
impl EntropyProvider for Entropy {
    fn random_bytes(&self, out: &mut [u8]) {
        rand::rng().fill_bytes(out);
    }
}

fn bench_keygen<SCHEME: HqcScheme>(c: &mut Criterion, name: &str) {
    let entropy = Entropy;
    let mut pk = vec![0u8; SCHEME::PUBLIC_KEY_BYTES];
    let mut sk = vec![0u8; SCHEME::SECRET_KEY_BYTES];
    let mut ent = [0u8; 48];

    c.bench_function(&format!("{name}_keygen"), |b| {
        b.iter(|| {
            entropy.random_bytes(&mut ent);
            unsafe {
                SCHEME::keypair(&ent, &mut pk, &mut sk);
            }
        })
    });
}

fn bench_dec<SCHEME: HqcScheme>(c: &mut Criterion, name: &str) {
    let entropy = Entropy;
    let mut pk = vec![0u8; SCHEME::PUBLIC_KEY_BYTES];
    let mut sk = vec![0u8; SCHEME::SECRET_KEY_BYTES];
    let mut ent = [0u8; 48];
    entropy.random_bytes(&mut ent);
    unsafe {
        SCHEME::keypair(&ent, &mut pk, &mut sk);
    }

    // A garbage ciphertext still exercises the full decode path; HQC's
    // decoder isn't structured to fast-path on validity (see
    // profiling/timing_breakdown.rs for the same rationale).
    let ct = vec![0u8; SCHEME::CIPHERTEXT_BYTES];
    let mut ss = vec![0u8; SCHEME::SHARED_SECRET_BYTES];

    c.bench_function(&format!("{name}_dec"), |b| {
        b.iter(|| {
            SCHEME::dec(&mut ss, &ct, &sk);
        })
    });
}

fn bench_enc<SCHEME: HqcScheme>(c: &mut Criterion, name: &str) {
    let entropy = Entropy;
    let mut pk = vec![0u8; SCHEME::PUBLIC_KEY_BYTES];
    let mut sk = vec![0u8; SCHEME::SECRET_KEY_BYTES];
    let mut ent = [0u8; 48];
    entropy.random_bytes(&mut ent);
    unsafe {
        SCHEME::keypair(&ent, &mut pk, &mut sk);
    }
    let mut ct = vec![0u8; SCHEME::CIPHERTEXT_BYTES];
    let mut ss = vec![0u8; SCHEME::SHARED_SECRET_BYTES];

    c.bench_function(&format!("{name}_enc"), |b| {
        b.iter(|| {
            entropy.random_bytes(&mut ent);
            unsafe {
                SCHEME::enc(&ent, &mut ct, &mut ss, &pk);
            }
        })
    });
}

fn bench_vect_mul<SCHEME: HqcScheme>(c: &mut Criterion, name: &str) {
    let mut a = vec![0u64; SCHEME::VEC_N_SIZE_64];
    let mut b = vec![0u64; SCHEME::VEC_N_SIZE_64];
    let mut product = vec![0u64; SCHEME::VEC_N_SIZE_64];
    rand::rng().fill_bytes(bytemuck::cast_slice_mut(&mut a));
    rand::rng().fill_bytes(bytemuck::cast_slice_mut(&mut b));
    let top_word = SCHEME::PARAM_N % 64;
    for operand in [&mut a, &mut b] {
        *operand.last_mut().unwrap() &= (1u64 << top_word) - 1;
    }

    c.bench_function(&format!("{name}_vect_mul"), |bencher| {
        bencher.iter(|| SCHEME::ring_multiply(&mut product, &a, &b))
    });
}

fn bench_hqc1(c: &mut Criterion) {
    bench_keygen::<Hqc1>(c, "hqc1");
    bench_dec::<Hqc1>(c, "hqc1");
    bench_enc::<Hqc1>(c, "hqc1");
    bench_vect_mul::<Hqc1>(c, "hqc1");
}

fn bench_hqc3(c: &mut Criterion) {
    bench_keygen::<Hqc3>(c, "hqc3");
    bench_dec::<Hqc3>(c, "hqc3");
    bench_enc::<Hqc3>(c, "hqc3");
    bench_vect_mul::<Hqc3>(c, "hqc3");
}

fn bench_hqc5(c: &mut Criterion) {
    bench_keygen::<Hqc5>(c, "hqc5");
    bench_dec::<Hqc5>(c, "hqc5");
    bench_enc::<Hqc5>(c, "hqc5");
    bench_vect_mul::<Hqc5>(c, "hqc5");
}

criterion_group!(benches, bench_hqc1, bench_hqc3, bench_hqc5);
criterion_main!(benches);
