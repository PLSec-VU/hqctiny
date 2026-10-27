use HQCLethe::blinding;
use HQCLethe::crt::gf2x::{mul_mod, reduce_in_place};
use HQCLethe::crt::scatter::{scatter_buffer_words, scatter_support};
use HQCLethe::crt::server::masked_residue;
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme, HqcSupportParameters};
use criterion::{Criterion, criterion_group, criterion_main};
use rand::Rng;
use std::hint::black_box;

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,pclmulqdq,bmi2")]
fn scatter_wide(support: &[u32], out: &mut [u64]) {
    scatter_support(support, out)
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn scatter_wide(support: &[u32], out: &mut [u64]) {
    scatter_support(support, out)
}

fn bench_parts<S: HqcScheme>(c: &mut Criterion, name: &str) {
    let theta = [7u8; 32];
    let m = vec![9u8; S::PARAM_SECURITY_BYTES];
    let n = S::PARAM_N;
    let n_words = S::VEC_N_SIZE_64;
    let modulus = S::CRT_MODULI[0];
    let words = modulus.words();

    let s_residue = vec![0x5555_5555_5555_5555u64 >> 1; words];
    let mut residue = vec![0u64; words];
    c.bench_function(&format!("{name}_part_masked_residue_total"), |b| {
        b.iter(|| {
            masked_residue::<S>(
                black_box(&theta),
                black_box(&m),
                modulus,
                black_box(&s_residue),
                &mut residue,
            )
        })
    });
    c.bench_function(&format!("{name}_part_sample_supports"), |b| {
        b.iter(|| S::partial_message_encaps_v_support(black_box(&m), black_box(&theta)))
    });
    let support = S::partial_message_encaps_v_support(&m, &theta);
    let mut buf = vec![0u64; 2 * n_words];
    c.bench_function(&format!("{name}_part_scatter"), |b| {
        b.iter(|| unsafe {
            scatter_wide(
                black_box(support.r2()),
                &mut buf[..scatter_buffer_words(n_words)],
            )
        })
    });
    c.bench_function(&format!("{name}_part_reduce_n_bits"), |b| {
        b.iter(|| reduce_in_place(black_box(&mut buf[..n_words]), modulus))
    });
    c.bench_function(&format!("{name}_part_reduce_2n_bits"), |b| {
        b.iter(|| reduce_in_place(black_box(&mut buf[..]), modulus))
    });
    let a: Vec<u64> = (0..words).map(|_| rand::rng().next_u64() >> 1).collect();
    let mut out = vec![0u64; words];
    c.bench_function(&format!("{name}_part_mul_mod"), |b| {
        b.iter(|| mul_mod(black_box(&a), black_box(&a), modulus, &mut out))
    });
    let mut scratch = vec![0u64; n_words];
    c.bench_function(&format!("{name}_part_quotient_mask"), |b| {
        b.iter(|| {
            blinding::generate_quotient_mask(
                black_box(&theta),
                b"crt quotient mask",
                n,
                &mut scratch,
            )
            .len()
        })
    });
    c.bench_function(&format!("{name}_part_code_encode"), |b| {
        b.iter(|| S::code_encode(black_box(&mut scratch), &m))
    });
    c.bench_function(&format!("{name}_part_truncate_word"), |b| {
        b.iter(|| {
            blinding::truncate_mask_word(black_box(&theta), b"crt truncate mask", n, S::PARAM_N1N2)
        })
    });
}

fn bench_all(c: &mut Criterion) {
    bench_parts::<Hqc1>(c, "hqc1");
    bench_parts::<Hqc3>(c, "hqc3");
    bench_parts::<Hqc5>(c, "hqc5");
}

criterion_group!(benches, bench_all);
criterion_main!(benches);
