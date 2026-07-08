use HQCTiny::math::gf2_9009::Gf2_9009;
use HQCTiny::math::interpolate::{interpolate_newton, load_newton_weights};
use criterion::{Criterion, criterion_group, criterion_main};

fn make_evals<const M: usize>(seed: u64) -> [Gf2_9009; M] {
    let mut evals = [Gf2_9009::zero(); M];
    for (i, e) in evals.iter_mut().enumerate() {
        let mut data = [0u64; 141];
        for (j, word) in data.iter_mut().enumerate() {
            *word = seed
                .wrapping_mul(0x9e3779b97f4a7c15)
                .wrapping_add((i as u64).wrapping_mul(0x6c62272e07bb0142))
                .wrapping_add((j as u64).wrapping_mul(0x94d049bb133111eb));
        }
        *e = Gf2_9009::new(data);
    }
    evals
}

fn bench_m7(c: &mut Criterion) {
    let weights = load_newton_weights::<7>(include_bytes!("../src/math/newton_weights_17669.bin"));
    let evals = make_evals::<7>(0xdeadbeefcafe1234);
    c.bench_function("interpolate_M7", |b| {
        b.iter(|| interpolate_newton::<7>(&weights, &evals))
    });
}

fn bench_m15(c: &mut Criterion) {
    let weights = load_newton_weights::<15>(include_bytes!("../src/math/newton_weights_35851.bin"));
    let evals = make_evals::<15>(0xdeadbeefcafe1234);
    c.bench_function("interpolate_M15", |b| {
        b.iter(|| interpolate_newton::<15>(&weights, &evals))
    });
}

fn bench_m25(c: &mut Criterion) {
    let weights = load_newton_weights::<25>(include_bytes!("../src/math/newton_weights_57637.bin"));
    let evals = make_evals::<25>(0xdeadbeefcafe1234);
    c.bench_function("interpolate_M25", |b| {
        b.iter(|| interpolate_newton::<25>(&weights, &evals))
    });
}

criterion_group!(benches, bench_m7, bench_m15, bench_m25);
criterion_main!(benches);
