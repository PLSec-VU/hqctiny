#[cfg(target_arch = "aarch64")]
mod ops {
    use std::arch::asm;
    use std::hint::black_box;
    use std::time::Instant;

    const ITERATIONS: u64 = 2_000_000;
    const CLOCK_GHZ: f64 = 1.2;

    macro_rules! loop_body {
    ($($line:literal),* $(,)?) => {{
        let start = Instant::now();
        unsafe {
            asm!(
                "2:",
                $($line,)*
                "subs {n}, {n}, #1",
                "b.ne 2b",
                n = inout(reg) black_box(ITERATIONS) => _,
                out("v16") _, out("v17") _, out("v18") _, out("v19") _,
                out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                out("v24") _, out("v25") _, out("v26") _, out("v27") _,
                out("v28") _, out("v29") _, out("v30") _, out("v31") _,
                options(nostack),
            );
        }
        start.elapsed().as_secs_f64()
    }};
}

    fn report(name: &str, instructions_per_iteration: u32, seconds: f64) {
        let cycles =
            seconds * CLOCK_GHZ * 1e9 / (ITERATIONS as f64 * instructions_per_iteration as f64);
        println!("{name:<40} {cycles:6.2} cycles per instruction");
    }

    pub fn run() {
        report(
            "eor.16b x8 independent",
            8,
            loop_body!(
                "eor v24.16b, v24.16b, v16.16b",
                "eor v25.16b, v25.16b, v16.16b",
                "eor v26.16b, v26.16b, v16.16b",
                "eor v27.16b, v27.16b, v16.16b",
                "eor v28.16b, v28.16b, v16.16b",
                "eor v29.16b, v29.16b, v16.16b",
                "eor v30.16b, v30.16b, v16.16b",
                "eor v31.16b, v31.16b, v16.16b",
            ),
        );
        report(
            "eor.8b x8 independent",
            8,
            loop_body!(
                "eor v24.8b, v24.8b, v16.8b",
                "eor v25.8b, v25.8b, v16.8b",
                "eor v26.8b, v26.8b, v16.8b",
                "eor v27.8b, v27.8b, v16.8b",
                "eor v28.8b, v28.8b, v16.8b",
                "eor v29.8b, v29.8b, v16.8b",
                "eor v30.8b, v30.8b, v16.8b",
                "eor v31.8b, v31.8b, v16.8b",
            ),
        );
        report(
            "eor.16b x1 dependent chain",
            8,
            loop_body!(
                "eor v24.16b, v24.16b, v16.16b",
                "eor v24.16b, v24.16b, v17.16b",
                "eor v24.16b, v24.16b, v18.16b",
                "eor v24.16b, v24.16b, v19.16b",
                "eor v24.16b, v24.16b, v20.16b",
                "eor v24.16b, v24.16b, v21.16b",
                "eor v24.16b, v24.16b, v22.16b",
                "eor v24.16b, v24.16b, v23.16b",
            ),
        );
        report(
            "pmull.8h x8 independent",
            8,
            loop_body!(
                "pmull v24.8h, v16.8b, v17.8b",
                "pmull v25.8h, v16.8b, v18.8b",
                "pmull v26.8h, v16.8b, v19.8b",
                "pmull v27.8h, v16.8b, v20.8b",
                "pmull v28.8h, v16.8b, v21.8b",
                "pmull v29.8h, v16.8b, v22.8b",
                "pmull v30.8h, v16.8b, v23.8b",
                "pmull v31.8h, v16.8b, v17.8b",
            ),
        );
        report(
            "pmull.8h x1 dest (WAW chain)",
            8,
            loop_body!(
                "pmull v24.8h, v16.8b, v17.8b",
                "pmull v24.8h, v16.8b, v18.8b",
                "pmull v24.8h, v16.8b, v19.8b",
                "pmull v24.8h, v16.8b, v20.8b",
                "pmull v24.8h, v16.8b, v21.8b",
                "pmull v24.8h, v16.8b, v22.8b",
                "pmull v24.8h, v16.8b, v23.8b",
                "pmull v24.8h, v16.8b, v17.8b",
            ),
        );
        report(
            "pmull then eor, adjacent, same temp",
            16,
            loop_body!(
                "pmull v31.8h, v16.8b, v17.8b",
                "eor v24.16b, v24.16b, v31.16b",
                "pmull v31.8h, v16.8b, v18.8b",
                "eor v25.16b, v25.16b, v31.16b",
                "pmull v31.8h, v16.8b, v19.8b",
                "eor v26.16b, v26.16b, v31.16b",
                "pmull v31.8h, v16.8b, v20.8b",
                "eor v27.16b, v27.16b, v31.16b",
                "pmull v31.8h, v16.8b, v21.8b",
                "eor v28.16b, v28.16b, v31.16b",
                "pmull v31.8h, v16.8b, v22.8b",
                "eor v29.16b, v29.16b, v31.16b",
                "pmull v31.8h, v16.8b, v23.8b",
                "eor v30.16b, v30.16b, v31.16b",
                "pmull v31.8h, v16.8b, v17.8b",
                "eor v24.16b, v24.16b, v31.16b",
            ),
        );
        report(
            "pmull x4 then eor x4, x2 (batched)",
            16,
            loop_body!(
                "pmull v28.8h, v16.8b, v17.8b",
                "pmull v29.8h, v16.8b, v18.8b",
                "pmull v30.8h, v16.8b, v19.8b",
                "pmull v31.8h, v16.8b, v20.8b",
                "eor v24.16b, v24.16b, v28.16b",
                "eor v25.16b, v25.16b, v29.16b",
                "eor v26.16b, v26.16b, v30.16b",
                "eor v27.16b, v27.16b, v31.16b",
                "pmull v28.8h, v16.8b, v21.8b",
                "pmull v29.8h, v16.8b, v22.8b",
                "pmull v30.8h, v16.8b, v23.8b",
                "pmull v31.8h, v16.8b, v17.8b",
                "eor v24.16b, v24.16b, v28.16b",
                "eor v25.16b, v25.16b, v29.16b",
                "eor v26.16b, v26.16b, v30.16b",
                "eor v27.16b, v27.16b, v31.16b",
            ),
        );
        report(
            "pmull x8 then eor x8 (v20..v27 temps)",
            16,
            loop_body!(
                "pmull v20.8h, v16.8b, v17.8b",
                "pmull v21.8h, v16.8b, v18.8b",
                "pmull v22.8h, v16.8b, v19.8b",
                "pmull v23.8h, v16.8b, v17.8b",
                "pmull v24.8h, v16.8b, v18.8b",
                "pmull v25.8h, v16.8b, v19.8b",
                "pmull v26.8h, v16.8b, v17.8b",
                "pmull v27.8h, v16.8b, v18.8b",
                "eor v28.16b, v28.16b, v20.16b",
                "eor v29.16b, v29.16b, v21.16b",
                "eor v30.16b, v30.16b, v22.16b",
                "eor v31.16b, v31.16b, v23.16b",
                "eor v28.16b, v28.16b, v24.16b",
                "eor v29.16b, v29.16b, v25.16b",
                "eor v30.16b, v30.16b, v26.16b",
                "eor v31.16b, v31.16b, v27.16b",
            ),
        );
        report(
            "ext.16b x8 independent",
            8,
            loop_body!(
                "ext v24.16b, v16.16b, v17.16b, #3",
                "ext v25.16b, v16.16b, v17.16b, #5",
                "ext v26.16b, v16.16b, v17.16b, #7",
                "ext v27.16b, v16.16b, v17.16b, #9",
                "ext v28.16b, v16.16b, v17.16b, #11",
                "ext v29.16b, v16.16b, v17.16b, #13",
                "ext v30.16b, v16.16b, v17.16b, #15",
                "ext v31.16b, v16.16b, v17.16b, #1",
            ),
        );
        report(
            "ext.8b x8 independent",
            8,
            loop_body!(
                "ext v24.8b, v16.8b, v17.8b, #3",
                "ext v25.8b, v16.8b, v17.8b, #5",
                "ext v26.8b, v16.8b, v17.8b, #7",
                "ext v27.8b, v16.8b, v17.8b, #1",
                "ext v28.8b, v16.8b, v17.8b, #2",
                "ext v29.8b, v16.8b, v17.8b, #4",
                "ext v30.8b, v16.8b, v17.8b, #6",
                "ext v31.8b, v16.8b, v17.8b, #1",
            ),
        );
        report(
            "tbl.16b (1 reg) x8 independent",
            8,
            loop_body!(
                "tbl v24.16b, {{v16.16b}}, v20.16b",
                "tbl v25.16b, {{v17.16b}}, v20.16b",
                "tbl v26.16b, {{v18.16b}}, v20.16b",
                "tbl v27.16b, {{v19.16b}}, v20.16b",
                "tbl v28.16b, {{v16.16b}}, v21.16b",
                "tbl v29.16b, {{v17.16b}}, v21.16b",
                "tbl v30.16b, {{v18.16b}}, v21.16b",
                "tbl v31.16b, {{v19.16b}}, v21.16b",
            ),
        );
        report(
            "and.16b x8 independent",
            8,
            loop_body!(
                "and v24.16b, v16.16b, v20.16b",
                "and v25.16b, v17.16b, v20.16b",
                "and v26.16b, v18.16b, v20.16b",
                "and v27.16b, v19.16b, v20.16b",
                "and v28.16b, v16.16b, v21.16b",
                "and v29.16b, v17.16b, v21.16b",
                "and v30.16b, v18.16b, v21.16b",
                "and v31.16b, v19.16b, v21.16b",
            ),
        );
        report(
            "eor.16b + ext.16b alternating",
            16,
            loop_body!(
                "eor v24.16b, v24.16b, v16.16b",
                "ext v28.16b, v17.16b, v18.16b, #3",
                "eor v25.16b, v25.16b, v16.16b",
                "ext v29.16b, v17.16b, v18.16b, #5",
                "eor v26.16b, v26.16b, v16.16b",
                "ext v30.16b, v17.16b, v18.16b, #7",
                "eor v27.16b, v27.16b, v16.16b",
                "ext v31.16b, v17.16b, v18.16b, #9",
                "eor v24.16b, v24.16b, v19.16b",
                "ext v28.16b, v17.16b, v18.16b, #11",
                "eor v25.16b, v25.16b, v19.16b",
                "ext v29.16b, v17.16b, v18.16b, #13",
                "eor v26.16b, v26.16b, v19.16b",
                "ext v30.16b, v17.16b, v18.16b, #15",
                "eor v27.16b, v27.16b, v19.16b",
                "ext v31.16b, v17.16b, v18.16b, #1",
            ),
        );
        report(
            "ldr d (L1 hit) x8 + eor.16b x8",
            16,
            loop_body!(
                "ldr d28, [sp, #-16]",
                "eor v24.16b, v24.16b, v16.16b",
                "ldr d29, [sp, #-16]",
                "eor v25.16b, v25.16b, v16.16b",
                "ldr d30, [sp, #-16]",
                "eor v26.16b, v26.16b, v16.16b",
                "ldr d31, [sp, #-16]",
                "eor v27.16b, v27.16b, v16.16b",
                "ldr d28, [sp, #-16]",
                "eor v24.16b, v24.16b, v17.16b",
                "ldr d29, [sp, #-16]",
                "eor v25.16b, v25.16b, v17.16b",
                "ldr d30, [sp, #-16]",
                "eor v26.16b, v26.16b, v17.16b",
                "ldr d31, [sp, #-16]",
                "eor v27.16b, v27.16b, v17.16b",
            ),
        );
        report(
            "fmov d, x + eor.8b",
            16,
            loop_body!(
                "fmov d28, {n}",
                "eor v24.8b, v24.8b, v16.8b",
                "fmov d29, {n}",
                "eor v25.8b, v25.8b, v16.8b",
                "fmov d30, {n}",
                "eor v26.8b, v26.8b, v16.8b",
                "fmov d31, {n}",
                "eor v27.8b, v27.8b, v16.8b",
                "fmov d28, {n}",
                "eor v24.8b, v24.8b, v17.8b",
                "fmov d29, {n}",
                "eor v25.8b, v25.8b, v17.8b",
                "fmov d30, {n}",
                "eor v26.8b, v26.8b, v17.8b",
                "fmov d31, {n}",
                "eor v27.8b, v27.8b, v17.8b",
            ),
        );
    }
}

fn main() {
    #[cfg(target_arch = "aarch64")]
    ops::run();
}
