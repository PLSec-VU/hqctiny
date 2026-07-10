#[path = "workload.rs"]
mod workload;

fn main() {
    let iterations: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);

    workload::run_all(iterations);
}
