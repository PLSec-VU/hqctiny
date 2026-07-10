#[path = "workload.rs"]
mod workload;

use HQCTiny::hqc::Hqc5;

fn main() {
    workload::run_round_trip::<Hqc5>();
}
