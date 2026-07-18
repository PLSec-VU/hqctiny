#[path = "workload.rs"]
mod workload;

use HQCLethe::hqc::Hqc5;

fn main() {
    workload::run_round_trip::<Hqc5>();
}
