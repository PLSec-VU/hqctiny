//! Distribution of the client puzzle solve time. Usage: puzzle-solve [DIFFICULTY...]

use HQCLethe::puzzle::{self, Challenge, PeerAddress};
use rand::RngExt;
use std::time::{Duration, Instant};

const DEFAULT_DIFFICULTIES: [u8; 4] = [8, 12, 16, 20];
const SAMPLES_UP_TO_DIFFICULTY_16: usize = 1000;
const SAMPLES_ABOVE_DIFFICULTY_16: usize = 200;
const FIXED_TIMESTAMP: u32 = 1_800_000_000;

fn samples_for(difficulty: u8) -> usize {
    if difficulty <= 16 {
        SAMPLES_UP_TO_DIFFICULTY_16
    } else {
        SAMPLES_ABOVE_DIFFICULTY_16
    }
}

fn random_challenge(difficulty: u8) -> (Challenge, PeerAddress, [u8; 32]) {
    let mut rng = rand::rng();
    let key = puzzle::mac_key(&rng.random());
    let peer: PeerAddress = rng.random();
    let challenge = Challenge::issue(&key, &peer, rng.random(), difficulty, FIXED_TIMESTAMP);
    (challenge, peer, rng.random())
}

fn percentile(sorted: &[Duration], fraction: f64) -> Duration {
    sorted[((sorted.len() - 1) as f64 * fraction).round() as usize]
}

fn report(difficulty: u8) {
    let mut times = Vec::new();
    let mut counters = Vec::new();
    for _ in 0..samples_for(difficulty) {
        let (challenge, peer, digest) = random_challenge(difficulty);
        let start = Instant::now();
        let counter = puzzle::solve(&challenge, &peer, &digest);
        times.push(start.elapsed());
        counters.push(counter + 1);
    }
    times.sort();
    let total: Duration = times.iter().sum();
    let mean = total / times.len() as u32;
    let hashes: u64 = counters.iter().sum();
    let hash_rate = hashes as f64 / total.as_secs_f64();
    println!(
        "d={difficulty:<2} n={:<4} min={:?} p10={:?} median={:?} mean={:?} p90={:?} p99={:?} max={:?} hashes/s={:.2}M",
        times.len(),
        times[0],
        percentile(&times, 0.10),
        percentile(&times, 0.50),
        mean,
        percentile(&times, 0.90),
        percentile(&times, 0.99),
        times[times.len() - 1],
        hash_rate / 1e6,
    );
}

fn main() {
    let requested: Vec<u8> = std::env::args()
        .skip(1)
        .map(|arg| arg.parse().expect("difficulty is a number below 256"))
        .collect();
    let difficulties = if requested.is_empty() {
        DEFAULT_DIFFICULTIES.to_vec()
    } else {
        requested
    };
    for difficulty in difficulties {
        report(difficulty);
    }
}
