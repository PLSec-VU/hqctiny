set -e
cargo build --release -p hqclethe-client -p hqclethe-stateful --features quiet,avx2 2>&1 | tail -3
mkdir -p /out/x86 && cp /target-x86/release/hqclethe-client /target-x86/release/hqclethe-client-stateful /out/x86/
