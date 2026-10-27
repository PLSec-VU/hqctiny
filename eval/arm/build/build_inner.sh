set -e
F=${HQC_FEATURE:-hqc-addfft}
T=aarch64-unknown-linux-gnu
export RUSTFLAGS=""
cargo build --release --target $T -p hqclethe-client -p hqclethe-stateful --features quiet,$F 2>&1 | tail -3
cargo build --profile tiny-release --target $T -p hqclethe-server -p hqclethe-stateful --features quiet,$F 2>&1 | tail -3
mkdir -p /out/quiet && cp /target/$T/tiny-release/hqclethe-server /target/$T/tiny-release/hqclethe-server-stateful /target/$T/release/hqclethe-client /target/$T/release/hqclethe-client-stateful /out/quiet/
cargo build --profile tiny-release --target $T -p hqclethe-server -p hqclethe-stateful --features flood-stats,quiet,$F 2>&1 | tail -3
mkdir -p /out/floodstats && cp /target/$T/tiny-release/hqclethe-server /target/$T/tiny-release/hqclethe-server-stateful /out/floodstats/
cargo build --release --target $T --features $F --bin stack-test --bin protocol-breakdown --bin timing-breakdown 2>&1 | tail -3
mkdir -p /out/prof && cp /target/$T/release/stack-test /target/$T/release/protocol-breakdown /target/$T/release/timing-breakdown /out/prof/
mkdir -p /out/bench
cargo bench --no-run --target $T --bench kem_primitives --bench protocol_phases --bench puzzle --bench stateful_baseline --features $F --message-format=json 2>/dev/null | grep -o '"executable":"[^"]*"' | sort -u | tee /out/bench/list.txt
cargo bench --no-run --target $T --bench kem_comparison --features $F,mceliece-ref --message-format=json 2>/dev/null | grep -o '"executable":"[^"]*"' | sort -u | tee -a /out/bench/list.txt
cargo test --release --no-run --target $T --test zero_alloc --features $F --message-format=json 2>/dev/null | grep -o '"executable":"[^"]*"' | sort -u | tee /out/test-list.txt
