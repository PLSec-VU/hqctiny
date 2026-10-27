set -e
F=${HQC_FEATURE:-hqc-addfft}
T=aarch64-unknown-linux-gnu
export RUSTFLAGS=""
cargo build --release --target $T -p hqclethe-client -p hqclethe-stateful --features quiet,$F 2>&1 | tail -3
cargo build --profile tiny-release --target $T -p hqclethe-server -p hqclethe-stateful --features quiet,$F 2>&1 | tail -3
mkdir -p /out/arm-quiet && cp /target/$T/tiny-release/hqclethe-server /target/$T/tiny-release/hqclethe-server-stateful /target/$T/release/hqclethe-client /target/$T/release/hqclethe-client-stateful /out/arm-quiet/
cargo build --profile tiny-release --target $T -p hqclethe-stateful --features flood-stats,quiet,$F 2>&1 | tail -3
mkdir -p /out/arm-floodstats && cp /target/$T/tiny-release/hqclethe-server-stateful /out/arm-floodstats/
