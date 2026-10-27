set -e
T=aarch64-unknown-linux-gnu
export RUSTFLAGS=""
mkdir -p /out/extra/tests /out/extra/addfft /out/extra/toom /out/extra/normal
cargo test --release --no-run --target $T --features hqc-addfft --message-format=json 2>/out/extra/tests-build.log | grep -o '"executable":"[^"]*"' | sort -u | sed 's/"executable":"//;s/"$//' > /out/extra/tests-list.txt
for exe in $(cat /out/extra/tests-list.txt); do
  cp "$exe" /out/extra/tests/$(basename "$exe" | sed 's/-[0-9a-f]*$//')
done
cargo build --profile profiling --target $T --features hqc-addfft --bin ct-check --bin backend-vectors 2>&1 | tail -2
cp /target/$T/profiling/ct-check /target/$T/profiling/backend-vectors /out/extra/addfft/
cargo build --release --target $T --features hqc-addfft-toom --bin backend-vectors 2>&1 | tail -2
cp /target/$T/release/backend-vectors /out/extra/toom/
cargo build --profile profiling --target $T --bin ct-check --bin backend-vectors 2>&1 | tail -2
cp /target/$T/profiling/ct-check /target/$T/profiling/backend-vectors /out/extra/normal/
ls -l /out/extra/*
