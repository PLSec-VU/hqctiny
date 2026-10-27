set -e
cd /work
export RUSTFLAGS=""
for features in "" "avx2" "hqc-addfft"; do
  echo "=== features: [$features]"
  cargo test --release --workspace --features "$features" 2>&1 | grep -E "^test result|FAILED|panicked|^error|cannot find|undefined reference|multiple definition|Running" || true
done
echo "=== backend vectors"
cargo build --release --bin backend-vectors 2>&1 | grep -E "^error" || true
/target/release/backend-vectors emit > /out/vectors-x86-default.txt
cargo build --release --features avx2 --bin backend-vectors 2>&1 | grep -E "^error" || true
/target/release/backend-vectors emit > /out/vectors-x86-avx2.txt
cargo build --release --features hqc-addfft --bin backend-vectors 2>&1 | grep -E "^error" || true
/target/release/backend-vectors emit > /out/vectors-x86-addfft.txt
cmp /out/vectors-x86-default.txt /out/vectors-x86-avx2.txt && echo "x86 default == avx2 vectors"
cmp /out/vectors-x86-default.txt /out/vectors-x86-addfft.txt && echo "x86 default == addfft vectors"
