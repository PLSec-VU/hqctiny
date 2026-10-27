set -e
cd /work
export RUSTFLAGS=""
FEATURE_SETS="|avx2|hqc-addfft"
TEST_FILTER="^test result|FAILED|panicked|^error|warning: unused|cannot find|undefined reference|multiple definition"
test_feature_set() {
  features=$1
  echo "=== features: [$features]"
  cargo test --release --features "$features" 2>&1 | grep -E "$TEST_FILTER" | head -40 || true
}
emit_vectors() {
  features=$1; output=$2
  cargo build --release --features "$features" --bin backend-vectors 2>&1 | grep -E "^error" | head || true
  /target/release/backend-vectors emit > $output || echo "emit failed ($features)"
}
OLD_IFS=$IFS; IFS="|"
for features in $FEATURE_SETS; do test_feature_set "$features"; done
IFS=$OLD_IFS
echo "=== backend vectors"
emit_vectors "" /out/vectors-default.txt
emit_vectors hqc-addfft /out/vectors-addfft.txt
cmp /out/vectors-default.txt /out/vectors-addfft.txt && echo "x86 vectors identical" || echo "x86 vectors differ or missing"
