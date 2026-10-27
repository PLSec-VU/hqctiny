set -e
T=aarch64-unknown-linux-gnu
export RUSTFLAGS="$EXTRA_RUSTFLAGS"
cd /work
copy_executables() {
  listing=$1; destination=$2
  for exe in $(sed 's/"executable":"//;s/"$//' $listing); do
    cp "$exe" $destination/$(basename "$exe" | sed 's/-[0-9a-f]*$//')
  done
}
cargo bench --no-run --target $T --features "$FEATURES" $BENCHES --message-format=json 2>/out/build.log | grep -o '"executable":"[^"]*"' | sort -u > /out/list.txt || true
copy_executables /out/list.txt /out
if [ -n "$BUILD_TESTS" ]; then
  mkdir -p /out/tests
  cargo test --no-run --release --target $T --features "$FEATURES" --message-format=json 2>/out/tests.log | grep -o '"executable":"[^"]*"' | sort -u > /out/tests.txt || true
  for exe in $(sed 's/"executable":"//;s/"$//' /out/tests.txt); do cp "$exe" /out/tests/$(basename "$exe"); done
fi
for bin in $BINS; do
  cargo build --release --target $T --features "$FEATURES" --bin $bin 2>&1 | tail -2
  cp /target/$T/release/$bin /out/$bin
done
if [ -f /out/field_mul ]; then
  aarch64-linux-gnu-objdump -d --no-show-raw-insn /out/field_mul > /out/field_mul.s
fi
