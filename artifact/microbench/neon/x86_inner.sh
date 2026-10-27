set -e
cd /work
export RUSTFLAGS=""
BENCH_FILTER='hqc[135]_server_(uchunk|vpoint)_request|hqc[135]_client_(keygen|initialize|decap)'
CT_ARGS="control 1 3 5"
bench_requests() {
  taskset -c 12-15 nice cargo bench --features avx2 --bench protocol_phases -- "$BENCH_FILTER" --warm-up-time 2 --measurement-time 4 --noplot 2>&1 | grep -E "^hqc|time:"
}
bench_mul() {
  taskset -c 12-15 nice cargo bench --features avx2 --bench field_mul -- 'poly_mul|field' --warm-up-time 2 --measurement-time 3 --noplot 2>&1 | grep -E "^(poly_mul|field)|time:"
}
constant_time() {
  cargo build --release --features avx2 --bin ct-check 2>&1 | tail -1
  for arg in $CT_ARGS; do
    if valgrind --error-exitcode=9 --track-origins=yes /target/release/ct-check $arg > /tmp/vg.out 2>&1; then status=0; else status=$?; fi
    echo "ct-check $arg valgrind exit=$status $(grep 'ERROR SUMMARY' /tmp/vg.out)"
  done
}
case "$MODE" in
  test-avx2) cargo test --release --features avx2 2>&1 | grep -E "^test result|FAILED|panicked|error" ;;
  test-portable) cargo test --release 2>&1 | grep -E "^test result|FAILED|panicked|error" ;;
  bench-requests) bench_requests ;;
  bench-mul) bench_mul ;;
  ct) constant_time ;;
esac
