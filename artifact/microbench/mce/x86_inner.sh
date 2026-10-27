set -e
cd /work
export RUSTFLAGS=""
case "$MODE" in
  test-avx2) cargo test --release --workspace 2>&1 | grep -E "^test result|FAILED|panicked|error" ;;
  test-portable) cargo test --release --workspace 2>&1 | grep -E "^test result|FAILED|panicked|error" ;;
  bench-requests) taskset -c 12-15 nice cargo bench --bench protocol_phases -- 'hqc[135]_server_(uchunk|vpoint)_request|hqc[135]_client_(keygen|initialize|decap)' --warm-up-time 2 --measurement-time 4 --noplot 2>&1 | grep -E "^hqc|time:" ;;
  bench-mul) taskset -c 12-15 nice cargo bench --bench field_mul -- 'poly_mul|field' --warm-up-time 2 --measurement-time 3 --noplot 2>&1 | grep -E "^(poly_mul|field)|time:" ;;
  ct) cargo build --release --bin ct-check 2>&1 | tail -1
      for arg in control 1 3 5; do
        if valgrind --error-exitcode=9 --track-origins=yes /target/release/ct-check $arg > /tmp/vg.out 2>&1; then status=0; else status=$?; fi
        echo "ct-check $arg valgrind exit=$status $(grep 'ERROR SUMMARY' /tmp/vg.out)"
      done ;;
esac
