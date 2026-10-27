#!/bin/sh -e
# usage: pi_verify.sh   Copies the extra build to the Pi and runs, each under the Pi lock with clock/temperature evidence:
# every test binary, the backend-vector cross checks (normal, KS+CRT/Toom, Toom, x86), and the Valgrind ctgrind runs.
. "$(dirname "$0")/lib.sh"
sync_tools; pi_cap_clock
ssh $PI "rm -rf $PI_ROOT/extra; mkdir -p $PI_ROOT/extra $PI_ROOT/results/verify"
play_hold_start
scp -3 -rq "$PLAY:$BUILD_DIR/out/extra/tests" "$PLAY:$BUILD_DIR/out/extra/addfft" "$PLAY:$BUILD_DIR/out/extra/toom" "$PLAY:$BUILD_DIR/out/extra/normal" "$PI:$PI_ROOT/extra/"
scp -3 -q "$PLAY:$BUILD_DIR/out/vectors-x86-default.txt" "$PI:$PI_ROOT/extra/vectors-x86-default.txt"
play_hold_stop
run() { pi_run "$@" || echo "nonzero exit: $1"; }
scp -q "$ARM_SCRIPTS/vgct.sh" $PI:$PI_ROOT/vgct.sh
E=$PI_ROOT/extra
R=$PI_ROOT/results/verify
for t in HQCLethe protocol_flow stateful_auth stateful_baseline zero_alloc; do
  run test_$t "cd $E && taskset -c 1-3 $E/tests/$t --test-threads=1"
done
run vec_emit_normal "$E/normal/backend-vectors emit > $R/vectors_normal.txt"
run vec_emit_addfft "$E/addfft/backend-vectors emit > $R/vectors_addfft.txt"
run vec_emit_toom "$E/toom/backend-vectors emit > $R/vectors_toom.txt"
for label in normal addfft toom; do
  for other in normal addfft toom; do
    run vec_verify_${label}_$other "$E/$label/backend-vectors verify $R/vectors_$other.txt"
  done
  run vec_verify_${label}_x86 "$E/$label/backend-vectors verify $E/vectors-x86-default.txt"
done
VG=$PI_ROOT/vgct.sh
for arg in control classify-control 1 3 5 kem1 kem3 kem5 mlkem1 mlkem3 mlkem5 session1 session3 session5; do
  run vg_addfft_$arg "$VG $E/addfft/ct-check $arg"
done
for arg in kem1 kem3 kem5 session1 session3 session5; do
  run vg_normal_$arg "$VG $E/normal/ct-check $arg"
done
fetch
