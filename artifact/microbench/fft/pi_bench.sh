#!/bin/sh
# usage: pi_bench.sh LABEL BIN_DIR [LEVEL...]   (on the Pi)
LABEL=$1; BIN=$2; shift 2
LEVELS=${*:-1 3 5}
PI_ROOT=${PI_ROOT:-/mnt/fft}; export PI_ROOT
for lvl in $LEVELS; do
  $PI_ROOT/pi_run.sh bench_${LABEL}_hqc${lvl} env CRITERION_HOME=$PI_ROOT/crit/$LABEL taskset -c 2 \
    $BIN/protocol_phases --bench "hqc${lvl}_(server_uchunk_request|server_vpoint_request|client_keygen|client_initialize|client_decap|full_transaction)" --noplot --warm-up-time 2 --measurement-time 4 --sample-size 20
  $PI_ROOT/pi_run.sh kem_${LABEL}_hqc${lvl} env CRITERION_HOME=$PI_ROOT/crit/$LABEL taskset -c 2 \
    $BIN/kem_primitives --bench "hqc${lvl}_(keygen|enc|dec|vect_mul)" --noplot --warm-up-time 2 --measurement-time 4 --sample-size 20
done
