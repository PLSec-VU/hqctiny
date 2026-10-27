#!/bin/sh
# usage: pi_chain.sh   (on the Pi; binaries in $PI_ROOT/bin/{base,vec,head,head-tests})
PI_ROOT=${PI_ROOT:-/mnt/mce}; export PI_ROOT
VALGRIND_KIT=${VALGRIND_KIT:-/mnt/neon}; export VALGRIND_KIT
cd $PI_ROOT
B=$PI_ROOT/bin
CRITERION_HOME=$PI_ROOT/crit; export CRITERION_HOME
./pi_run.sh mceliece_bench taskset -c 2 $B/head/mceliece-bench
for label in base vec head; do
  ./pi_run.sh phases_$label env CRITERION_HOME=$PI_ROOT/crit/$label taskset -c 2 $B/$label/protocol_phases \
    --bench 'hqc[135]_(server_handshake|server_mceliece_decap|client_mceliece_encap|full_transaction)$' --noplot --warm-up-time 2 --measurement-time 4 --sample-size 20
done
for path in $B/head-tests/HQCLethe-* $B/head-tests/protocol_flow-* $B/head-tests/stateful_auth-* $B/head-tests/stateful_baseline-* $B/head-tests/zero_alloc-*; do
  t=$(basename $path)
  ./pi_run.sh test_$t sh -c "cd $PI_ROOT/src && taskset -c 1-3 $B/head-tests/$t --test-threads=1"
done
for arg in control mceliece1 mceliece3 mceliece5; do
  ./pi_run.sh vg_$arg ./vgct.sh $B/head/ct-check $arg
done
