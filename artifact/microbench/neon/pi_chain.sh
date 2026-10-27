#!/bin/sh
# usage: pi_chain.sh   (on the Pi; binaries in $PI_ROOT/bin/f_{base,fref,ffull,fneon})
PI_ROOT=${PI_ROOT:-/mnt/neon}; export PI_ROOT
cd $PI_ROOT
FIELD_MUL_ARGS="--bench --noplot --warm-up-time 1 --measurement-time 3 --sample-size 30"
for label in base fref; do
  ./pi_run.sh fm_$label env CRITERION_HOME=$PI_ROOT/crit/fm_$label taskset -c 2 $PI_ROOT/bin/f_$label/field_mul $FIELD_MUL_ARGS
done
./pi_bench.sh bfinal $PI_ROOT/bin/f_base
./pi_bench.sh ffull $PI_ROOT/bin/f_ffull
./pi_bench.sh fref2 $PI_ROOT/bin/f_fref
./pi_bench.sh fneon $PI_ROOT/bin/f_fneon
for lvl in hqc1 hqc5; do
  for label in f_base f_ffull; do
    ./pi_run.sh stack_${label}_${lvl}_uchunk taskset -c 2 sh $PI_ROOT/stack_search.sh $PI_ROOT/bin/$label/stack-test $lvl uchunk
  done
done
for arg in control 1 3 5; do
  ./pi_run.sh vg_ffull_$arg ./vgct.sh $PI_ROOT/bin/f_ffull/ct-check $arg
done
for arg in 1 3 5; do
  ./pi_run.sh vg_fref_$arg ./vgct.sh $PI_ROOT/bin/f_fref/ct-check $arg
done
