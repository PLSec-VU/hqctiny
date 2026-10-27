#!/bin/sh
# usage: pi_chain.sh   (on the Pi; binaries in $PI_ROOT/bin/{ref,vm,fft,toom})
PI_ROOT=${PI_ROOT:-/mnt/fft}; export PI_ROOT
VALGRIND_KIT=${VALGRIND_KIT:-/mnt/neon}; export VALGRIND_KIT
cd $PI_ROOT
LABELS="ref vm fft toom"
for label in $LABELS; do ./pi_bench.sh $label $PI_ROOT/bin/$label; done
for label in $LABELS; do
  ./pi_run.sh vec_emit_$label sh -c "$PI_ROOT/bin/$label/backend-vectors emit > $PI_ROOT/results/vectors_$label.txt"
done
for label in $LABELS; do
  for other in $LABELS; do
    ./pi_run.sh vec_verify_${label}_$other $PI_ROOT/bin/$label/backend-vectors verify $PI_ROOT/results/vectors_$other.txt
  done
done
for label in fft toom ref; do
  for arg in control 1 3 5 kem1 kem3 kem5; do
    ./pi_run.sh vg_${label}_$arg ./vgct.sh $PI_ROOT/bin/$label/ct-check $arg
  done
done
