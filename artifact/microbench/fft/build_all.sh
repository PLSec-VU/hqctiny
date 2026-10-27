#!/bin/sh -e
# usage: build_all.sh TREE_FFT TREE_VM   (TREE_FFT: sp27-fft head; TREE_VM: scratch-fft-vm head)
HERE=$(cd "$(dirname "$0")" && pwd)
export STUDY=fft
SYNC=$HERE/../common/sync_build.sh
BENCHES='--bench protocol_phases --bench kem_primitives'
BINS='ct-check backend-vectors'
$SYNC $1 ref "$BENCHES" "$BINS" ''
$SYNC $1 fft "$BENCHES" "$BINS" 'hqc-addfft'
$SYNC $1 toom "$BENCHES" "$BINS" 'hqc-addfft-toom'
$SYNC $2 vm "$BENCHES" "$BINS" ''
