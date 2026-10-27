#!/bin/sh -e
# usage: build_all.sh TREE_WITH_NEON TREE_BASE   (checkouts of the sp27-neon head and of 46efa02)
STUDY=neon
HERE=$(cd "$(dirname "$0")" && pwd)
SYNC=$HERE/../common/sync_build.sh
export STUDY
NEON_TREE=$1; BASE_TREE=$2
BENCH='--bench protocol_phases --bench field_mul'
STUDY=$STUDY $SYNC $NEON_TREE fref "$BENCH" ct-check reference-gf2x ''
STUDY=$STUDY $SYNC $NEON_TREE ffull "$BENCH" ct-check '' ''
STUDY=$STUDY $SYNC $BASE_TREE base "$BENCH" '' '' ''
STUDY=$STUDY $SYNC $NEON_TREE fneon '--bench protocol_phases' '' '' '--cfg chacha20_force_neon'
