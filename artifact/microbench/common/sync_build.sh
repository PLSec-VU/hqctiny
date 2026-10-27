#!/bin/sh -e
# usage: sync_build.sh TREE LABEL BENCH_ARGS BINS FEATURES RUSTFLAGS   (TREE is a checkout of the commit to build)
. "$(dirname "$0")/config.sh"
TREE=$1; LABEL=$2; BENCHES=$3; BINS=${4:-}; FEATURES=${5:-}; EXTRA_RUSTFLAGS=${6:-}
HERE=$(cd "$(dirname "$0")" && pwd)
ssh $BUILD_HOST "mkdir -p $BUILD_ROOT"
scp -q $HERE/build_inner.sh $HERE/build.sh $HERE/x86_run.sh $BUILD_HOST:$BUILD_ROOT/
rsync -a --delete --exclude target --exclude .git --exclude .worktrees "$TREE/" $BUILD_HOST:$BUILD_ROOT/src-$LABEL/
ssh $BUILD_HOST "cd $BUILD_ROOT && BUILD_ROOT=. BUILD_CPUS=$BUILD_CPUS BUILD_TESTS=${BUILD_TESTS:-} flock $MEASURE_LOCK nice taskset -c $BUILD_CPUS sh build.sh '$LABEL' '$BENCHES' '$BINS' '$FEATURES' '$EXTRA_RUSTFLAGS' 2>&1 | tail -25"
