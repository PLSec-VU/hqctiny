#!/bin/sh -e
# usage: x86_run.sh LABEL MODE   (on the build host; MODE is a case of x86_inner.sh)
LABEL=$1; MODE=$2
BASE=$(cd "${BUILD_ROOT:?}" && pwd)
mkdir -p $BASE/target-x86-$LABEL $BASE/results
LOCK="flock ${MEASURE_LOCK:-$HOME/measure.lock}"
[ -n "$NOLOCK" ] && LOCK=""
$LOCK docker run --rm --network host --cpuset-cpus ${BUILD_CPUS:-12-15} \
  -v $BASE/src-$LABEL:/work -v $BASE/cargo:/cargo-reg -v $BASE/target-x86-$LABEL:/target -v $BASE/x86_inner.sh:/inner.sh -w /work \
  -e CARGO_HOME=/cargo-reg -e CARGO_TARGET_DIR=/target -e MODE=$MODE \
  ${BUILDER_IMAGE:-arm-builder:2} sh /inner.sh | tee $BASE/results/x86-$LABEL-$MODE.txt
