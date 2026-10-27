#!/bin/sh -e
# usage: build.sh LABEL BENCH_ARGS BINS FEATURES RUSTFLAGS   (runs on the x86 build host, tree in $BUILD_ROOT/src-LABEL)
LABEL=$1
BASE=$(cd "${BUILD_ROOT:?}" && pwd)
mkdir -p $BASE/cargo $BASE/target-$LABEL $BASE/out-$LABEL
docker run --rm --network host --cpuset-cpus ${BUILD_CPUS:-12-15} \
  -v $BASE/src-$LABEL:/work -v $BASE/cargo:/cargo-reg -v $BASE/target-$LABEL:/target -v $BASE/out-$LABEL:/out -v $BASE/build_inner.sh:/inner.sh -w /work \
  -e CARGO_HOME=/cargo-reg -e CARGO_TARGET_DIR=/target -e CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc -e CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc -e AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar -e CARGO_BUILD_JOBS=4 \
  -e BENCHES="$2" -e BINS="$3" -e FEATURES="$4" -e EXTRA_RUSTFLAGS="$5" -e BUILD_TESTS="${BUILD_TESTS:-}" \
  ${BUILDER_IMAGE:-arm-builder:2} sh /inner.sh
