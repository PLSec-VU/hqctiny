#!/bin/sh -e
cd "$HOME/$BUILD_DIR"
D="docker run --rm --network host --cpuset-cpus ${BUILD_CPUS:-12-15}"
if ! docker image inspect arm-builder:2 >/dev/null 2>&1; then
  docker rm -f arm-builder-prep 2>/dev/null || true
  docker run --name arm-builder-prep --network host --cpuset-cpus ${BUILD_CPUS:-12-15} hqclethe-eval sh -c "apt-get update -qq && apt-get install -y -qq --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross binutils-aarch64-linux-gnu && rustup target add --toolchain nightly-2026-06-15 aarch64-unknown-linux-gnu"
  docker commit arm-builder-prep arm-builder:2
  docker rm arm-builder-prep
fi
mkdir -p out target target-x86 cargo
rm -f mct/inc/crypto_sort_int32.h mct/inc/crypto_sort_uint32.h
sudo rm -rf out/quiet out/floodstats out/prof out/bench out/mctiny out/x86
ARM_ENV="-e CARGO_HOME=/cargo-reg -e CARGO_TARGET_DIR=/target -e CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc -e CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc -e AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar -e CARGO_BUILD_JOBS=4"
$D -v $PWD/src:/work -v $PWD/cargo:/cargo-reg -v $PWD/target:/target -v $PWD/out:/out -v $PWD/build/build_inner.sh:/inner.sh -w /work $ARM_ENV arm-builder:2 sh /inner.sh
$D -v $PWD:/work -v $PWD/out:/out arm-builder:2 sh /work/build/mct_inner.sh
$D -v $PWD/src:/work -v $PWD/cargo:/cargo-reg -v $PWD/target-x86:/target-x86 -v $PWD/out:/out -v $PWD/build/x86_inner.sh:/inner.sh -w /work -e CARGO_HOME=/cargo-reg -e CARGO_TARGET_DIR=/target-x86 arm-builder:2 sh /inner.sh
sudo chown -R "$(id -u):$(id -g)" out
D2=target/aarch64-unknown-linux-gnu/release/deps
mkdir -p out/bench
for b in kem_primitives protocol_phases puzzle kem_comparison stateful_baseline zero_alloc; do
  cp "$(ls -t $D2/$b-* | grep -v '\.d$' | head -1)" out/bench/$b
done
