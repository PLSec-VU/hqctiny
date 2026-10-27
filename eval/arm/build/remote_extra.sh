#!/bin/sh -e
cd "$HOME/$BUILD_DIR"
D="docker run --rm --network host --cpuset-cpus ${BUILD_CPUS:-12-15}"
ARM_ENV="-e CARGO_HOME=/cargo-reg -e CARGO_TARGET_DIR=/target -e CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc -e CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc -e AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar -e CARGO_BUILD_JOBS=4"
mkdir -p out target target-x86 cargo target-x86-tests
sudo rm -rf out/extra
mkdir -p out/extra
$D -v $PWD/src:/work -v $PWD/cargo:/cargo-reg -v $PWD/target:/target -v $PWD/out:/out -v $PWD/build/extra_inner.sh:/inner.sh -w /work $ARM_ENV arm-builder:2 sh /inner.sh
$D -v $PWD/src:/work -v $PWD/cargo:/cargo-reg -v $PWD/target-x86-tests:/target -v $PWD/out:/out -v $PWD/build/x86_tests_inner.sh:/inner.sh -w /work -e CARGO_HOME=/cargo-reg -e CARGO_TARGET_DIR=/target arm-builder:2 sh /inner.sh > out/x86-tests.log 2>&1
sudo chown -R "$(id -u):$(id -g)" out
