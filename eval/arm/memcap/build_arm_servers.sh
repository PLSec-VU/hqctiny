#!/bin/sh -e
ARM_SCRIPTS=$(cd "$(dirname "$0")/.." && pwd)
. "$ARM_SCRIPTS/config.sh"
MEMCAP_BUILD=${MEMCAP_BUILD:-memcap-build}
CARGO_CACHE=${CARGO_CACHE:-$BUILD_DIR/cargo}
rsync -a "$ARM_SCRIPTS/memcap/arm_servers_inner.sh" $PLAY:$MEMCAP_BUILD/build/
ssh $PLAY "cd ~/$MEMCAP_BUILD && mkdir -p out target cargo && flock $PLAY_LOCK docker run --rm --network host --cpuset-cpus $BUILD_CPUS \
  -v \$PWD/src:/work -v \$HOME/$CARGO_CACHE:/cargo-reg -v \$PWD/target:/target -v \$PWD/out:/out -v \$PWD/build/arm_servers_inner.sh:/inner.sh \
  -w /work -e CARGO_HOME=/cargo-reg -e CARGO_TARGET_DIR=/target -e CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  -e CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc -e AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar -e CARGO_BUILD_JOBS=4 arm-builder:2 sh /inner.sh"
ssh $PLAY "sudo chown -R \$(id -u):\$(id -g) ~/$MEMCAP_BUILD/out; cd ~/$MEMCAP_BUILD/out && sha256sum arm-quiet/* arm-floodstats/*"
