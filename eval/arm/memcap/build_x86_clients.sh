#!/bin/sh -e
ARM_SCRIPTS=$(cd "$(dirname "$0")/.." && pwd)
. "$ARM_SCRIPTS/config.sh"
MEMCAP_BUILD=${MEMCAP_BUILD:-memcap-build}
CARGO_CACHE=${CARGO_CACHE:-$BUILD_DIR/cargo}
BUILD_DIR=$MEMCAP_BUILD "$ARM_SCRIPTS/sync_src.sh" "$1"
rsync -a "$ARM_SCRIPTS/build/" $PLAY:$MEMCAP_BUILD/build/
ssh $PLAY "cd ~/$MEMCAP_BUILD && mkdir -p out/x86 target-x86 && flock $PLAY_LOCK docker run --rm --network host --cpuset-cpus $BUILD_CPUS \
  -v \$PWD/src:/work -v \$HOME/$CARGO_CACHE:/cargo-reg -v \$PWD/target-x86:/target-x86 -v \$PWD/out:/out -v \$PWD/build/x86_inner.sh:/inner.sh \
  -w /work -e CARGO_HOME=/cargo-reg -e CARGO_TARGET_DIR=/target-x86 arm-builder:2 sh /inner.sh"
ssh $PLAY "sudo chown -R \$(id -u):\$(id -g) ~/$MEMCAP_BUILD/out; ls -l ~/$MEMCAP_BUILD/out/x86"
