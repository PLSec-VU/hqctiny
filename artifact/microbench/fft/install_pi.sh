#!/bin/sh -e
# usage: install_pi.sh PI   (copies binaries and helper scripts to the Pi)
PI=${1:?usage: install_pi.sh user@host}
export STUDY=fft
. "$(dirname "$0")/../common/config.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
COMMON=$HERE/../common
ssh $PI "mkdir -p $PI_ROOT/bin"
scp -q $COMMON/pi_run.sh $COMMON/pi_snapshot.sh $COMMON/vgct.sh $COMMON/stack_search.sh $HERE/pi_chain.sh $HERE/pi_bench.sh $PI:$PI_ROOT/
for label in ref vm fft toom; do
  rsync -a $BUILD_HOST:$BUILD_ROOT/out-$label/ $PI:$PI_ROOT/bin/$label/
done


