#!/bin/sh -e
# usage: install_pi.sh PI   (PI is user@host; copies the build outputs and helper scripts into $PI_ROOT on the Pi)
PI=${1:?usage: install_pi.sh user@host}
export STUDY=neon
. "$(dirname "$0")/../common/config.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
COMMON=$HERE/../common
ssh $PI "mkdir -p $PI_ROOT/bin"
scp -q $COMMON/pi_run.sh $COMMON/pi_snapshot.sh $COMMON/vgct.sh $COMMON/stack_search.sh $HERE/pi_bench.sh $HERE/pi_chain.sh $PI:$PI_ROOT/
for label in base fref ffull fneon; do
  rsync -a $BUILD_HOST:$BUILD_ROOT/out-$label/ $PI:$PI_ROOT/bin/f_$label/
done
