#!/bin/sh -e
# usage: install_pi.sh PI TREE_HEAD   (copies binaries, the head sources for the tests, and helper scripts to the Pi)
PI=${1:?usage: install_pi.sh user@host TREE_HEAD}
export STUDY=mce
. "$(dirname "$0")/../common/config.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
COMMON=$HERE/../common
ssh $PI "mkdir -p $PI_ROOT/bin"
scp -q $COMMON/pi_run.sh $COMMON/pi_snapshot.sh $COMMON/vgct.sh $HERE/pi_chain.sh $PI:$PI_ROOT/
for label in base vec head; do
  rsync -a $BUILD_HOST:$BUILD_ROOT/out-$label/ $PI:$PI_ROOT/bin/$label/
done
rsync -a $BUILD_HOST:$BUILD_ROOT/out-head/tests/ $PI:$PI_ROOT/bin/head-tests/
rsync -a --exclude target --exclude .git "$2/" $PI:$PI_ROOT/src/
