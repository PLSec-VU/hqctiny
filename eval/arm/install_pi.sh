#!/bin/sh -e
# usage: install_pi.sh COMMIT   Copies the built aarch64 files from playground to the Pi.
. "$(dirname "$0")/config.sh"
COMMIT=$(git -C "$REPO" rev-parse "$1")
ssh $PI "mkdir -p $PI_BIN"
for d in quiet floodstats prof bench mctiny; do
  ssh $PI "rm -rf $PI_BIN/$d; mkdir -p $PI_BIN/$d"
  scp -3 -q "$PLAY:$BUILD_DIR/out/$d/*" "$PI:$PI_BIN/$d/"
done
echo "$COMMIT" | ssh $PI "cat > $PI_BIN/COMMIT"
echo "installed $COMMIT"
