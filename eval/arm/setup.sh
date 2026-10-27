#!/bin/sh -e
# One-time setup of the Pi and playground: Pi packages, ML-KEM keys (made on the Pi with the installed client),
# the McTiny state directory, and the public keys on playground. Run after build.sh.
. "$(dirname "$0")/lib.sh"
ssh $PI "sudo apt-get install -y -qq --no-install-recommends iperf3 sysstat strace >/dev/null; mkdir -p $PI_ROOT/keys $PI_ROOT/results; sudo touch $PI_LOCK; sudo chmod 666 $PI_LOCK"
for v in hqc1 hqc3 hqc5; do
  ssh $PI "[ -f $PI_ROOT/keys/server-$v.sk ] || $PI_BIN/quiet/hqclethe-client keygen --variant $v --out $PI_ROOT/keys/server-$v"
  ssh $PLAY "mkdir -p ~/$BUILD_DIR/keys"
  ssh $PI "cat $PI_ROOT/keys/server-$v.pk" | ssh $PLAY "cat > ~/$BUILD_DIR/keys/server-$v.pk"
done
ssh $PI "[ -d $PI_ROOT/mctiny_state ]" || scp -3 -rq ${PLAY}:${MCTINY_STATE_PLAY} ${PI}:${PI_ROOT}/mctiny_state
