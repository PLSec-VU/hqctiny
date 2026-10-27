#!/bin/sh -e
ARM_SCRIPTS=$(cd "$(dirname "$0")/.." && pwd)
. "$ARM_SCRIPTS/lib.sh"
MEMCAP_DIR=$ARM_SCRIPTS/memcap
MEMCAP_BUILD=${MEMCAP_BUILD:-memcap-build}
MEMCAP_OUT=${MEMCAP_OUT:-$REPO/eval/results/memcap/raw}
LAN_GATEWAY=${LAN_GATEWAY:-192.168.50.236}
rsync -a --delete --exclude __pycache__ "$MEMCAP_DIR/" $PI:$PI_ROOT/memcap/
sync_tools
pi_cap_clock
ssh $PLAY "mkdir -p ~/$MEMCAP_BUILD/tools ~/$MEMCAP_BUILD/memcap ~/$MEMCAP_BUILD/keys"
scp -3 -q "$PI:$PI_ROOT/keys/*.pk" $PLAY:$MEMCAP_BUILD/keys/
rsync -a --delete --exclude __pycache__ "$TOOLS_DIR/" $PLAY:$MEMCAP_BUILD/tools/
rsync -a --delete --exclude __pycache__ "$MEMCAP_DIR/" $PLAY:$MEMCAP_BUILD/memcap/
play_hold_start
pi_hold_start
cleanup() {
  ssh $PI "sudo ip route del 10.99.0.0/16 via $LAN_GATEWAY dev eth0" || true
  ssh $PLAY "sudo ip route del local 10.99.0.0/16 dev lo" || true
  ssh $PI "sudo rmdir /sys/fs/cgroup/memcap-* 2>/dev/null" || true
  pi_hold_stop
  play_hold_stop
}
trap cleanup EXIT
ssh $PI "sudo ip route replace 10.99.0.0/16 via $LAN_GATEWAY dev eth0"
ssh $PLAY "sudo ip route replace local 10.99.0.0/16 dev lo"
python3 "$MEMCAP_DIR/search.py" --out "$MEMCAP_OUT" "$@"
