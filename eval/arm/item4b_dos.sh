#!/bin/sh -e
# Item 4, part 2: real-network flood. Server on the Pi (pinned core 2), flood and legitimate probes from playground over the LAN.
# Holds the Pi lock and the playground lock for the whole run. Adds temporary routes so that the flood can use 10.99.0.0/16 source
# addresses (churn2 botnet shape) and removes them at the end.
. "$(dirname "$0")/lib.sh"
ALL_CELLS=stateless:none:single,stateless:handshake:single,stateless:uchunk:single,stateless:vresidue:single,stateful:none:single,stateful:hello:single,stateful:churn2:botnet
PLAY_TOOLS=$PLAY_HOME/$BUILD_DIR/tools
rsync -a --delete --exclude __pycache__ "$TOOLS_DIR/" $PLAY:$BUILD_DIR/tools/
sync_tools
play_hold_start
pi_hold_start
bridge_start
cleanup() {
  bridge_stop
  ssh $PI "sudo ip route del 10.99.0.0/16 via 192.168.50.236 dev eth0" || true
  ssh $PLAY "sudo ip route del local 10.99.0.0/16 dev lo" || true
  pi_hold_stop
  play_hold_stop
}
trap cleanup EXIT
ssh $PI "sudo ip route replace 10.99.0.0/16 via 192.168.50.236 dev eth0"
ssh $PLAY "sudo ip route replace local 10.99.0.0/16 dev lo"
pi_cap_clock
while IFS='|' read -r NAME RUN_VARIANTS RUN_CELLS RUN_DURATION RUN_PROBE RUN_REPS; do
  [ -n "$NAME" ] || continue
  ssh -n -o ServerAliveInterval=30 $PLAY "ulimit -n 65536; env CLIENT_BIN_DIR=$PLAY_HOME/$BUILD_DIR/out/x86 KEY_DIR=$PLAY_HOME/$BUILD_DIR/keys FLOOD_CORE=$FLOOD_CORE LEGIT_CORE=$LEGIT_CORE ORCHESTRATOR_CORE=$ORCHESTRATOR_CORE FLOOD_SOURCE_BASE=$FLOOD_SOURCE_BASE python3 $PLAY_TOOLS/arm/dos_flood_lan.py --pi tcp:$BRIDGE_PORT --out $PLAY_HOME/$BUILD_DIR/dos_lan_$NAME.json --cells $RUN_CELLS --variants $RUN_VARIANTS --reps $RUN_REPS --duration $RUN_DURATION --probe-interval $RUN_PROBE ${DOS_PUZZLE_DIFFICULTY:+--puzzle-difficulty $DOS_PUZZLE_DIFFICULTY}" | tee "$ARM_DIR/raw/dos_lan_$NAME.log"
  scp -q $PLAY:$BUILD_DIR/dos_lan_$NAME.json "$ARM_DIR/raw/pi/dos_lan_$NAME.json"
done <<RUNS
${DOS_RUNS:-spec|hqc1,hqc5|$ALL_CELLS|10|0.2|5
paced1|hqc1|$ALL_CELLS|10|1.0|5
paced5|hqc5|$ALL_CELLS|40|4.0|5}
RUNS
