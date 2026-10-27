#!/bin/sh -e
# Item 5: LAN session latency, server on the Pi, client on playground, no loss, 20 sessions per cell.
# SKIP_HQC=1 runs only McTiny, SKIP_MCTINY=1 only HQCLethe and the stateful baseline.
. "$(dirname "$0")/lib.sh"
PLAY_TOOLS=$PLAY_HOME/$BUILD_DIR/tools
rsync -a --delete --exclude __pycache__ "$TOOLS_DIR/" $PLAY:$BUILD_DIR/tools/
sync_tools; pi_cap_clock
play_hold_start
pi_hold_start
bridge_start
trap "bridge_stop; pi_hold_stop; play_hold_stop" EXIT
KEYFILE=$(ssh $PLAY "ls $MCTINY_STATE_PLAY/public/*")
RUN="env CLIENT_BIN_DIR=$PLAY_HOME/$BUILD_DIR/out/x86 KEY_DIR=$PLAY_HOME/$BUILD_DIR/keys LEGIT_CORE=$LEGIT_CORE CLIENT_CORE=$LEGIT_CORE python3 $PLAY_TOOLS/arm/lan_latency.py --pi tcp:$BRIDGE_PORT --reps 20"
[ -n "$SKIP_HQC" ] || ssh -n -o ServerAliveInterval=30 $PLAY "$RUN --out $PLAY_HOME/$BUILD_DIR/lan_latency.json" | tee "$ARM_DIR/raw/lan_latency.log"
[ -n "$SKIP_MCTINY" ] || ssh -n -o ServerAliveInterval=30 $PLAY "$RUN --only-mctiny --out $PLAY_HOME/$BUILD_DIR/lan_latency_mctiny.json --mctiny-client $MCTINY_BUILD/mctiny-20200804/mctiny-client --mctiny-public-key $KEYFILE" | tee "$ARM_DIR/raw/lan_latency_mctiny.log"
[ -n "$SKIP_HQC" ] || scp -q $PLAY:$BUILD_DIR/lan_latency.json "$ARM_DIR/raw/pi/lan_latency.json"
[ -n "$SKIP_MCTINY" ] || scp -q $PLAY:$BUILD_DIR/lan_latency_mctiny.json "$ARM_DIR/raw/pi/lan_latency_mctiny.json"
