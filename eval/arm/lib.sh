. "${ARM_SCRIPTS:-$(dirname "$0")}/config.sh"

sync_tools() {
  rsync -a --delete --exclude __pycache__ "$TOOLS_DIR/" $PI:$PI_ROOT/scripts/
  ssh $PI "cat > $PI_ROOT/env.sh" <<ENV
export SERVER_BIN_DIR=$PI_BIN/quiet CLIENT_BIN_DIR=$PI_BIN/quiet KEY_DIR=$PI_ROOT/keys SERVER_CORE=$PI_SERVER_CORE CLIENT_CORE=$PI_CLIENT_CORE ORCHESTRATOR_CORE=$PI_ORCHESTRATOR_CORE HOST_RESULTS_DIR=/tmp/unused STATELESS_REPLAY_RATES=$STATELESS_REPLAY_RATES
ENV
}

pi_cap_clock() {
  ssh $PI "sudo sh -c 'echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor >/dev/null; echo 1200000 | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_max_freq >/dev/null'"
}

pi_run() {
  name=$1; shift
  printf '%s\n' ". $PI_ROOT/env.sh" "$*" | ssh $PI "cat > $PI_ROOT/run_$name.sh"
  ssh -o ServerAliveInterval=30 $PI "sudo rm -f $PI_ROOT/results/state/$name.*; cd $PI_ROOT && sudo flock $PI_LOCK env -u SUDO_USER sh scripts/arm/with_state.sh $PI_ROOT/results/state $name sh $PI_ROOT/run_$name.sh"
}

fetch() {
  mkdir -p "$ARM_DIR/raw/pi"
  rsync -a $PI:$PI_ROOT/results/ "$ARM_DIR/raw/pi/"
}

pi_hold_start() {
  HOLD_DIR=$(mktemp -d)
  mkfifo "$HOLD_DIR/in"
  ssh $PI "flock $PI_LOCK sh -c 'echo held; read x'" < "$HOLD_DIR/in" > "$HOLD_DIR/out" &
  HOLD_PID=$!
  exec 9> "$HOLD_DIR/in"
  until grep -q held "$HOLD_DIR/out" 2>/dev/null; do sleep 1; done
}

pi_hold_stop() {
  echo done >&9
  exec 9>&-
  wait $HOLD_PID
  rm -rf "$HOLD_DIR"
}

play_hold_start() {
  [ -z "$PLAY_HELD" ] || return 0
  PHOLD_DIR=$(mktemp -d)
  mkfifo "$PHOLD_DIR/in"
  ssh $PLAY "flock $PLAY_LOCK sh -c 'echo held; read x'" < "$PHOLD_DIR/in" > "$PHOLD_DIR/out" &
  PHOLD_PID=$!
  exec 8> "$PHOLD_DIR/in"
  until grep -q held "$PHOLD_DIR/out" 2>/dev/null; do sleep 1; done
}

play_hold_stop() {
  [ -z "$PLAY_HELD" ] || return 0
  echo done >&8
  exec 8>&-
  wait $PHOLD_PID
  rm -rf "$PHOLD_DIR"
}

BRIDGE_PORT=${BRIDGE_PORT:-24777}
bridge_start() {
  python3 "$TOOLS_DIR/arm/agent_bridge.py" $BRIDGE_PORT $PI &
  BRIDGE_PID=$!
  ssh -N -R $BRIDGE_PORT:127.0.0.1:$BRIDGE_PORT $PLAY &
  TUNNEL_PID=$!
  sleep 3
}

bridge_stop() {
  kill $BRIDGE_PID $TUNNEL_PID 2>/dev/null || true
}
