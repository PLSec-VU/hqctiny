#!/bin/sh -e
# Item 6: answers per second of one server with 1 and 4 workers on the Pi, under a real LAN request flood.
# MULTICORE_ARGS="--system stateless --kind handshake" floods HQCLethe; MULTICORE_OUT names the result file.
# Holds the Pi lock and the playground lock for the whole run.
. "$(dirname "$0")/lib.sh"
play_hold_start
pi_hold_start
trap 'pi_hold_stop; play_hold_stop' EXIT
pi_cap_clock
mkdir -p "$ARM_DIR/raw/pi"
python3 "$TOOLS_DIR/arm/multicore_hello.py" --out "$ARM_DIR/raw/pi/${MULTICORE_OUT:-multicore_hello.json}" --pi $PI --pi-host $PI_HOST \
  --flood-host $PLAY --client-dir $PLAY_HOME/$BUILD_DIR/out/x86 --key-dir $PLAY_HOME/$BUILD_DIR/keys \
  --single-core $PI_SERVER_CORE ${MULTICORE_ARGS}
