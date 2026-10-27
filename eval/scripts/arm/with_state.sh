#!/bin/sh
LOGDIR=$1; NAME=$2; shift 2
HERE=$(dirname "$0")
mkdir -p "$LOGDIR"
[ -n "$SUDO_USER" ] && chown "$SUDO_USER" "$LOGDIR"
python3 "$HERE/pi_state.py" wait-cool "${MAX_START_C:-70}"
python3 "$HERE/pi_state.py" snapshot > "$LOGDIR/$NAME.state_start.json"
python3 "$HERE/pi_state.py" sample "$LOGDIR/$NAME.state_series.jsonl" 2 &
SAMPLER=$!
${SUDO_USER:+sudo -u "$SUDO_USER"} "$@" > "$LOGDIR/$NAME.log" 2>&1
STATUS=$?
kill $SAMPLER
python3 "$HERE/pi_state.py" snapshot > "$LOGDIR/$NAME.state_end.json"
exit $STATUS
