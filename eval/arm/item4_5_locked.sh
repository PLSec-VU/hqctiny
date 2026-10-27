#!/bin/sh -e
# Items 4a, 5 and 4b in one playground lock hold. The inner scripts skip their own hold when PLAY_HELD is set.
. "$(dirname "$0")/lib.sh"
play_hold_start
trap play_hold_stop EXIT
PLAY_HELD=1 "$(dirname "$0")/item4a_link.sh"
PLAY_HELD=1 "$(dirname "$0")/item5_latency.sh"
PLAY_HELD=1 "$(dirname "$0")/item4b_dos.sh"
