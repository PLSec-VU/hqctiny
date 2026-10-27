#!/bin/sh -e
# Item 1b: McTiny server cost per answered query without a flood (stock server on one core, client sessions at a low steady rate).
. "$(dirname "$0")/lib.sh"
sync_tools; pi_cap_clock
pi_run mctiny_cost "python3 $PI_ROOT/scripts/arm/mctiny_cost_pi.py --out $PI_ROOT/results/mctiny_cost.json --reps 3 --sessions 20 --gap 1.0 --mctiny-dir $PI_BIN/mctiny"
fetch
