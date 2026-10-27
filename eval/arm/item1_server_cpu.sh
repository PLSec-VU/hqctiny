#!/bin/sh -e
# Item 1: Criterion server benches, then server CPU per session (stateless, stateful, McTiny).
. "$(dirname "$0")/lib.sh"
sync_tools; pi_cap_clock
ssh $PI "mkdir -p $PI_ROOT/results/criterion"
pi_run criterion "for b in kem_primitives protocol_phases stateful_baseline; do CRITERION_HOME=$PI_ROOT/results/criterion taskset -c $PI_SERVER_CORE $PI_BIN/bench/\$b --bench --noplot; done"
pi_run session_cpu_hqclethe "python3 $PI_ROOT/scripts/arm/session_cpu_pi.py --out $PI_ROOT/results/session_cpu_hqclethe.json --reps 5 --sessions 50 --no-mctiny --mctiny-dir $PI_BIN/mctiny"
pi_run session_cpu_mctiny "python3 $PI_ROOT/scripts/arm/session_cpu_pi.py --out $PI_ROOT/results/session_cpu_mctiny.json --reps 5 --mctiny-sessions 10 --variants '' --mctiny-dir $PI_BIN/mctiny"
fetch
