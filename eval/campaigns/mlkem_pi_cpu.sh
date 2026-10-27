#!/bin/sh -e
# Pi handler costs and server CPU per session after the ML-KEM-768 swap. Needs the Pi only.
# usage: ARM_DIR=<result dir> mlkem_pi_cpu.sh
ARM_SCRIPTS=$(cd "$(dirname "$0")/../arm" && pwd)
. "$ARM_SCRIPTS/lib.sh"
sync_tools; pi_cap_clock
ssh $PI "mkdir -p $PI_ROOT/results/criterion"
pi_run criterion "for b in protocol_phases puzzle stateful_baseline kem_comparison; do [ -x $PI_BIN/bench/\$b ] || continue; CRITERION_HOME=$PI_ROOT/results/criterion taskset -c $PI_SERVER_CORE $PI_BIN/bench/\$b --bench --noplot; done"
pi_run session_cpu_hqclethe "python3 $PI_ROOT/scripts/arm/session_cpu_pi.py --out $PI_ROOT/results/session_cpu_hqclethe.json --reps 5 --sessions 50 --no-mctiny --mctiny-dir $PI_BIN/mctiny"
fetch
