#!/bin/sh -e
# Item 2: client CPU per session (stateless, stateful, McTiny) and the McTiny keygen/decap bench. The client primitives are in item 1 (Criterion).
. "$(dirname "$0")/lib.sh"
sync_tools; pi_cap_clock
pi_run client_cpu_hqclethe "python3 $PI_ROOT/scripts/arm/client_cpu_pi.py --out $PI_ROOT/results/client_cpu_hqclethe.json --reps 5 --sessions 30 --no-mctiny --mctiny-dir $PI_BIN/mctiny"
pi_run client_cpu_mctiny "python3 $PI_ROOT/scripts/arm/client_cpu_pi.py --out $PI_ROOT/results/client_cpu_mctiny.json --reps 5 --mctiny-sessions 5 --variants '' --mctiny-dir $PI_BIN/mctiny; echo '== keygen/decap bench'; taskset -c 2 $PI_BIN/mctiny/mctiny_keygen_decap_bench"
fetch
