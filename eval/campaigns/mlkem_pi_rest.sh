#!/bin/sh -e
# Pi campaign after the ML-KEM-768 swap, part 2. Needs the Pi and playground.
# usage: ARM_DIR=<result dir> mlkem_pi_rest.sh COMMIT
# Rebuilds COMMIT and installs it, verifies it (tests, vectors, Valgrind), measures the handler costs and the server CPU per
# session, the client CPU, stack and RSS, the LAN latency, the LAN floods that involve handshakes (puzzle off and d=16), the
# one- and four-worker throughput, and the smallest memory cap of the stateless server. McTiny is not re-measured.
CAMPAIGNS=$(cd "$(dirname "$0")" && pwd)
ARM=$(cd "$CAMPAIGNS/../arm" && pwd)
ARM_SCRIPTS=$ARM
. "$ARM/lib.sh"
"$ARM/build.sh" "$1"
"$ARM/setup.sh"
"$ARM/pi_verify.sh"
"$CAMPAIGNS/mlkem_pi_cpu.sh"
sync_tools; pi_cap_clock
pi_run client_cpu_hqclethe "python3 $PI_ROOT/scripts/arm/client_cpu_pi.py --out $PI_ROOT/results/client_cpu_hqclethe.json --reps 5 --sessions 30 --no-mctiny --mctiny-dir $PI_BIN/mctiny"
pi_run memory_hqclethe "python3 $PI_ROOT/scripts/arm/memory_pi.py --out $PI_ROOT/results/memory_hqclethe.json --no-mctiny; for v in hqc1 hqc3 hqc5; do echo \"== strace audit \$v\"; python3 $PI_ROOT/scripts/container/memory_syscall_audit.py \$v 50 24001; done; echo '== zero_alloc'; taskset -c 2 $PI_BIN/bench/zero_alloc --test-threads=1 --nocapture"
fetch
SKIP_MCTINY=1 "$ARM/item5_latency.sh"

handshake_cells=stateless:none:single,stateless:handshake:single,stateful:none:single,stateful:hello:single
harvest_cells=stateless:uchunk-harvest:single,stateless:vresidue-harvest:single
DOS_RUNS="paced1|hqc1|$handshake_cells|10|1.0|5
paced5|hqc5|$handshake_cells|40|4.0|5
harvest|hqc1,hqc3,hqc5|$harvest_cells|10|0.2|5" "$ARM/item4b_dos.sh"
DOS_PUZZLE_DIFFICULTY=16 DOS_RUNS="paced1_d16|hqc1|stateless:handshake:single|10|1.0|5
paced5_d16|hqc5|stateless:handshake:single|40|4.0|5
harvest_d16|hqc1,hqc3,hqc5|$harvest_cells|10|0.2|5" "$ARM/item4b_dos.sh"

MULTICORE_OUT=multicore_handshake.json MULTICORE_ARGS="--system stateless --kind handshake --reps 3" \
  "$ARM/item6_multicore_hello.sh"
MULTICORE_OUT=multicore_hello.json MULTICORE_ARGS="--system stateful --kind hello --reps 3 --server-counts 1,4" \
  "$ARM/item6_multicore_hello.sh"
fetch

stateless_cells=stateless:hqc1,stateless:hqc3,stateless:hqc5
"$ARM/memcap/build_x86_clients.sh" "$1"
MEMCAP_OUT=$ARM_DIR/memcap "$ARM/memcap/run.sh" --cells $stateless_cells
MEMCAP_OUT=$ARM_DIR/memcap "$ARM/memcap/run.sh" --cells $stateless_cells --quiet-scan
