#!/bin/sh -e
# Pi campaign after the ML-KEM-768 swap, part 3, on the build that mlkem_pi_rest.sh installed. Needs ARM_DIR with the
# Criterion results of part 2. Sets the replay-filter rate of every stateless Pi server from the Pi's own v-residue cost
# (as the McEliece campaign did), then repeats the runs that start a stateless server: session CPU, memory, LAN latency,
# LAN floods, multicore and the memory cap. Also runs the Valgrind checks with the installed valgrind package.
# usage: ARM_DIR=<result dir> mlkem_pi_redo.sh
CAMPAIGNS=$(cd "$(dirname "$0")" && pwd)
ARM=$(cd "$CAMPAIGNS/../arm" && pwd)
ARM_SCRIPTS=$ARM
. "$ARM/lib.sh"

STATELESS_REPLAY_RATES=$(python3 - "$ARM_DIR" <<'PY'
import glob, json, sys
rates = []
for variant in ("hqc1", "hqc3", "hqc5"):
    path = glob.glob(f"{sys.argv[1]}/raw/pi/criterion/{variant}_server_vresidue_request/new/estimates.json")[0]
    nanoseconds = json.load(open(path))["median"]["point_estimate"]
    rates.append(f"{variant}={int(1e9 / nanoseconds) // 100 * 100}")
print(",".join(rates))
PY
)
export STATELESS_REPLAY_RATES
echo "replay rates $STATELESS_REPLAY_RATES" | tee "$ARM_DIR/replay_rates.txt"

sync_tools; pi_cap_clock
ssh $PI "sudo apt-get install -y -qq valgrind >/dev/null"
scp -q "$ARM/vgct.sh" $PI:$PI_ROOT/vgct.sh
for arg in control classify-control 1 3 5 kem1 kem3 kem5 mlkem1 mlkem3 mlkem5 session1 session3 session5; do
  pi_run vg_addfft_$arg "$PI_ROOT/vgct.sh $PI_ROOT/extra/addfft/ct-check $arg" || echo "nonzero exit: vg_addfft_$arg"
done
for arg in kem1 kem3 kem5 session1 session3 session5; do
  pi_run vg_normal_$arg "$PI_ROOT/vgct.sh $PI_ROOT/extra/normal/ct-check $arg" || echo "nonzero exit: vg_normal_$arg"
done

pi_run session_cpu_hqclethe "python3 $PI_ROOT/scripts/arm/session_cpu_pi.py --out $PI_ROOT/results/session_cpu_hqclethe.json --reps 5 --sessions 50 --no-mctiny --mctiny-dir $PI_BIN/mctiny"
pi_run memory_hqclethe "python3 $PI_ROOT/scripts/arm/memory_pi.py --out $PI_ROOT/results/memory_hqclethe.json --no-mctiny; for v in hqc1 hqc3 hqc5; do echo \"== strace audit \$v\"; python3 $PI_ROOT/scripts/container/memory_syscall_audit.py \$v 50 24001; done"
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
MEMCAP_OUT=$ARM_DIR/memcap_replay "$ARM/memcap/run.sh" --cells $stateless_cells
MEMCAP_OUT=$ARM_DIR/memcap_replay "$ARM/memcap/run.sh" --cells $stateless_cells --quiet-scan
