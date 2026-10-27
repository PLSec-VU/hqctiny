#!/bin/sh -e
# Item 3: size, stack, RSS, strace allocation audit, zero_alloc test.
. "$(dirname "$0")/lib.sh"
sync_tools; pi_cap_clock
pi_run memory_hqclethe "python3 $PI_ROOT/scripts/arm/memory_pi.py --out $PI_ROOT/results/memory_hqclethe.json --no-mctiny; for v in hqc1 hqc3 hqc5; do echo \"== strace audit \$v\"; python3 $PI_ROOT/scripts/container/memory_syscall_audit.py \$v 50 24001; done; echo '== zero_alloc'; taskset -c 2 $PI_BIN/bench/zero_alloc --test-threads=1 --nocapture"
pi_run memory_mctiny "python3 $PI_ROOT/scripts/arm/memory_pi.py --out $PI_ROOT/results/memory_mctiny.json --variants '' --mctiny-dir $PI_BIN/mctiny"
fetch
