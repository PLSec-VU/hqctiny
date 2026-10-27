#!/bin/sh -e
# usage: run_all.sh COMMIT
# One command for the whole ARM campaign on COMMIT (a commit of the repository $REPO): build and install, verify (tests,
# vector cross-checks, Valgrind), run items 1 to 5, fetch the raw data, and write tables.md to $ARM_DIR. Every Pi run takes
# $PI_LOCK, every playground run takes $PLAY_LOCK; a job takes the playground lock before the Pi lock.
. "$(dirname "$0")/config.sh"
"$ARM_SCRIPTS/build.sh" "$1"
"$ARM_SCRIPTS/setup.sh"
"$ARM_SCRIPTS/pi_verify.sh"
"$ARM_SCRIPTS/item1_server_cpu.sh"
"$ARM_SCRIPTS/item1b_mctiny_cost.sh"
"$ARM_SCRIPTS/item2_client_cpu.sh"
"$ARM_SCRIPTS/item3_memory.sh"
"$ARM_SCRIPTS/item4_5_locked.sh"
mkdir -p "$ARM_DIR"
"$ARM_SCRIPTS/make_tables.py" > "$ARM_DIR/tables.md"
