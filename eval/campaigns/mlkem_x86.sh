#!/usr/bin/env bash
# x86 campaign after the ML-KEM-768 swap: the categories the handshake changes.
# Run on the measurement host from the repository root.
#
#   eval/campaigns/mlkem_x86.sh a1          first run: categories 1, 2, 3, 6, 7, 9, 10, the WAN sweep and the floods
#   eval/campaigns/mlkem_x86.sh a2          second run: categories 3, 6, 9 (constant-time check) and the floods
#
# The whole run holds ~/measure.lock and brackets itself with
# measurement_on.sh and measurement_off.sh. Stage directories are listed in
# ~/mlkem_<tag>_stage_dirs.txt.
set -uo pipefail

tag="${1:?usage: mlkem_x86.sh a1|a2}"
case "$tag" in
  a1) first_categories="1,2,3,6,7,9,10" ;;
  a2) first_categories="3,6,9" ;;
  *) echo "unknown tag $tag" >&2; exit 2 ;;
esac

lock=~/measure.lock
stage_log=~/mlkem_${tag}_stages.log
stage_dirs=~/mlkem_${tag}_stage_dirs.txt
harvest_kinds="handshake auth uchunk vresidue uchunk-harvest vresidue-harvest"
puzzle_16="--puzzle-difficulty 16"
: > "$stage_log"
: > "$stage_dirs"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "$stage_log"; }

exec 9>"$lock"
flock -n 9 || { log "lock busy, waiting"; flock 9; }
log "lock acquired"

cleanup() {
  log "measurement_off.sh"
  sudo eval/scripts/host/measurement_off.sh >> "$stage_log" 2>&1
  log "lock released"
  flock -u 9
}
trap cleanup EXIT

log "commit $(git rev-parse HEAD), $(git status --porcelain | wc -l) dirty files"
sudo eval/scripts/host/measurement_on.sh 2>&1 | tee -a "$stage_log"

run_stage() {
  local name="$1"; shift
  log "start $name"
  if "$@" > "/tmp/mlkem_${tag}_${name}.out" 2>&1; then
    log "end $name ok"
  else
    log "end $name FAILED, see /tmp/mlkem_${tag}_${name}.out"
  fi
  echo "$name $(ls -1t eval/results | head -1)" >> "$stage_dirs"
}

dos_stage() {
  local name="$1" server_args="$2" flood_kinds="$3"; shift 3
  run_stage "$name" env STATELESS_SERVER_ARGS="$server_args" STATELESS_FLOOD_KINDS="$flood_kinds" \
    bash eval/run_all.sh --categories 4 --dos-args="$* --name ${name}_${tag}"
}

run_stage categories bash eval/run_all.sh --categories "$first_categories"

if [ "$tag" = a1 ]; then
  for variant in hqc1 hqc3 hqc5; do
    run_stage "wan_$variant" bash eval/run_all.sh --categories 8 \
      --wan-sweep-args="--systems stateless,stateful --variant $variant --name wan_${variant}_${tag}"
  done
fi

ulimit -n 65536

stateless_handshake="--systems stateless --kinds handshake,auth --reps 10"
stateless_harvest="--systems stateless --kinds uchunk-harvest,vresidue-harvest --reps 5"
dos_stage hs_single "" "$harvest_kinds" "$stateless_handshake --shapes single"
dos_stage hs_single_puzzle16 "$puzzle_16" "$harvest_kinds" "$stateless_handshake --shapes single"
dos_stage hs_botnet "" "$harvest_kinds" "$stateless_handshake --shapes botnet"
dos_stage hs_botnet_puzzle16 "$puzzle_16" "$harvest_kinds" "$stateless_handshake --shapes botnet"
dos_stage harvest_single "" "$harvest_kinds" "$stateless_harvest --shapes single"
dos_stage harvest_single_puzzle16 "$puzzle_16" "$harvest_kinds" "$stateless_harvest --shapes single"
dos_stage harvest_botnet "" "$harvest_kinds" "$stateless_harvest --shapes botnet"
dos_stage harvest_botnet_puzzle16 "$puzzle_16" "$harvest_kinds" "$stateless_harvest --shapes botnet"
run_stage stateful_single bash eval/run_all.sh --categories 4 \
  --dos-args="--systems stateful --shapes single --kinds hello,auth,partial,fullkey --reps 10 --name stateful_single_${tag}"
run_stage stateful_botnet bash eval/run_all.sh --categories 4 \
  --dos-args="--systems stateful --shapes botnet --kinds hello,auth,fullkey --reps 10 --name stateful_botnet_${tag}"
run_stage stateful_tablefill bash eval/run_all.sh --categories 4 \
  --dos-args="--systems stateful --shapes botnet --kinds partial,churn2 --reps 5 --name stateful_tablefill_${tag}"

log "all stages done"
