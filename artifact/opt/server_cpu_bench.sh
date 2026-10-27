#!/bin/bash
# usage: server_cpu_bench.sh OUT_DIR [COMMIT...]
# Criterion medians of the server request benchmarks for each commit (default: baseline, Merkle removal, optimized).
# Builds each commit before it takes the measurement lock, then runs the binaries twice in a fixed order on cpu0.
set -euo pipefail
REPO_DIR=${REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}
OUT_DIR=$(mkdir -p "${1:?usage: server_cpu_bench.sh OUT_DIR [COMMIT...]}" && cd "$1" && pwd)
shift
COMMITS=${*:-61a6717 853aead 46efa02}
MEASURE_LOCK=${MEASURE_LOCK:-$HOME/measure.lock}
EVAL_IMAGE=${EVAL_IMAGE:-hqclethe-eval}
BENCH_CPU=${BENCH_CPU:-0}
BUILD_CPUS=${BUILD_CPUS:-12-15}
ROUNDS=${ROUNDS:-2}
TREES=$REPO_DIR/.worktrees
BENCH_FILTER=server_
CRITERION_ARGS="--noplot --warm-up-time 2 --measurement-time 4"

in_container() { cpus=$1; tree=$2; shift 2
  docker run --rm --cpuset-cpus "$cpus" -v "$tree:/work" -v opt_registry:/usr/local/cargo/registry -w /work \
    -e CARGO_TARGET_DIR=/work/target-linux "$EVAL_IMAGE" "$@"
}

prepare_tree() { commit=$1; tree=$TREES/opt-$commit
  [ -d "$tree" ] || git -C "$REPO_DIR" worktree add --detach "$tree" "$commit"
  git -C "$tree" submodule update --init
  in_container "$BUILD_CPUS" "$tree" cargo bench --features avx2 --bench protocol_phases --no-run
}

bench_binary() { tree=$1
  ls -t "$tree"/target-linux/release/deps/protocol_phases-* | grep -v '\.d$' | head -1 | sed "s|$tree|.|"
}

run_bench() { commit=$1; round=$2; tree=$TREES/opt-$commit
  in_container "$BENCH_CPU" "$tree" "$(bench_binary "$tree")" --bench "$BENCH_FILTER" $CRITERION_ARGS > "$OUT_DIR/$commit-r$round.txt" 2>&1
}

for commit in $COMMITS; do prepare_tree "$commit"; done

exec 9>"$MEASURE_LOCK"
flock 9
sudo bash "$REPO_DIR/eval/scripts/host/measurement_on.sh" > "$OUT_DIR/measurement_on.txt" 2>&1
trap 'sudo bash "$REPO_DIR/eval/scripts/host/measurement_off.sh" > "$OUT_DIR/measurement_off.txt" 2>&1' EXIT
for round in $(seq "$ROUNDS"); do
  for commit in $COMMITS; do run_bench "$commit" "$round"; done
done
