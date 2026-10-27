#!/bin/bash
# usage: server_profile.sh OUT_DIR [COMMIT]
# perf profile (self time by symbol) of the server-loop binary for each level and request kind. Relative breakdowns only.
set -euo pipefail
REPO_DIR=${REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}
OUT_DIR=$(mkdir -p "${1:?usage: server_profile.sh OUT_DIR [COMMIT]}" && cd "$1" && pwd)
COMMIT=${2:-46efa02}
EVAL_IMAGE=${EVAL_IMAGE:-hqclethe-eval}
PROFILE_CPU=${PROFILE_CPU:-12}
BUILD_CPUS=${BUILD_CPUS:-12-15}
SAMPLE_HZ=5000
TOP_SYMBOLS=80
TREE=$REPO_DIR/.worktrees/opt-$COMMIT
HANDSHAKE_ITERATIONS=20000
REQUEST_ITERATIONS=40000

iterations_for() { [ "$1" = handshake ] && echo $HANDSHAKE_ITERATIONS || echo $REQUEST_ITERATIONS; }

[ -d "$TREE" ] || git -C "$REPO_DIR" worktree add --detach "$TREE" "$COMMIT"
git -C "$TREE" submodule update --init
docker run --rm --cpuset-cpus "$BUILD_CPUS" -v "$TREE:/work" -v opt_registry:/usr/local/cargo/registry -w /work \
  -e CARGO_TARGET_DIR=/work/target-linux -e CARGO_PROFILE_PROFILING_LTO=fat -e CARGO_PROFILE_PROFILING_CODEGEN_UNITS=1 \
  "$EVAL_IMAGE" cargo build --profile profiling --features avx2 --bin server-loop
BIN=$TREE/target-linux/profiling/server-loop
for level in 1 3 5; do
  for kind in handshake uchunk vpoint; do
    data=$OUT_DIR/perf.data
    sudo nice -n 10 taskset -c "$PROFILE_CPU" perf record -F $SAMPLE_HZ -o "$data" "$BIN" $level $kind "$(iterations_for $kind)" > "$OUT_DIR/time-$level-$kind.txt" 2>&1
    sudo perf report -i "$data" --no-children --sort sym --stdio 2>/dev/null | grep -E '^ +[0-9]' | head -$TOP_SYMBOLS > "$OUT_DIR/self-$level-$kind.txt"
  done
done
sudo rm -f "$OUT_DIR/perf.data"
