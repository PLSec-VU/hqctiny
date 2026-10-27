#!/bin/bash
# Usage: ./run.sh [outdir [variant ...]]   (default outdir: ../../eval/results/proverif)
# Builds each variant of hqclethe.pv by replacing the (*KNOB:tag*) lines listed in
# variants/NAME.knobs, runs ProVerif, and stores the model, the full output and the
# run time in outdir.
set -u
cd "$(dirname "$0")"
PV=${PROVERIF:-proverif}
OUT=${1:-../../eval/results/proverif}
mkdir -p "$OUT"
shift
if [ $# -gt 0 ]; then names=("$@"); else names=($(ls variants | sed 's/\.knobs$//')); fi
for name in "${names[@]}"; do
  knobs=variants/$name.knobs
  awk -F'\t' 'NR==FNR { repl[$1]=$2; next }
    { if (match($0, /\(\*KNOB:[a-z]+\*\)/)) {
        tag=substr($0, RSTART+7, RLENGTH-9)
        if (tag in repl) { print repl[tag] "   (*VARIANT*)"; next } }
      print }' "$knobs" hqclethe.pv > "$OUT/$name.pv"
  start=$(date +%s)
  perl -e 'alarm shift; exec @ARGV' "${TIMEOUT:-900}" "$PV" "$OUT/$name.pv" > "$OUT/$name.out" 2>&1
  status=$?
  end=$(date +%s)
  echo "$((end-start))" > "$OUT/$name.seconds"
  echo "== $name ($((end-start)) s, exit $status)"
  sed -n '/^Verification summary/,$p' "$OUT/$name.out" | grep -E '^( - )?Query'
done
