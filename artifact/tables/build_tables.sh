#!/bin/sh -e
# usage: build_tables.sh RESULTS_DIR [PAPER_TABLE_DIR]
RESULTS_DIR=$(cd "${1:?usage: build_tables.sh RESULTS_DIR [PAPER_TABLE_DIR]}" && pwd)
PAPER_TABLE_DIR=${2:-$PWD/paper-tables}
HERE=$(cd "$(dirname "$0")" && pwd)
export RESULTS_DIR
python3 "$HERE/make_tables_part1.py" > "$RESULTS_DIR/part1/tables_part1.md"
python3 "$HERE/make_tables_part2.py"
python3 "$HERE/make_tables_part3.py" > "$RESULTS_DIR/part3/tables_part3.md"
python3 "$HERE/make_tables_dos_part3.py"
python3 "$HERE/make_tables_final.py" > "$RESULTS_DIR/final-x86/tables_final.md"
python3 "$HERE/make_tables_dos.py"
python3 "$HERE/numbers_for_paper.py" > "$RESULTS_DIR/final-x86/numbers_for_paper.md"
python3 "$HERE/build_results.py"
python3 "$HERE/gen_paper_tables.py" "$PAPER_TABLE_DIR"
