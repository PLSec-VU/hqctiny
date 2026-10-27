#!/bin/sh
# usage: stack_search.sh <binary> <level> <kind>
BIN=$1; LEVEL=$2; KIND=$3
LOW=16; HIGH=1024
while [ $((HIGH - LOW)) -gt 4 ]; do
  MID=$(( (LOW + HIGH) / 2 ))
  if "$BIN" $LEVEL $KIND $MID >/dev/null 2>&1; then HIGH=$MID; else LOW=$MID; fi
done
echo "$BIN $LEVEL $KIND min_stack_kib<=$HIGH"
