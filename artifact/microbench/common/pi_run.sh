#!/bin/sh
# usage: pi_run.sh NAME COMMAND...   (on the Pi; takes $PI_LOCK, waits until the SoC is cool, pins the clock)
NAME=$1; shift
PI_ROOT=${PI_ROOT:?}
PI_LOCK=${PI_LOCK:-/mnt/pi.lock}
OUT=$PI_ROOT/results
mkdir -p $OUT
MAX_START_MC=60000
PI_CLOCK_KHZ=1200000
COOL_DOWN_RETRY_S=30
COOL_DOWN_EXIT=75
HERE=$(dirname "$0")
while :; do
  flock $PI_LOCK sh -c '
    NAME=$1; OUT=$2; MAX=$3; HERE=$4; CLOCK=$5; COOL=$6; shift 6
    t=$(cat /sys/class/thermal/thermal_zone0/temp)
    [ "$t" -le "$MAX" ] || exit $COOL
    sudo sh -c "echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor >/dev/null; echo $CLOCK | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_max_freq >/dev/null"
    sh $HERE/pi_snapshot.sh > $OUT/$NAME.env.txt
    "$@" > $OUT/$NAME.out 2> $OUT/$NAME.err
    status=$?
    sh $HERE/pi_snapshot.sh >> $OUT/$NAME.env.txt
    echo "exit=$status" >> $OUT/$NAME.env.txt
    exit $status
  ' sh "$NAME" "$OUT" "$MAX_START_MC" "$HERE" "$PI_CLOCK_KHZ" "$COOL_DOWN_EXIT" "$@"
  status=$?
  [ $status -eq $COOL_DOWN_EXIT ] || exit $status
  sleep $COOL_DOWN_RETRY_S
done
