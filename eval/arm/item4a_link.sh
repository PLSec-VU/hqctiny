#!/bin/sh -e
# Item 4, part 1: link limits between playground and the Pi (TCP both directions, UDP with small and large datagrams),
# with Pi kernel UDP counters and per-core CPU (mpstat) around each run. Takes the playground lock.
. "$(dirname "$0")/lib.sh"
OUT=$ARM_DIR/raw/link; mkdir -p "$OUT"
play_hold_start
pi_hold_start
ssh $PI "pkill -x iperf3 || true; nohup taskset -c 2 iperf3 -s -D >/dev/null 2>&1"
snmp() { ssh $PI "grep '^Udp:' /proc/net/snmp; ip -s link show eth0 | tail -n 4"; }
run() {
  name=$1; shift
  snmp > "$OUT/$name.pi_before.txt"
  ssh $PLAY "iperf3 -c $PI_HOST -t 10 -J $*" > "$OUT/$name.json" &
  CLIENT=$!
  sleep 3
  ssh $PI "mpstat -P ALL 5 1 > $PI_ROOT/results/mpstat_$name.txt"
  wait $CLIENT
  snmp > "$OUT/$name.pi_after.txt"
  scp -q $PI:$PI_ROOT/results/mpstat_$name.txt "$OUT/$name.mpstat.txt"
}
run tcp_to_pi
run tcp_from_pi -R
run udp_small_to_pi -u -b 0 -l 100
run udp_1200_to_pi -u -b 0 -l 1200
ssh $PI "pkill -x iperf3 || true"
play_hold_stop
pi_hold_stop
