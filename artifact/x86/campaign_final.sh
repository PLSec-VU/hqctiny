#!/bin/bash
. "$(dirname "${BASH_SOURCE[0]}")/campaign_env.sh"
LOG=${LOG_OVERRIDE:-$CAMPAIGN_OUT/campaign_final.stages}
PROVENANCE=${PROV_OVERRIDE:-$CAMPAIGN_OUT/campaign_final.provenance.jsonl}
NIC=${MEASURE_NIC:-$(awk '$2=="00000000"{print $1; exit}' /proc/net/route)}
NIC_FLAG_BYTES=$((50 * 1000 * 1000))
MAX_ATTEMPTS=2
SAMPLE_SECONDS=5
MEASURE_ON="sudo bash eval/scripts/host/measurement_on.sh"
MEASURE_OFF="sudo bash eval/scripts/host/measurement_off.sh"

nic_stat() { cat /sys/class/net/$NIC/statistics/$1; }

sample_nic() {
  while true; do
    echo "$(date +%s) $(nic_stat rx_bytes) $(nic_stat tx_bytes)" >> "$1"
    sleep $SAMPLE_SECONDS
  done
}

nic_snapshot() { echo "$(nic_stat rx_bytes) $(nic_stat tx_bytes) $(nic_stat rx_packets) $(nic_stat tx_packets)"; }

locked_run() { series=$1; counters=$2; shift 2
  exec 9>"$MEASURE_LOCK"
  flock 9
  echo "$(date -u +%FT%TZ) lock acquired"
  : > $series
  sample_nic $series &
  sampler=$!
  echo "$(date -u +%FT%TZ) $(nic_snapshot)" > $counters
  $MEASURE_ON || { $MEASURE_OFF; kill $sampler; return 97; }
  "$@"
  rc=$?
  $MEASURE_OFF
  echo "$(date -u +%FT%TZ) $(nic_snapshot)" >> $counters
  kill $sampler
  return $rc
}

attempt() { name=$1; attempt_no=$2; shift 2
  before=$(ls eval/results 2>/dev/null | sort)
  series=$CAMPAIGN_OUT/campaign_final_${name}_a${attempt_no}.nic
  counters=$CAMPAIGN_OUT/campaign_final_${name}_a${attempt_no}.counters
  echo "$(date -u +%FT%TZ) START $name attempt=$attempt_no :: $*" >> $LOG
  ( locked_run $series $counters "$@" ) < /dev/null > $CAMPAIGN_OUT/campaign_final_${name}_a${attempt_no}.out 2>&1; rc=$?
  after=$(ls eval/results 2>/dev/null | sort)
  new=$(comm -13 <(echo "$before") <(echo "$after") | tr "\n" " ")
  read start rx0 tx0 rp0 tp0 < <(sed -n 1p $counters)
  read end rx1 tx1 rp1 tp1 < <(sed -n 2p $counters)
  total=$(( (rx1 - rx0) + (tx1 - tx0) ))
  flagged=false; [ $total -gt $NIC_FLAG_BYTES ] && flagged=true
  peak=$(awk 'NR>1{d=($2-pr)+($3-pt); if(d>m)m=d} {pr=$2; pt=$3} END{print m+0}' $series)
  echo "{\"stage\":\"$name\",\"attempt\":$attempt_no,\"rc\":$rc,\"measure_start\":\"$start\",\"measure_end\":\"$end\",\"dirs\":\"$new\",\"nic\":\"$NIC\",\"rx_bytes\":$((rx1-rx0)),\"tx_bytes\":$((tx1-tx0)),\"rx_packets\":$((rp1-rp0)),\"tx_packets\":$((tp1-tp0)),\"peak_${SAMPLE_SECONDS}s_bytes\":$peak,\"flagged_over_50MB\":$flagged,\"series\":\"$(basename $series)\"}" >> $PROVENANCE
  echo "$(date -u +%FT%TZ) END $name attempt=$attempt_no rc=$rc dirs=$new nic_bytes=$total flagged=$flagged" >> $LOG
  last_flagged=$flagged; last_rc=$rc
}

stage() { name=$1; shift
  n=1
  while [ $n -le $MAX_ATTEMPTS ]; do
    attempt $name $n "$@"
    [ "$last_flagged" = false ] && [ $last_rc -eq 0 ] && break
    n=$((n + 1))
  done
}

STAGES=${STAGES_FILE:-$STAGES_DIR/final.stagelist}
while IFS='|' read -r name cmd; do
  [ -z "$name" ] && continue
  stage "$name" bash -c "$cmd"
done < $STAGES
echo "$(date -u +%FT%TZ) ALLDONE" >> $LOG
