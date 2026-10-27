#!/bin/bash
. "$(dirname "${BASH_SOURCE[0]}")/campaign_env.sh"
LOG=$CAMPAIGN_OUT/campaign_part2.stages
stage() { name=$1; shift
  before=$(ls eval/results 2>/dev/null | sort)
  echo "$(date -u +%FT%TZ) START $name :: $*" >> $LOG
  "$@" > $CAMPAIGN_OUT/campaign2_$name.out 2>&1; rc=$?
  after=$(ls eval/results 2>/dev/null | sort)
  new=$(comm -13 <(echo "$before") <(echo "$after") | tr "\n" " ")
  echo "$(date -u +%FT%TZ) END $name rc=$rc dirs=$new" >> $LOG
}
stage cat4_hqc1 eval/run_all.sh --categories 4 --variant hqc1
stage cat4_hqc3 eval/run_all.sh --categories 4 --variant hqc3
stage cat4_hqc5 eval/run_all.sh --categories 4 --variant hqc5
stage cat4_rtt_hqc5 eval/run_all.sh --categories 4 --variant hqc5 --dos-args="--rtts-ms 75,300 --kinds none,handshake,vpoint,partial,churn2"
echo "$(date -u +%FT%TZ) ALLDONE" >> $LOG
