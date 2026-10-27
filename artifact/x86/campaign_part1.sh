#!/bin/bash
. "$(dirname "${BASH_SOURCE[0]}")/campaign_env.sh"
LOG=$CAMPAIGN_OUT/campaign_part1.stages
stage() { name=$1; shift
  before=$(ls eval/results 2>/dev/null | sort)
  echo "$(date -u +%FT%TZ) START $name :: $*" >> $LOG
  "$@" > $CAMPAIGN_OUT/campaign_$name.out 2>&1; rc=$?
  after=$(ls eval/results 2>/dev/null | sort)
  new=$(comm -13 <(echo "$before") <(echo "$after") | tr "\n" " ")
  echo "$(date -u +%FT%TZ) END $name rc=$rc dirs=$new" >> $LOG
}
stage A eval/run_all.sh --categories 1,2,3,6,7
stage R2 eval/run_all.sh --categories 3,6
stage wan_profiles eval/run_all.sh --categories 8 --wan-sweep-args="--sets profiles --name wan_profiles"
stage R3 eval/run_all.sh --categories 3,6
stage wan_loss_low eval/run_all.sh --categories 8 --wan-sweep-args="--sets loss --losses 0,1,2,2.5,3 --name wan_loss_low"
stage wan_ge eval/run_all.sh --categories 8 --wan-sweep-args="--sets ge --name wan_ge"
stage wan_loss_high eval/run_all.sh --categories 8 --wan-sweep-args="--sets loss --losses 4,5 --name wan_loss_high"
echo "$(date -u +%FT%TZ) ALLDONE" >> $LOG
