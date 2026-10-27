#!/bin/bash
. "$(dirname "${BASH_SOURCE[0]}")/campaign_env.sh"
LOG=$CAMPAIGN_OUT/campaign_part3.stages
MEASURE_ON="sudo bash eval/scripts/host/measurement_on.sh"
MEASURE_OFF="sudo bash eval/scripts/host/measurement_off.sh"

locked_run() {
  exec 9>"$MEASURE_LOCK"
  flock 9
  $MEASURE_ON || { $MEASURE_OFF; return 97; }
  "$@"
  rc=$?
  $MEASURE_OFF
  return $rc
}

stage() { name=$1; shift
  before=$(ls eval/results 2>/dev/null | sort)
  echo "$(date -u +%FT%TZ) START $name :: $*" >> $LOG
  ( locked_run "$@" ) > $CAMPAIGN_OUT/campaign3_$name.out 2>&1; rc=$?
  after=$(ls eval/results 2>/dev/null | sort)
  new=$(comm -13 <(echo "$before") <(echo "$after") | tr "\n" " ")
  echo "$(date -u +%FT%TZ) END $name rc=$rc dirs=$new" >> $LOG
}

stage verify_rtt eval/run_all.sh --categories 4 --variant hqc5 --dos-reps 2 --dos-args="--systems stateless --rtts-ms 75 --kinds none --shapes single"
stage wan_profiles eval/run_all.sh --categories 8 --wan-sweep-args="--sets profiles --name wan_profiles"
stage wan_loss_low eval/run_all.sh --categories 8 --wan-sweep-args="--sets loss --losses 0,1,2,2.5,3 --only-mctiny --name wan_loss_low"
stage wan_ge eval/run_all.sh --categories 8 --wan-sweep-args="--sets ge --only-mctiny --name wan_ge"
stage wan_loss_high eval/run_all.sh --categories 8 --wan-sweep-args="--sets loss --losses 4,5 --only-mctiny --name wan_loss_high"
stage cat4_rtt_stateless eval/run_all.sh --categories 4 --variant hqc5 --dos-args="--systems stateless --rtts-ms 75,300 --kinds none,handshake,vpoint"
echo "$(date -u +%FT%TZ) ALLDONE" >> $LOG
