#!/bin/sh -e
# usage: fetch_results.sh HOST REMOTE_REPO_DIR RESULTS_DIR   (copies eval/results of a campaign host into RESULTS_DIR/<study>)
HOST=${1:?usage: fetch_results.sh HOST REMOTE_REPO_DIR RESULTS_DIR STUDY}
REMOTE_REPO_DIR=${2:?}
RESULTS_DIR=${3:?}
STUDY=${4:?part1, part2, part3 or final-x86}
mkdir -p "$RESULTS_DIR/$STUDY"
rsync -a "$HOST:$REMOTE_REPO_DIR/eval/results/" "$RESULTS_DIR/$STUDY/"
