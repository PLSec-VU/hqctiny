#!/bin/sh -e
# usage: build_all.sh TREE_BASE TREE_VEC TREE_HEAD   (checkouts of the three compared commits)
HERE=$(cd "$(dirname "$0")" && pwd)
export STUDY=mce BUILD_TESTS=${BUILD_TESTS:-}
SYNC=$HERE/../common/sync_build.sh
$SYNC $1 base '--bench protocol_phases' '' '' ''
$SYNC $2 vec '--bench protocol_phases' '' '' ''
BUILD_TESTS=1 $SYNC $3 head '--bench protocol_phases' 'mceliece-bench ct-check' '' ''
